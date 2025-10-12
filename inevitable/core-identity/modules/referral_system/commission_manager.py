"""
Commission calculation and payout management
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, date
from decimal import Decimal
import logging
from enum import Enum

from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Commission, CommissionType, PayoutStatus,
    PayoutRequest, AffiliatePartner, Referral,
    ReferralCampaign
)


logger = logging.getLogger(__name__)


class PaymentMethod(str, Enum):
    """Supported payout methods"""
    STRIPE = "stripe"
    PAYPAL = "paypal"
    WIRE = "wire"
    CRYPTO = "crypto"
    CHECK = "check"


class CommissionCalculator:
    """Calculate commissions based on various models"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.calculation_methods = {
            CommissionType.PERCENTAGE: self._calculate_percentage,
            CommissionType.FIXED: self._calculate_fixed,
            CommissionType.TIERED: self._calculate_tiered,
            CommissionType.RECURRING: self._calculate_recurring,
            CommissionType.HYBRID: self._calculate_hybrid
        }
    
    async def calculate_commission(
        self,
        referral: Referral,
        campaign: ReferralCampaign,
        partner: Optional[AffiliatePartner] = None
    ) -> Commission:
        """Calculate commission for a referral"""
        async with self.db_factory() as db:
            # Get commission configuration
            if partner and partner.custom_commission_config:
                # Use partner's custom config
                commission_type = partner.default_commission_type
                config = partner.custom_commission_config
            else:
                # Use campaign config
                commission_type = campaign.commission_type
                config = campaign.commission_config
            
            # Calculate base commission
            calculator = self.calculation_methods.get(
                commission_type,
                self._calculate_percentage
            )
            
            base_amount = referral.conversion_value or Decimal('0')
            commission_amount = await calculator(base_amount, config)
            
            # Apply partner tier multiplier
            if partner and partner.performance_multiplier:
                commission_amount *= partner.performance_multiplier
            
            # Apply campaign limits
            if campaign.commission_config.get('max_commission'):
                max_amount = Decimal(str(campaign.commission_config['max_commission']))
                commission_amount = min(commission_amount, max_amount)
            
            # Create commission record
            commission = Commission(
                referral_id=referral.id,
                partner_id=partner.partner_id if partner else None,
                commission_type=commission_type,
                base_amount=base_amount,
                commission_rate=config.get('rate'),
                commission_amount=commission_amount,
                currency=config.get('currency', 'USD'),
                is_recurring=commission_type == CommissionType.RECURRING,
                recurring_period=config.get('recurring_period'),
                recurring_end_date=self._calculate_recurring_end_date(config),
                tenant_id=referral.tenant_id
            )
            
            db.add(commission)
            await db.commit()
            
            return commission
    
    async def _calculate_percentage(
        self,
        base_amount: Decimal,
        config: Dict[str, Any]
    ) -> Decimal:
        """Calculate percentage-based commission"""
        rate = Decimal(str(config.get('rate', 0))) / 100
        return base_amount * rate
    
    async def _calculate_fixed(
        self,
        base_amount: Decimal,
        config: Dict[str, Any]
    ) -> Decimal:
        """Calculate fixed commission"""
        return Decimal(str(config.get('amount', 0)))
    
    async def _calculate_tiered(
        self,
        base_amount: Decimal,
        config: Dict[str, Any]
    ) -> Decimal:
        """Calculate tiered commission"""
        tiers = config.get('tiers', [])
        
        # Sort tiers by threshold
        sorted_tiers = sorted(tiers, key=lambda x: x['threshold'])
        
        commission = Decimal('0')
        previous_threshold = Decimal('0')
        
        for tier in sorted_tiers:
            threshold = Decimal(str(tier['threshold']))
            
            if base_amount <= threshold:
                # Calculate commission for this tier portion
                tier_amount = base_amount - previous_threshold
            else:
                # Full tier
                tier_amount = threshold - previous_threshold
            
            if tier['type'] == 'percentage':
                rate = Decimal(str(tier['rate'])) / 100
                commission += tier_amount * rate
            else:
                # Fixed amount per tier
                commission += Decimal(str(tier['amount']))
            
            if base_amount <= threshold:
                break
                
            previous_threshold = threshold
        
        # Handle amount above highest tier
        if base_amount > previous_threshold and sorted_tiers:
            last_tier = sorted_tiers[-1]
            remaining = base_amount - previous_threshold
            
            if last_tier['type'] == 'percentage':
                rate = Decimal(str(last_tier['rate'])) / 100
                commission += remaining * rate
        
        return commission
    
    async def _calculate_recurring(
        self,
        base_amount: Decimal,
        config: Dict[str, Any]
    ) -> Decimal:
        """Calculate recurring commission (first payment)"""
        # For recurring, calculate like percentage but mark as recurring
        rate = Decimal(str(config.get('rate', 0))) / 100
        return base_amount * rate
    
    async def _calculate_hybrid(
        self,
        base_amount: Decimal,
        config: Dict[str, Any]
    ) -> Decimal:
        """Calculate hybrid commission (fixed + percentage)"""
        fixed = Decimal(str(config.get('fixed_amount', 0)))
        rate = Decimal(str(config.get('percentage_rate', 0))) / 100
        
        return fixed + (base_amount * rate)
    
    def _calculate_recurring_end_date(
        self,
        config: Dict[str, Any]
    ) -> Optional[date]:
        """Calculate end date for recurring commissions"""
        duration_months = config.get('recurring_duration_months')
        if duration_months:
            return date.today() + timedelta(days=30 * duration_months)
        return None
    
    async def process_recurring_commissions(self):
        """Process recurring commission payments"""
        async with self.db_factory() as db:
            # Get active recurring commissions
            today = date.today()
            
            result = await db.execute(
                select(Commission).where(
                    and_(
                        Commission.is_recurring == True,
                        Commission.payout_status == PayoutStatus.PENDING,
                        or_(
                            Commission.recurring_end_date == None,
                            Commission.recurring_end_date >= today
                        )
                    )
                )
            )
            commissions = result.scalars().all()
            
            for commission in commissions:
                # Create new commission entry for this period
                new_commission = Commission(
                    referral_id=commission.referral_id,
                    partner_id=commission.partner_id,
                    commission_type=commission.commission_type,
                    base_amount=commission.base_amount,
                    commission_rate=commission.commission_rate,
                    commission_amount=commission.commission_amount,
                    currency=commission.currency,
                    is_recurring=False,  # Individual payment
                    transaction_date=datetime.utcnow(),
                    tenant_id=commission.tenant_id
                )
                
                db.add(new_commission)
            
            await db.commit()


class PayoutManager:
    """Manage commission payouts"""
    
    def __init__(self, db_factory, payment_processors: Dict[str, Any]):
        self.db_factory = db_factory
        self.payment_processors = payment_processors
        self.minimum_payouts = {
            PaymentMethod.STRIPE: Decimal('10.00'),
            PaymentMethod.PAYPAL: Decimal('10.00'),
            PaymentMethod.WIRE: Decimal('100.00'),
            PaymentMethod.CRYPTO: Decimal('50.00'),
            PaymentMethod.CHECK: Decimal('50.00')
        }
    
    async def create_payout_request(
        self,
        partner_id: str,
        payment_method: PaymentMethod,
        tenant_id: str
    ) -> PayoutRequest:
        """Create payout request for partner"""
        async with self.db_factory() as db:
            # Get partner
            result = await db.execute(
                select(AffiliatePartner).where(
                    and_(
                        AffiliatePartner.partner_id == partner_id,
                        AffiliatePartner.tenant_id == tenant_id
                    )
                )
            )
            partner = result.scalar_one_or_none()
            
            if not partner:
                raise ValueError("Partner not found")
            
            if not partner.is_active:
                raise ValueError("Partner is not active")
            
            # Check minimum payout
            minimum = self.minimum_payouts.get(payment_method, Decimal('10.00'))
            if partner.current_balance < minimum:
                raise ValueError(f"Minimum payout is {minimum}")
            
            # Get unpaid commissions
            result = await db.execute(
                select(Commission).where(
                    and_(
                        Commission.partner_id == partner_id,
                        Commission.payout_status == PayoutStatus.PENDING,
                        Commission.tenant_id == tenant_id
                    )
                )
            )
            commissions = result.scalars().all()
            
            if not commissions:
                raise ValueError("No unpaid commissions")
            
            # Calculate total
            total_amount = sum(c.commission_amount for c in commissions)
            commission_ids = [c.id for c in commissions]
            
            # Calculate fees
            processing_fee = self._calculate_processing_fee(
                payment_method,
                total_amount
            )
            
            # Create payout request
            payout = PayoutRequest(
                partner_id=partner_id,
                amount_requested=total_amount,
                currency='USD',
                payment_method=payment_method.value,
                payment_details=partner.payment_details,  # Encrypted
                status=PayoutStatus.PENDING,
                processing_fee=processing_fee,
                net_amount=total_amount - processing_fee,
                commission_ids=commission_ids,
                tenant_id=tenant_id
            )
            
            db.add(payout)
            
            # Update commission status
            for commission in commissions:
                commission.payout_status = PayoutStatus.PROCESSING
                commission.payout_request_id = payout.id
            
            await db.commit()
            
            return payout
    
    async def process_payout(
        self,
        payout_id: str,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Process payout through payment provider"""
        async with self.db_factory() as db:
            # Get payout request
            result = await db.execute(
                select(PayoutRequest).where(
                    and_(
                        PayoutRequest.payout_id == payout_id,
                        PayoutRequest.tenant_id == tenant_id
                    )
                )
            )
            payout = result.scalar_one_or_none()
            
            if not payout:
                raise ValueError("Payout request not found")
            
            if payout.status != PayoutStatus.PENDING:
                raise ValueError(f"Payout already {payout.status.value}")
            
            # Get payment processor
            processor = self.payment_processors.get(payout.payment_method)
            if not processor:
                raise ValueError(f"Payment processor not configured: {payout.payment_method}")
            
            try:
                # Process payment
                result = await processor.send_payment(
                    amount=payout.net_amount,
                    currency=payout.currency,
                    recipient=payout.payment_details,
                    metadata={
                        'payout_id': payout.payout_id,
                        'partner_id': payout.partner_id
                    }
                )
                
                # Update payout status
                payout.status = PayoutStatus.COMPLETED
                payout.processed_at = datetime.utcnow()
                payout.processor_reference = result.get('transaction_id')
                
                # Update commissions
                await db.execute(
                    update(Commission)
                    .where(Commission.id.in_(payout.commission_ids))
                    .values(
                        payout_status=PayoutStatus.COMPLETED,
                        paid_at=datetime.utcnow()
                    )
                )
                
                # Update partner balance
                partner = await db.get(AffiliatePartner, payout.partner_id)
                if partner:
                    partner.current_balance -= payout.amount_requested
                    partner.lifetime_commission += payout.amount_requested
                
                await db.commit()
                
                return {
                    'success': True,
                    'transaction_id': result.get('transaction_id'),
                    'amount_paid': payout.net_amount,
                    'processing_fee': payout.processing_fee
                }
                
            except Exception as e:
                # Payment failed
                payout.status = PayoutStatus.FAILED
                payout.failure_reason = str(e)
                
                # Revert commission status
                await db.execute(
                    update(Commission)
                    .where(Commission.id.in_(payout.commission_ids))
                    .values(payout_status=PayoutStatus.PENDING)
                )
                
                await db.commit()
                
                raise
    
    def _calculate_processing_fee(
        self,
        payment_method: PaymentMethod,
        amount: Decimal
    ) -> Decimal:
        """Calculate processing fee for payment method"""
        fees = {
            PaymentMethod.STRIPE: (Decimal('0.029'), Decimal('0.30')),  # 2.9% + $0.30
            PaymentMethod.PAYPAL: (Decimal('0.029'), Decimal('0.30')),  # 2.9% + $0.30
            PaymentMethod.WIRE: (Decimal('0'), Decimal('25.00')),       # $25 flat
            PaymentMethod.CRYPTO: (Decimal('0.01'), Decimal('0')),       # 1%
            PaymentMethod.CHECK: (Decimal('0'), Decimal('5.00'))         # $5 flat
        }
        
        percentage, fixed = fees.get(payment_method, (Decimal('0'), Decimal('0')))
        
        return (amount * percentage) + fixed
    
    async def get_payout_history(
        self,
        partner_id: str,
        tenant_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get payout history for partner"""
        async with self.db_factory() as db:
            result = await db.execute(
                select(PayoutRequest)
                .where(
                    and_(
                        PayoutRequest.partner_id == partner_id,
                        PayoutRequest.tenant_id == tenant_id
                    )
                )
                .order_by(PayoutRequest.created_at.desc())
                .limit(limit)
            )
            payouts = result.scalars().all()
            
            history = []
            for payout in payouts:
                history.append({
                    'payout_id': payout.payout_id,
                    'amount': float(payout.amount_requested),
                    'net_amount': float(payout.net_amount),
                    'processing_fee': float(payout.processing_fee),
                    'payment_method': payout.payment_method,
                    'status': payout.status.value,
                    'created_at': payout.created_at,
                    'processed_at': payout.processed_at,
                    'processor_reference': payout.processor_reference
                })
            
            return history


class TaxDocumentGenerator:
    """Generate tax documents for affiliates"""
    
    def __init__(self, db_factory):
        self.db_factory = db_factory
        self.tax_thresholds = {
            'US': Decimal('600.00'),  # 1099 threshold
            'EU': Decimal('0.00'),     # No threshold
        }
    
    async def generate_1099(
        self,
        partner_id: str,
        tax_year: int,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Generate 1099 tax form for US affiliates"""
        async with self.db_factory() as db:
            # Get partner
            partner = await db.get(AffiliatePartner, partner_id)
            if not partner:
                raise ValueError("Partner not found")
            
            # Get year's payouts
            start_date = datetime(tax_year, 1, 1)
            end_date = datetime(tax_year, 12, 31, 23, 59, 59)
            
            result = await db.execute(
                select(
                    func.sum(PayoutRequest.amount_requested),
                    func.count(PayoutRequest.id)
                ).where(
                    and_(
                        PayoutRequest.partner_id == partner_id,
                        PayoutRequest.tenant_id == tenant_id,
                        PayoutRequest.status == PayoutStatus.COMPLETED,
                        PayoutRequest.processed_at >= start_date,
                        PayoutRequest.processed_at <= end_date
                    )
                )
            )
            total_paid, payout_count = result.first()
            
            if not total_paid or total_paid < self.tax_thresholds['US']:
                return {
                    'required': False,
                    'reason': f'Below ${self.tax_thresholds["US"]} threshold'
                }
            
            # Generate 1099 data
            return {
                'required': True,
                'form_type': '1099-MISC',
                'tax_year': tax_year,
                'payer': {
                    'name': 'Platform Forge Inc.',
                    'ein': 'XX-XXXXXXX',  # Would use real EIN
                    'address': '123 Main St, San Francisco, CA 94105'
                },
                'payee': {
                    'name': partner.company_name or partner.contact_name,
                    'tin': partner.tax_id,
                    'address': partner.payment_details.get('address', {})
                },
                'amounts': {
                    'box_3': float(total_paid),  # Other income
                    'total': float(total_paid)
                },
                'payout_count': payout_count
            }
    
    async def should_withhold_tax(
        self,
        partner: AffiliatePartner,
        amount: Decimal
    ) -> tuple[bool, Decimal]:
        """Determine if tax should be withheld"""
        # Check if W-9 on file
        if not partner.tax_form_on_file:
            # Backup withholding required
            return True, amount * Decimal('0.24')  # 24% backup withholding
        
        return False, Decimal('0')