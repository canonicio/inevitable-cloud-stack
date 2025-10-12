"""
Referral tracking and attribution system
"""
import secrets
import string
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import hashlib
import logging

from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Referral, ReferralCampaign, ReferralStatus,
    ReferralType, AttributionModel
)
from modules.core.security import SecurityUtils


logger = logging.getLogger(__name__)


class ReferralCodeGenerator:
    """Generate unique referral codes"""
    
    def __init__(
        self,
        code_length: int = 8,
        prefix: Optional[str] = None,
        custom_alphabet: Optional[str] = None
    ):
        self.code_length = code_length
        self.prefix = prefix or ""
        self.alphabet = custom_alphabet or string.ascii_uppercase + string.digits
        # Remove ambiguous characters
        self.alphabet = self.alphabet.replace('0', '').replace('O', '').replace('I', '').replace('l', '')
    
    async def generate_code(
        self,
        db: AsyncSession,
        user_id: Optional[str] = None,
        campaign_id: Optional[str] = None
    ) -> str:
        """Generate unique referral code"""
        max_attempts = 10
        
        for _ in range(max_attempts):
            # Generate random part
            random_part = ''.join(
                secrets.choice(self.alphabet) 
                for _ in range(self.code_length)
            )
            
            # Build full code
            code_parts = []
            if self.prefix:
                code_parts.append(self.prefix)
            
            # Add user/campaign specific part if needed
            if user_id:
                user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:4].upper()
                code_parts.append(user_hash)
            
            code_parts.append(random_part)
            code = '-'.join(code_parts)
            
            # Check uniqueness
            result = await db.execute(
                select(Referral).where(Referral.referral_code == code)
            )
            if not result.scalar_one_or_none():
                return code
        
        raise ValueError("Failed to generate unique code")
    
    def generate_custom_code(
        self,
        base: str,
        suffix_length: int = 4
    ) -> str:
        """Generate custom vanity code"""
        # Sanitize base
        base = ''.join(c.upper() for c in base if c.isalnum())
        
        # Add random suffix
        suffix = ''.join(
            secrets.choice(self.alphabet) 
            for _ in range(suffix_length)
        )
        
        return f"{base}-{suffix}"


class AttributionEngine:
    """Handle multi-touch attribution"""
    
    def __init__(self, default_model: AttributionModel = AttributionModel.LAST_TOUCH):
        self.default_model = default_model
        self.touchpoint_weights = {
            AttributionModel.FIRST_TOUCH: self._first_touch_weights,
            AttributionModel.LAST_TOUCH: self._last_touch_weights,
            AttributionModel.LINEAR: self._linear_weights,
            AttributionModel.TIME_DECAY: self._time_decay_weights,
            AttributionModel.POSITION_BASED: self._position_based_weights
        }
    
    async def calculate_attribution(
        self,
        touchpoints: List[Dict[str, Any]],
        conversion_value: float,
        model: Optional[AttributionModel] = None
    ) -> List[Tuple[str, float]]:
        """
        Calculate attribution for multiple touchpoints
        
        Returns list of (referrer_id, attributed_value) tuples
        """
        if not touchpoints:
            return []
        
        model = model or self.default_model
        
        # Sort touchpoints by timestamp
        sorted_touchpoints = sorted(
            touchpoints,
            key=lambda x: x['timestamp']
        )
        
        # Get weight function
        weight_func = self.touchpoint_weights.get(
            model,
            self._last_touch_weights
        )
        
        # Calculate weights
        weights = weight_func(sorted_touchpoints)
        
        # Apply weights to conversion value
        attributions = []
        for i, touchpoint in enumerate(sorted_touchpoints):
            if i < len(weights):
                attributed_value = conversion_value * weights[i]
                attributions.append((
                    touchpoint['referrer_id'],
                    attributed_value
                ))
        
        return attributions
    
    def _first_touch_weights(self, touchpoints: List[Dict[str, Any]]) -> List[float]:
        """First touch gets 100% credit"""
        weights = [0.0] * len(touchpoints)
        weights[0] = 1.0
        return weights
    
    def _last_touch_weights(self, touchpoints: List[Dict[str, Any]]) -> List[float]:
        """Last touch gets 100% credit"""
        weights = [0.0] * len(touchpoints)
        weights[-1] = 1.0
        return weights
    
    def _linear_weights(self, touchpoints: List[Dict[str, Any]]) -> List[float]:
        """Equal credit to all touchpoints"""
        count = len(touchpoints)
        return [1.0 / count] * count
    
    def _time_decay_weights(self, touchpoints: List[Dict[str, Any]]) -> List[float]:
        """More recent touchpoints get more credit"""
        if len(touchpoints) == 1:
            return [1.0]
        
        # Calculate time differences
        last_time = touchpoints[-1]['timestamp']
        time_diffs = [
            (last_time - tp['timestamp']).total_seconds()
            for tp in touchpoints
        ]
        
        # Apply exponential decay
        decay_rate = 0.5  # Half credit every period
        period = 7 * 24 * 3600  # 7 days in seconds
        
        raw_weights = [
            decay_rate ** (diff / period)
            for diff in time_diffs
        ]
        
        # Normalize
        total = sum(raw_weights)
        return [w / total for w in raw_weights]
    
    def _position_based_weights(self, touchpoints: List[Dict[str, Any]]) -> List[float]:
        """40% first, 40% last, 20% middle touches"""
        count = len(touchpoints)
        
        if count == 1:
            return [1.0]
        elif count == 2:
            return [0.5, 0.5]
        else:
            weights = [0.0] * count
            weights[0] = 0.4  # First touch
            weights[-1] = 0.4  # Last touch
            
            # Distribute remaining 20% among middle touches
            middle_count = count - 2
            middle_weight = 0.2 / middle_count
            for i in range(1, count - 1):
                weights[i] = middle_weight
            
            return weights


class ReferralTracker:
    """Main referral tracking system"""
    
    def __init__(
        self,
        db_factory,
        code_generator: Optional[ReferralCodeGenerator] = None,
        attribution_engine: Optional[AttributionEngine] = None
    ):
        self.db_factory = db_factory
        self.code_generator = code_generator or ReferralCodeGenerator()
        self.attribution_engine = attribution_engine or AttributionEngine()
    
    async def create_referral(
        self,
        referrer_id: str,
        campaign_id: str,
        tenant_id: str,
        custom_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Referral:
        """Create new referral link"""
        async with self.db_factory() as db:
            # Get campaign
            result = await db.execute(
                select(ReferralCampaign).where(
                    and_(
                        ReferralCampaign.campaign_id == campaign_id,
                        ReferralCampaign.tenant_id == tenant_id,
                        ReferralCampaign.is_active == True
                    )
                )
            )
            campaign = result.scalar_one_or_none()
            
            if not campaign:
                raise ValueError("Invalid or inactive campaign")
            
            # Check campaign dates
            now = datetime.utcnow()
            if now < campaign.start_date:
                raise ValueError("Campaign has not started yet")
            if campaign.end_date and now > campaign.end_date:
                raise ValueError("Campaign has ended")
            
            # Check referral limits
            if campaign.max_referrals_per_user:
                count = await self._get_user_referral_count(
                    db,
                    referrer_id,
                    campaign_id
                )
                if count >= campaign.max_referrals_per_user:
                    raise ValueError("Referral limit reached")
            
            # Generate code
            if custom_code:
                code = self.code_generator.generate_custom_code(custom_code)
                # Check uniqueness
                existing = await db.execute(
                    select(Referral).where(Referral.referral_code == code)
                )
                if existing.scalar_one_or_none():
                    raise ValueError("Custom code already exists")
            else:
                code = await self.code_generator.generate_code(
                    db,
                    user_id=referrer_id,
                    campaign_id=campaign_id
                )
            
            # Calculate expiration
            expires_at = None
            if campaign.attribution_window_days:
                expires_at = now + timedelta(days=campaign.attribution_window_days)
            
            # Create referral
            referral = Referral(
                referral_code=code,
                referrer_id=referrer_id,
                campaign_id=campaign_id,
                status=ReferralStatus.PENDING,
                expires_at=expires_at,
                metadata=metadata or {},
                tenant_id=tenant_id
            )
            
            db.add(referral)
            await db.commit()
            
            return referral
    
    async def track_click(
        self,
        referral_code: str,
        click_data: Dict[str, Any]
    ) -> Optional[Referral]:
        """Track referral link click"""
        async with self.db_factory() as db:
            # Get referral
            result = await db.execute(
                select(Referral).where(
                    Referral.referral_code == referral_code
                )
            )
            referral = result.scalar_one_or_none()
            
            if not referral:
                return None
            
            # Check expiration
            if referral.expires_at and datetime.utcnow() > referral.expires_at:
                referral.status = ReferralStatus.EXPIRED
                await db.commit()
                return None
            
            # Update click data
            referral.click_count += 1
            if not referral.first_click_at:
                referral.first_click_at = datetime.utcnow()
                referral.status = ReferralStatus.CLICKED
            
            # Store attribution data
            attribution_data = referral.attribution_data or {}
            attribution_data.update({
                'utm_source': click_data.get('utm_source'),
                'utm_medium': click_data.get('utm_medium'),
                'utm_campaign': click_data.get('utm_campaign'),
                'referrer': click_data.get('referrer'),
                'landing_page': click_data.get('landing_page')
            })
            referral.attribution_data = attribution_data
            
            # Store device info
            referral.ip_address = click_data.get('ip_address')
            referral.user_agent = click_data.get('user_agent')
            referral.device_fingerprint = click_data.get('device_fingerprint')
            
            # Update campaign stats
            campaign = await db.get(ReferralCampaign, referral.campaign_id)
            if campaign:
                campaign.total_clicks += 1
            
            await db.commit()
            
            return referral
    
    async def track_signup(
        self,
        referral_code: str,
        referred_user_id: str,
        signup_data: Optional[Dict[str, Any]] = None
    ) -> Optional[Referral]:
        """Track referred user signup"""
        async with self.db_factory() as db:
            # Get referral
            result = await db.execute(
                select(Referral).where(
                    and_(
                        Referral.referral_code == referral_code,
                        Referral.referred_id == None  # Not already used
                    )
                )
            )
            referral = result.scalar_one_or_none()
            
            if not referral:
                return None
            
            # Check if already signed up with different code
            existing = await db.execute(
                select(Referral).where(
                    and_(
                        Referral.referred_id == referred_user_id,
                        Referral.status != ReferralStatus.FRAUDULENT
                    )
                )
            )
            if existing.scalar_one_or_none():
                # User already referred
                return None
            
            # Update referral
            referral.referred_id = referred_user_id
            referral.signup_at = datetime.utcnow()
            referral.status = ReferralStatus.SIGNED_UP
            
            if signup_data:
                metadata = referral.metadata or {}
                metadata['signup_data'] = signup_data
                referral.metadata = metadata
            
            # Update campaign stats
            campaign = await db.get(ReferralCampaign, referral.campaign_id)
            if campaign:
                campaign.total_signups += 1
            
            await db.commit()
            
            return referral
    
    async def track_conversion(
        self,
        referred_user_id: str,
        conversion_value: float,
        conversion_data: Optional[Dict[str, Any]] = None
    ) -> Optional[Referral]:
        """Track referral conversion"""
        async with self.db_factory() as db:
            # Get all touchpoints for this user
            touchpoints = await self._get_user_touchpoints(
                db,
                referred_user_id
            )
            
            if not touchpoints:
                return None
            
            # Get campaign for attribution model
            primary_referral = touchpoints[-1]  # Most recent
            campaign = await db.get(
                ReferralCampaign,
                primary_referral['campaign_id']
            )
            
            # Calculate attribution
            attributions = await self.attribution_engine.calculate_attribution(
                touchpoints,
                conversion_value,
                campaign.attribution_model if campaign else None
            )
            
            # Update referrals and calculate commissions
            updated_referrals = []
            
            for referrer_id, attributed_value in attributions:
                # Find corresponding referral
                for tp in touchpoints:
                    if tp['referrer_id'] == referrer_id:
                        referral = await db.get(Referral, tp['id'])
                        if referral:
                            referral.status = ReferralStatus.CONVERTED
                            referral.conversion_at = datetime.utcnow()
                            referral.conversion_value = attributed_value
                            
                            # Calculate commission
                            if campaign:
                                commission = await self._calculate_commission(
                                    campaign,
                                    attributed_value
                                )
                                referral.commission_amount = commission
                            
                            updated_referrals.append(referral)
                            break
            
            # Update campaign stats
            if campaign:
                campaign.total_conversions += 1
                campaign.total_revenue += conversion_value
            
            await db.commit()
            
            return updated_referrals[0] if updated_referrals else None
    
    async def get_referral_stats(
        self,
        referrer_id: str,
        tenant_id: str,
        campaign_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get referral statistics for user"""
        async with self.db_factory() as db:
            query = select(Referral).where(
                and_(
                    Referral.referrer_id == referrer_id,
                    Referral.tenant_id == tenant_id
                )
            )
            
            if campaign_id:
                query = query.where(Referral.campaign_id == campaign_id)
            
            result = await db.execute(query)
            referrals = result.scalars().all()
            
            stats = {
                'total_referrals': len(referrals),
                'total_clicks': sum(r.click_count for r in referrals),
                'total_signups': sum(1 for r in referrals if r.signup_at),
                'total_conversions': sum(1 for r in referrals if r.conversion_at),
                'total_revenue': sum(
                    r.conversion_value or 0 for r in referrals
                ),
                'total_commission': sum(
                    r.commission_amount or 0 for r in referrals
                ),
                'conversion_rate': 0,
                'average_order_value': 0
            }
            
            if stats['total_signups'] > 0:
                stats['conversion_rate'] = (
                    stats['total_conversions'] / stats['total_signups']
                )
            
            if stats['total_conversions'] > 0:
                stats['average_order_value'] = (
                    stats['total_revenue'] / stats['total_conversions']
                )
            
            return stats
    
    async def _get_user_referral_count(
        self,
        db: AsyncSession,
        referrer_id: str,
        campaign_id: str
    ) -> int:
        """Get count of user's referrals for campaign"""
        result = await db.execute(
            select(func.count(Referral.id)).where(
                and_(
                    Referral.referrer_id == referrer_id,
                    Referral.campaign_id == campaign_id
                )
            )
        )
        return result.scalar() or 0
    
    async def _get_user_touchpoints(
        self,
        db: AsyncSession,
        user_id: str
    ) -> List[Dict[str, Any]]:
        """Get all referral touchpoints for user"""
        result = await db.execute(
            select(Referral).where(
                and_(
                    Referral.referred_id == user_id,
                    Referral.status != ReferralStatus.FRAUDULENT
                )
            ).order_by(Referral.signup_at)
        )
        referrals = result.scalars().all()
        
        return [
            {
                'id': r.id,
                'referrer_id': r.referrer_id,
                'campaign_id': r.campaign_id,
                'timestamp': r.signup_at or r.first_click_at or r.created_at
            }
            for r in referrals
        ]
    
    async def _calculate_commission(
        self,
        campaign: ReferralCampaign,
        conversion_value: float
    ) -> float:
        """Calculate commission based on campaign settings"""
        config = campaign.commission_config
        
        if campaign.commission_type == CommissionType.PERCENTAGE:
            rate = config.get('rate', 0) / 100
            return conversion_value * rate
            
        elif campaign.commission_type == CommissionType.FIXED:
            return config.get('amount', 0)
            
        elif campaign.commission_type == CommissionType.TIERED:
            # Find applicable tier
            tiers = config.get('tiers', [])
            for tier in sorted(tiers, key=lambda x: x['threshold'], reverse=True):
                if conversion_value >= tier['threshold']:
                    if tier['type'] == 'percentage':
                        return conversion_value * (tier['rate'] / 100)
                    else:
                        return tier['amount']
            return 0
            
        else:
            return 0