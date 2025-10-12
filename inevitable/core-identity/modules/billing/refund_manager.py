"""
Comprehensive Refund Management System
Addresses missing refund functionality identified in threat model
"""

from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime, timedelta
import stripe
from sqlalchemy.orm import Session
from fastapi import HTTPException, Depends
import logging

from modules.core.database import get_db
from modules.auth.dependencies import get_current_user, require_permission
from modules.billing.models import Refund, Subscription, Invoice
from modules.core.audit_logger import AuditLogger
from modules.core.security import SecurityUtils

logger = logging.getLogger(__name__)
audit_logger = AuditLogger()

class RefundStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved" 
    REJECTED = "rejected"
    PROCESSED = "processed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class RefundReason(Enum):
    CUSTOMER_REQUEST = "customer_request"
    BILLING_ERROR = "billing_error"
    SERVICE_ISSUE = "service_issue"
    FRAUDULENT_CHARGE = "fraudulent_charge"
    DUPLICATE_PAYMENT = "duplicate_payment"
    CANCELLATION = "cancellation"
    CHARGEBACK = "chargeback"

class RefundManager:
    """Comprehensive refund management with fraud prevention"""
    
    def __init__(self, db: Session):
        self.db = db
        self.stripe_client = stripe
        
    async def request_refund(
        self, 
        invoice_id: str,
        amount_cents: Optional[int] = None,
        reason: RefundReason = RefundReason.CUSTOMER_REQUEST,
        customer_note: Optional[str] = None,
        tenant_id: str = None,
        user_id: str = None
    ) -> Dict[str, Any]:
        """
        Request a refund with comprehensive validation and fraud prevention
        """
        try:
            # Validate invoice exists and belongs to tenant
            invoice = self.db.query(Invoice).filter(
                Invoice.id == invoice_id,
                Invoice.tenant_id == tenant_id
            ).first()
            
            if not invoice:
                raise HTTPException(status_code=404, detail="Invoice not found")
            
            # Check if invoice is refundable
            if not self._is_refundable(invoice):
                raise HTTPException(
                    status_code=400, 
                    detail="Invoice is not eligible for refund"
                )
            
            # Validate refund amount
            refund_amount = amount_cents or invoice.amount_cents
            if refund_amount > invoice.amount_cents:
                raise HTTPException(
                    status_code=400,
                    detail="Refund amount cannot exceed invoice amount"
                )
            
            # Check for duplicate refund requests
            existing_refund = self._check_duplicate_refund(invoice_id, tenant_id)
            if existing_refund:
                return {
                    "status": "duplicate",
                    "refund_id": existing_refund.id,
                    "message": "Refund request already exists"
                }
            
            # Fraud detection checks
            fraud_score = await self._calculate_fraud_score(
                tenant_id, user_id, invoice, refund_amount, reason
            )
            
            # Determine approval workflow
            requires_approval = self._requires_manual_approval(
                fraud_score, refund_amount, reason
            )
            
            # Create refund record
            refund = Refund(
                id=SecurityUtils.generate_secure_id(),
                tenant_id=tenant_id,
                invoice_id=invoice_id,
                user_id=user_id,
                amount_cents=refund_amount,
                reason=reason.value,
                customer_note=customer_note,
                status=RefundStatus.PENDING.value if requires_approval else RefundStatus.APPROVED.value,
                fraud_score=fraud_score,
                requires_approval=requires_approval,
                requested_at=datetime.utcnow()
            )
            
            self.db.add(refund)
            self.db.commit()
            
            # Audit logging
            await audit_logger.log_event(
                tenant_id=tenant_id,
                user_id=user_id,
                action="refund_requested",
                resource_type="refund",
                resource_id=refund.id,
                details={
                    "invoice_id": invoice_id,
                    "amount_cents": refund_amount,
                    "reason": reason.value,
                    "fraud_score": fraud_score,
                    "requires_approval": requires_approval
                }
            )
            
            # Auto-process if approved
            if not requires_approval:
                return await self._process_refund(refund)
            
            return {
                "status": "pending_approval",
                "refund_id": refund.id,
                "estimated_approval_time": "24-48 hours",
                "fraud_score": fraud_score
            }
            
        except Exception as e:
            logger.error(f"Refund request failed: {e}")
            raise HTTPException(status_code=500, detail="Refund request failed")
    
    async def approve_refund(
        self, 
        refund_id: str,
        approver_id: str,
        approval_note: Optional[str] = None,
        tenant_id: str = None
    ) -> Dict[str, Any]:
        """Approve a pending refund request"""
        
        refund = self.db.query(Refund).filter(
            Refund.id == refund_id,
            Refund.tenant_id == tenant_id,
            Refund.status == RefundStatus.PENDING.value
        ).first()
        
        if not refund:
            raise HTTPException(status_code=404, detail="Pending refund not found")
        
        # Update refund status
        refund.status = RefundStatus.APPROVED.value
        refund.approved_by = approver_id
        refund.approved_at = datetime.utcnow()
        refund.approval_note = approval_note
        
        self.db.commit()
        
        # Process the refund
        return await self._process_refund(refund)
    
    async def reject_refund(
        self,
        refund_id: str,
        rejector_id: str,
        rejection_reason: str,
        tenant_id: str = None
    ) -> Dict[str, Any]:
        """Reject a pending refund request"""
        
        refund = self.db.query(Refund).filter(
            Refund.id == refund_id,
            Refund.tenant_id == tenant_id,
            Refund.status == RefundStatus.PENDING.value
        ).first()
        
        if not refund:
            raise HTTPException(status_code=404, detail="Pending refund not found")
        
        refund.status = RefundStatus.REJECTED.value
        refund.rejected_by = rejector_id
        refund.rejected_at = datetime.utcnow()
        refund.rejection_reason = rejection_reason
        
        self.db.commit()
        
        await audit_logger.log_event(
            tenant_id=tenant_id,
            user_id=rejector_id,
            action="refund_rejected",
            resource_type="refund",
            resource_id=refund_id,
            details={"reason": rejection_reason}
        )
        
        return {
            "status": "rejected",
            "refund_id": refund_id,
            "reason": rejection_reason
        }
    
    async def _process_refund(self, refund: Refund) -> Dict[str, Any]:
        """Process an approved refund through Stripe"""
        try:
            # Get invoice details
            invoice = self.db.query(Invoice).filter(
                Invoice.id == refund.invoice_id
            ).first()
            
            if not invoice or not invoice.stripe_payment_intent_id:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot process refund: Invalid invoice"
                )
            
            # Create Stripe refund
            stripe_refund = self.stripe_client.Refund.create(
                payment_intent=invoice.stripe_payment_intent_id,
                amount=refund.amount_cents,
                reason='requested_by_customer',
                metadata={
                    'refund_id': refund.id,
                    'tenant_id': refund.tenant_id,
                    'invoice_id': refund.invoice_id
                }
            )
            
            # Update refund record
            refund.status = RefundStatus.PROCESSED.value
            refund.stripe_refund_id = stripe_refund.id
            refund.processed_at = datetime.utcnow()
            
            self.db.commit()
            
            # Update invoice
            invoice.refunded_amount_cents = (invoice.refunded_amount_cents or 0) + refund.amount_cents
            if invoice.refunded_amount_cents >= invoice.amount_cents:
                invoice.status = "refunded"
            else:
                invoice.status = "partially_refunded"
            
            self.db.commit()
            
            await audit_logger.log_event(
                tenant_id=refund.tenant_id,
                user_id=refund.approved_by or "system",
                action="refund_processed",
                resource_type="refund", 
                resource_id=refund.id,
                details={
                    "stripe_refund_id": stripe_refund.id,
                    "amount_cents": refund.amount_cents
                }
            )
            
            return {
                "status": "processed",
                "refund_id": refund.id,
                "stripe_refund_id": stripe_refund.id,
                "amount_cents": refund.amount_cents,
                "expected_arrival": "5-10 business days"
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe refund failed: {e}")
            refund.status = RefundStatus.FAILED.value
            refund.failure_reason = str(e)
            self.db.commit()
            
            raise HTTPException(
                status_code=400,
                detail=f"Refund processing failed: {e.user_message}"
            )
    
    def _is_refundable(self, invoice: Invoice) -> bool:
        """Check if invoice is eligible for refund"""
        # Cannot refund if already fully refunded
        if invoice.status == "refunded":
            return False
        
        # Check refund window (e.g., 30 days)
        refund_window = timedelta(days=30)
        if datetime.utcnow() - invoice.created_at > refund_window:
            return False
        
        # Cannot refund disputed/charged back invoices
        if invoice.status in ["disputed", "chargeback"]:
            return False
        
        # Must be paid
        if invoice.status != "paid":
            return False
        
        return True
    
    def _check_duplicate_refund(self, invoice_id: str, tenant_id: str) -> Optional[Refund]:
        """Check for existing refund requests"""
        return self.db.query(Refund).filter(
            Refund.invoice_id == invoice_id,
            Refund.tenant_id == tenant_id,
            Refund.status.in_([
                RefundStatus.PENDING.value,
                RefundStatus.APPROVED.value,
                RefundStatus.PROCESSED.value
            ])
        ).first()
    
    async def _calculate_fraud_score(
        self,
        tenant_id: str,
        user_id: str,
        invoice: Invoice,
        refund_amount: int,
        reason: RefundReason
    ) -> float:
        """Calculate fraud risk score for refund request"""
        score = 0.0
        
        # Recent refund history (last 30 days)
        recent_refunds = self.db.query(Refund).filter(
            Refund.tenant_id == tenant_id,
            Refund.created_at >= datetime.utcnow() - timedelta(days=30),
            Refund.status != RefundStatus.REJECTED.value
        ).count()
        
        score += min(recent_refunds * 0.2, 0.8)  # Max 0.8 for recent refunds
        
        # Large refund amount
        if refund_amount > 100000:  # $1000+
            score += 0.3
        
        # Invoice age (immediate refund requests are suspicious)
        invoice_age_hours = (datetime.utcnow() - invoice.created_at).total_seconds() / 3600
        if invoice_age_hours < 1:  # Less than 1 hour
            score += 0.4
        
        # Suspicious reasons
        if reason in [RefundReason.FRAUDULENT_CHARGE, RefundReason.CHARGEBACK]:
            score += 0.3
        
        # Customer account age
        # (This would require user table access - implement based on your user model)
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _requires_manual_approval(
        self,
        fraud_score: float,
        refund_amount: int,
        reason: RefundReason
    ) -> bool:
        """Determine if refund requires manual approval"""
        
        # High fraud score always requires approval
        if fraud_score >= 0.7:
            return True
        
        # Large amounts require approval
        if refund_amount >= 50000:  # $500+
            return True
        
        # Certain reasons require approval
        approval_reasons = [
            RefundReason.FRAUDULENT_CHARGE,
            RefundReason.CHARGEBACK,
            RefundReason.DUPLICATE_PAYMENT
        ]
        
        if reason in approval_reasons:
            return True
        
        return False
    
    async def get_refund_history(
        self,
        tenant_id: str,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[RefundStatus] = None
    ) -> Dict[str, Any]:
        """Get refund history for tenant"""
        
        query = self.db.query(Refund).filter(Refund.tenant_id == tenant_id)
        
        if status_filter:
            query = query.filter(Refund.status == status_filter.value)
        
        total = query.count()
        refunds = query.order_by(Refund.created_at.desc()).offset(offset).limit(limit).all()
        
        return {
            "refunds": [
                {
                    "id": refund.id,
                    "invoice_id": refund.invoice_id,
                    "amount_cents": refund.amount_cents,
                    "status": refund.status,
                    "reason": refund.reason,
                    "created_at": refund.created_at.isoformat(),
                    "processed_at": refund.processed_at.isoformat() if refund.processed_at else None,
                    "stripe_refund_id": refund.stripe_refund_id
                }
                for refund in refunds
            ],
            "total": total,
            "limit": limit,
            "offset": offset
        }

# Dependency injection
def get_refund_manager(db: Session = Depends(get_db)) -> RefundManager:
    return RefundManager(db)