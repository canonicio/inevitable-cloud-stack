"""
Refund Management API Routes
Provides comprehensive refund request and management endpoints
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from modules.core.database import get_db
from modules.auth.dependencies import get_current_user, require_permission
from modules.auth.models import User
from modules.billing.refund_manager import RefundManager, RefundStatus, RefundReason, get_refund_manager

router = APIRouter()

class RefundRequest(BaseModel):
    """Request model for refund creation"""
    invoice_id: str = Field(..., min_length=1, max_length=255)
    amount_cents: Optional[int] = Field(None, gt=0, description="Partial refund amount in cents")
    reason: RefundReason = Field(default=RefundReason.CUSTOMER_REQUEST)
    customer_note: Optional[str] = Field(None, max_length=1000)

class RefundResponse(BaseModel):
    """Response model for refund operations"""
    refund_id: str
    status: str
    message: Optional[str] = None
    estimated_approval_time: Optional[str] = None
    fraud_score: Optional[float] = None
    stripe_refund_id: Optional[str] = None
    amount_cents: Optional[int] = None
    expected_arrival: Optional[str] = None

class RefundApprovalRequest(BaseModel):
    """Request model for refund approval/rejection"""
    approval_note: Optional[str] = Field(None, max_length=1000)

class RefundRejectionRequest(BaseModel):
    """Request model for refund rejection"""
    rejection_reason: str = Field(..., min_length=1, max_length=1000)

class RefundHistoryResponse(BaseModel):
    """Response model for refund history"""
    refunds: List[dict]
    total: int
    limit: int
    offset: int

@router.post("/refunds/request", response_model=RefundResponse)
async def request_refund(
    request: RefundRequest,
    current_user: User = Depends(get_current_user),
    refund_manager: RefundManager = Depends(get_refund_manager)
):
    """
    Request a refund for an invoice
    
    **Required Permission**: billing:refund:request
    **MFA Required**: For refunds > $500
    """
    # Check if user has permission to request refunds
    if not require_permission("billing:refund:request", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # For high-value refunds, require MFA
    if request.amount_cents and request.amount_cents > 50000:  # $500+
        if not current_user.mfa_verified:
            raise HTTPException(
                status_code=403, 
                detail="MFA verification required for high-value refunds"
            )
    
    result = await refund_manager.request_refund(
        invoice_id=request.invoice_id,
        amount_cents=request.amount_cents,
        reason=request.reason,
        customer_note=request.customer_note,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id
    )
    
    return RefundResponse(**result)

@router.post("/refunds/{refund_id}/approve", response_model=RefundResponse)
async def approve_refund(
    refund_id: str,
    request: RefundApprovalRequest,
    current_user: User = Depends(get_current_user),
    refund_manager: RefundManager = Depends(get_refund_manager)
):
    """
    Approve a pending refund request
    
    **Required Permission**: billing:refund:approve
    **MFA Required**: Always
    """
    # Check if user has permission to approve refunds
    if not require_permission("billing:refund:approve", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Always require MFA for refund approvals
    if not current_user.mfa_verified:
        raise HTTPException(
            status_code=403, 
            detail="MFA verification required for refund approval"
        )
    
    result = await refund_manager.approve_refund(
        refund_id=refund_id,
        approver_id=current_user.id,
        approval_note=request.approval_note,
        tenant_id=current_user.tenant_id
    )
    
    return RefundResponse(**result)

@router.post("/refunds/{refund_id}/reject", response_model=RefundResponse)
async def reject_refund(
    refund_id: str,
    request: RefundRejectionRequest,
    current_user: User = Depends(get_current_user),
    refund_manager: RefundManager = Depends(get_refund_manager)
):
    """
    Reject a pending refund request
    
    **Required Permission**: billing:refund:approve
    **MFA Required**: Always
    """
    # Check if user has permission to reject refunds
    if not require_permission("billing:refund:approve", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    # Always require MFA for refund rejections
    if not current_user.mfa_verified:
        raise HTTPException(
            status_code=403, 
            detail="MFA verification required for refund rejection"
        )
    
    result = await refund_manager.reject_refund(
        refund_id=refund_id,
        rejector_id=current_user.id,
        rejection_reason=request.rejection_reason,
        tenant_id=current_user.tenant_id
    )
    
    return RefundResponse(**result)

@router.get("/refunds/{refund_id}")
async def get_refund(
    refund_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get refund details by ID
    
    **Required Permission**: billing:refund:read
    """
    if not require_permission("billing:refund:read", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    from modules.billing.models import Refund
    
    refund = db.query(Refund).filter(
        Refund.id == refund_id,
        Refund.tenant_id == current_user.tenant_id
    ).first()
    
    if not refund:
        raise HTTPException(status_code=404, detail="Refund not found")
    
    return {
        "id": refund.id,
        "invoice_id": refund.invoice_id,
        "amount_cents": refund.amount_cents,
        "currency": refund.currency,
        "status": refund.status,
        "reason": refund.reason,
        "customer_note": refund.customer_note,
        "internal_note": refund.internal_note,
        "fraud_score": float(refund.fraud_score) if refund.fraud_score else 0.0,
        "requires_approval": refund.requires_approval,
        "approved_by": refund.approved_by,
        "approved_at": refund.approved_at.isoformat() if refund.approved_at else None,
        "approval_note": refund.approval_note,
        "rejected_by": refund.rejected_by,
        "rejected_at": refund.rejected_at.isoformat() if refund.rejected_at else None,
        "rejection_reason": refund.rejection_reason,
        "requested_at": refund.requested_at.isoformat(),
        "processed_at": refund.processed_at.isoformat() if refund.processed_at else None,
        "stripe_refund_id": refund.stripe_refund_id,
        "failure_reason": refund.failure_reason,
        "created_at": refund.created_at.isoformat(),
        "updated_at": refund.updated_at.isoformat()
    }

@router.get("/refunds", response_model=RefundHistoryResponse)
async def get_refund_history(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[RefundStatus] = Query(None),
    current_user: User = Depends(get_current_user),
    refund_manager: RefundManager = Depends(get_refund_manager)
):
    """
    Get refund history for current tenant
    
    **Required Permission**: billing:refund:read
    """
    if not require_permission("billing:refund:read", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await refund_manager.get_refund_history(
        tenant_id=current_user.tenant_id,
        limit=limit,
        offset=offset,
        status_filter=status
    )
    
    return RefundHistoryResponse(**result)

@router.get("/refunds/pending/count")
async def get_pending_refunds_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get count of pending refunds requiring approval
    
    **Required Permission**: billing:refund:approve
    """
    if not require_permission("billing:refund:approve", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    from modules.billing.models import Refund
    
    count = db.query(Refund).filter(
        Refund.tenant_id == current_user.tenant_id,
        Refund.status == RefundStatus.PENDING.value
    ).count()
    
    return {"pending_refunds": count}

@router.get("/refunds/analytics")
async def get_refund_analytics(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get refund analytics for the tenant
    
    **Required Permission**: billing:refund:analytics
    """
    if not require_permission("billing:refund:analytics", current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    from modules.billing.models import Refund
    from sqlalchemy import func
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Basic statistics
    stats = db.query(
        func.count(Refund.id).label('total_refunds'),
        func.sum(Refund.amount_cents).label('total_amount_cents'),
        func.avg(Refund.fraud_score).label('avg_fraud_score')
    ).filter(
        Refund.tenant_id == current_user.tenant_id,
        Refund.created_at >= start_date
    ).first()
    
    # Status breakdown
    status_breakdown = db.query(
        Refund.status,
        func.count(Refund.id).label('count'),
        func.sum(Refund.amount_cents).label('amount_cents')
    ).filter(
        Refund.tenant_id == current_user.tenant_id,
        Refund.created_at >= start_date
    ).group_by(Refund.status).all()
    
    # Reason breakdown
    reason_breakdown = db.query(
        Refund.reason,
        func.count(Refund.id).label('count'),
        func.sum(Refund.amount_cents).label('amount_cents')
    ).filter(
        Refund.tenant_id == current_user.tenant_id,
        Refund.created_at >= start_date
    ).group_by(Refund.reason).all()
    
    return {
        "period_days": days,
        "total_refunds": stats.total_refunds or 0,
        "total_amount_cents": int(stats.total_amount_cents or 0),
        "average_fraud_score": float(stats.avg_fraud_score or 0.0),
        "status_breakdown": [
            {
                "status": status,
                "count": count,
                "amount_cents": int(amount_cents or 0)
            }
            for status, count, amount_cents in status_breakdown
        ],
        "reason_breakdown": [
            {
                "reason": reason,
                "count": count,
                "amount_cents": int(amount_cents or 0)
            }
            for reason, count, amount_cents in reason_breakdown
        ]
    }