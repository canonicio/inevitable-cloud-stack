"""
Stripe Webhook Router
Secure webhook endpoints for Stripe events
"""
from fastapi import APIRouter, Request, Depends
from sqlalchemy.orm import Session
from modules.core.database import get_db
from modules.billing.webhooks import get_webhook_handler

router = APIRouter()

@router.post("/stripe")
async def stripe_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Handle Stripe webhook events
    
    This endpoint receives and processes Stripe webhook events with proper
    security validation including signature verification and replay protection.
    """
    webhook_handler = get_webhook_handler()
    return await webhook_handler.handle_webhook(request, db)
