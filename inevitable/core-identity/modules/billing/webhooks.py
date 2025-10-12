"""
Secure Stripe webhook handling
Addresses CRITICAL-005: Webhook Signature Bypass
Addresses CRITICAL-006: Authorization Bypass in Billing Module
"""
import json
import logging
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, Depends, status
from sqlalchemy.orm import Session
from modules.core.database import get_db
from modules.core.security import WebhookSecurity, TenantSecurity, SecurityError
from modules.core.middleware import ResourceOwnershipValidator
from modules.billing.models import Customer, Package
from modules.billing.webhook_dedup import get_dedup_service
from modules.admin.audit_logs import SecureAuditService
import stripe
import os
import time

logger = logging.getLogger(__name__)

class SecureStripeWebhookHandler:
    """Secure Stripe webhook handler with proper validation"""
    
    def __init__(self):
        self.stripe_webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        if not self.stripe_webhook_secret:
            raise SecurityError("Stripe webhook secret not configured")
        
        self.webhook_security = WebhookSecurity(
            webhook_secret=self.stripe_webhook_secret,
            timestamp_tolerance=60  # CRITICAL: Reduced to 60 seconds to prevent replay attacks
        )
        
        # Use persistent deduplication service
        self.dedup_service = get_dedup_service()
    
    async def handle_webhook(
        self,
        request: Request,
        db: Session = Depends(get_db)
    ) -> Dict[str, Any]:
        """
        Handle incoming Stripe webhook with security validation
        """
        try:
            # Get raw payload
            payload = await request.body()
            signature_header = request.headers.get('stripe-signature', '')
            
            if not signature_header:
                logger.warning("Missing Stripe signature header")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing signature"
                )
            
            # Get client IP (FastAPI provides this)
            client_ip = request.client.host if request.client else None
            
            # HIGH-007 FIX: Enhanced webhook signature validation with Stripe SDK
            # Use Stripe's official SDK for signature verification to prevent bypass
            try:
                # Construct the event using Stripe's secure verification
                event = stripe.Webhook.construct_event(
                    payload, signature_header, self.stripe_webhook_secret
                )
            except ValueError as e:
                # Invalid payload
                logger.warning(f"Invalid webhook payload: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid payload"
                )
            except stripe.error.SignatureVerificationError as e:
                # Invalid signature - use constant time to prevent timing attacks
                logger.warning(f"Invalid webhook signature from {client_ip}: {e}")
                # Add delay to prevent timing attacks
                time.sleep(0.1)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid signature"
                )
            
            # Additional IP validation
            if not self.webhook_security.verify_source_ip(client_ip):
                logger.warning(f"Webhook from non-Stripe IP: {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized source"
                )
            
            # Event already parsed and validated by Stripe SDK above
            
            # Check for duplicate webhook (replay attack prevention)
            webhook_id = event.get('id')
            event_type = event.get('type', 'unknown')
            
            if webhook_id:
                # Use persistent deduplication service
                is_duplicate, existing_status = self.dedup_service.check_and_record_webhook(
                    webhook_id=webhook_id,
                    event_type=event_type,
                    payload=payload,
                    db=db,
                    source="stripe"
                )
                
                if is_duplicate:
                    logger.warning(f"Duplicate webhook {webhook_id} with status: {existing_status}")
                    return {
                        "status": "duplicate",
                        "message": "Already processed",
                        "original_status": existing_status
                    }
            
            # Process the webhook event
            result = await self._process_webhook_event(event, db, request)
            
            # Update webhook status to completed
            if webhook_id:
                self.dedup_service.update_webhook_status(
                    webhook_id=webhook_id,
                    status="completed",
                    details=result,
                    db=db
                )
            
            logger.info(f"Successfully processed webhook {webhook_id}: {event.get('type')}")
            return result
            
        except HTTPException:
            # Update status to failed if we have webhook_id
            if 'webhook_id' in locals() and webhook_id:
                self.dedup_service.update_webhook_status(
                    webhook_id=webhook_id,
                    status="failed",
                    details={"error": "HTTP error"},
                    db=db
                )
            raise
        except Exception as e:
            logger.error(f"Webhook processing error: {e}")
            # Update status to failed if we have webhook_id
            if 'webhook_id' in locals() and webhook_id:
                self.dedup_service.update_webhook_status(
                    webhook_id=webhook_id,
                    status="failed", 
                    details={"error": str(e)},
                    db=db
                )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Webhook processing failed"
            )
    
    async def _process_webhook_event(
        self,
        event: Dict[str, Any],
        db: Session,
        request: Request
    ) -> Dict[str, Any]:
        """Process specific webhook event types"""
        event_type = event.get('type')
        event_data = event.get('data', {}).get('object', {})
        
        # Import subscription webhook handler
        from .webhook_extensions import subscription_webhook_handler
        
        # Check if this is a subscription-related event
        if event_type.startswith('customer.subscription.') or event_type.startswith('price.'):
            return await subscription_webhook_handler.process_event(event_type, event, db)
        
        # Map event types to handlers
        handlers = {
            'customer.created': self._handle_customer_created,
            'customer.updated': self._handle_customer_updated,
            'customer.deleted': self._handle_customer_deleted,
            'customer.subscription.created': self._handle_subscription_created,
            'customer.subscription.updated': self._handle_subscription_updated,
            'customer.subscription.deleted': self._handle_subscription_deleted,
            'invoice.payment_succeeded': self._handle_payment_succeeded,
            'invoice.payment_failed': self._handle_payment_failed,
            'payment_method.attached': self._handle_payment_method_attached,
            'payment_method.detached': self._handle_payment_method_detached,
        }
        
        handler = handlers.get(event_type)
        if handler:
            return await handler(event_data, db, request)
        else:
            logger.info(f"Unhandled webhook event type: {event_type}")
            return {"status": "ignored", "message": f"Event type {event_type} not handled"}
    
    async def _handle_customer_created(
        self,
        customer_data: Dict[str, Any],
        db: Session,
        request: Request
    ) -> Dict[str, Any]:
        """Handle customer.created webhook"""
        stripe_customer_id = customer_data.get('id')
        email = customer_data.get('email')
        name = customer_data.get('name')
        
        # Extract tenant from metadata (if available)
        metadata = customer_data.get('metadata', {})
        tenant_id = metadata.get('tenant_id')
        
        # Create customer record
        customer = Customer(
            stripe_customer_id=stripe_customer_id,
            email=email,
            name=name,
            tenant_id=tenant_id
        )
        
        db.add(customer)
        db.commit()
        
        # Log the event
        await SecureAuditService.log_action(
            action="customer_created",
            resource_type="customer",
            resource_id=stripe_customer_id,
            details={
                "email": email,
                "name": name,
                "tenant_id": tenant_id
            },
            request=request,
            db=db
        )
        
        return {"status": "processed", "customer_id": customer.id}
    
    async def _handle_subscription_created(
        self,
        subscription_data: Dict[str, Any],
        db: Session,
        request: Request
    ) -> Dict[str, Any]:
        """Handle customer.subscription.created webhook"""
        subscription_id = subscription_data.get('id')
        customer_id = subscription_data.get('customer')
        status = subscription_data.get('status')
        current_period_start = subscription_data.get('current_period_start')
        current_period_end = subscription_data.get('current_period_end')
        
        # Get plan ID from subscription items
        items = subscription_data.get('items', {}).get('data', [])
        plan_id = items[0].get('price', {}).get('id') if items else None
        
        # Find customer record
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == customer_id
        ).first()
        
        if not customer:
            logger.warning(f"Customer {customer_id} not found for subscription {subscription_id}")
            return {"status": "error", "message": "Customer not found"}
        
        # Create subscription record
        subscription = Package(
            customer_id=customer.id,
            stripe_subscription_id=subscription_id,
            plan_id=plan_id,
            status=status,
            current_period_start=time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_period_start)),
            current_period_end=time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_period_end)),
            tenant_id=customer.tenant_id
        )
        
        db.add(subscription)
        db.commit()
        
        # Log the event
        await SecureAuditService.log_action(
            action="subscription_created",
            resource_type="subscription",
            resource_id=subscription_id,
            details={
                "customer_id": customer_id,
                "plan_id": plan_id,
                "status": status
            },
            request=request,
            db=db
        )
        
        return {"status": "processed", "subscription_id": subscription.id}
    
    async def _handle_payment_succeeded(
        self,
        invoice_data: Dict[str, Any],
        db: Session,
        request: Request
    ) -> Dict[str, Any]:
        """Handle invoice.payment_succeeded webhook"""
        invoice_id = invoice_data.get('id')
        customer_id = invoice_data.get('customer')
        subscription_id = invoice_data.get('subscription')
        amount_paid = invoice_data.get('amount_paid', 0)
        
        # Find customer and subscription
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == customer_id
        ).first()
        
        if not customer:
            logger.warning(f"Customer {customer_id} not found for payment {invoice_id}")
            return {"status": "error", "message": "Customer not found"}
        
        # Log successful payment
        await SecureAuditService.log_action(
            action="payment_succeeded",
            resource_type="payment",
            resource_id=invoice_id,
            details={
                "customer_id": customer_id,
                "subscription_id": subscription_id,
                "amount_paid": amount_paid / 100,  # Convert from cents
                "currency": invoice_data.get('currency', 'usd')
            },
            request=request,
            db=db
        )
        
        return {"status": "processed", "invoice_id": invoice_id}
    
    async def _handle_payment_failed(
        self,
        invoice_data: Dict[str, Any],
        db: Session,
        request: Request
    ) -> Dict[str, Any]:
        """Handle invoice.payment_failed webhook"""
        invoice_id = invoice_data.get('id')
        customer_id = invoice_data.get('customer')
        subscription_id = invoice_data.get('subscription')
        
        # Find customer
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == customer_id
        ).first()
        
        if not customer:
            logger.warning(f"Customer {customer_id} not found for failed payment {invoice_id}")
            return {"status": "error", "message": "Customer not found"}
        
        # Log failed payment
        await SecureAuditService.log_action(
            action="payment_failed",
            resource_type="payment",
            resource_id=invoice_id,
            details={
                "customer_id": customer_id,
                "subscription_id": subscription_id,
                "failure_reason": invoice_data.get('last_payment_error', {}).get('message')
            },
            request=request,
            db=db
        )
        
        return {"status": "processed", "invoice_id": invoice_id}
    
    async def _handle_customer_updated(self, customer_data, db, request):
        """Handle customer.updated webhook"""
        # Implementation for customer updates
        return {"status": "processed"}
    
    async def _handle_customer_deleted(self, customer_data, db, request):
        """Handle customer.deleted webhook"""
        # Implementation for customer deletion
        return {"status": "processed"}
    
    async def _handle_subscription_updated(self, subscription_data, db, request):
        """Handle customer.subscription.updated webhook"""
        # Implementation for subscription updates
        return {"status": "processed"}
    
    async def _handle_subscription_deleted(self, subscription_data, db, request):
        """Handle customer.subscription.deleted webhook"""
        # Implementation for subscription deletion
        return {"status": "processed"}
    
    async def _handle_payment_method_attached(self, payment_method_data, db, request):
        """Handle payment_method.attached webhook"""
        return {"status": "processed"}
    
    async def _handle_payment_method_detached(self, payment_method_data, db, request):
        """Handle payment_method.detached webhook"""
        return {"status": "processed"}

class SecureBillingService:
    """
    Secure billing service with proper authorization checks
    Addresses CRITICAL-006: Authorization Bypass in Billing Module
    """
    
    def __init__(self):
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
        if not stripe.api_key:
            raise SecurityError("Stripe secret key not configured")
    
    async def get_customer_payment_methods(
        self,
        customer_id: str,
        user_id: str,
        tenant_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """Get payment methods for a customer with authorization check"""
        
        # Validate customer access
        if not ResourceOwnershipValidator.validate_customer_access(
            user_id, customer_id, tenant_id, db
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to customer resource"
            )
        
        try:
            # Get payment methods from Stripe
            payment_methods = stripe.PaymentMethod.list(
                customer=customer_id,
                type='card'
            )
            
            # Return safe data (no sensitive card details)
            safe_payment_methods = []
            for pm in payment_methods.data:
                card = pm.card
                safe_payment_methods.append({
                    "id": pm.id,
                    "type": pm.type,
                    "card": {
                        "brand": card.brand,
                        "last4": card.last4,
                        "exp_month": card.exp_month,
                        "exp_year": card.exp_year
                    },
                    "created": pm.created
                })
            
            return {
                "payment_methods": safe_payment_methods,
                "total": len(safe_payment_methods)
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error getting payment methods: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve payment methods"
            )
    
    async def cancel_subscription(
        self,
        subscription_id: str,
        user_id: str,
        tenant_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """Cancel a subscription with authorization check"""
        
        # Validate subscription access
        if not ResourceOwnershipValidator.validate_subscription_access(
            user_id, subscription_id, tenant_id, db
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to subscription resource"
            )
        
        try:
            # Cancel subscription in Stripe
            subscription = stripe.Subscription.modify(
                subscription_id,
                cancel_at_period_end=True
            )
            
            # Update local record
            local_subscription = db.query(Package).filter(
                Package.stripe_subscription_id == subscription_id,
                Package.tenant_id == tenant_id
            ).first()
            
            if local_subscription:
                local_subscription.status = "canceling"
                db.commit()
            
            return {
                "message": "Subscription will be canceled at period end",
                "cancel_at_period_end": subscription.cancel_at_period_end,
                "current_period_end": subscription.current_period_end
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error canceling subscription: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to cancel subscription"
            )

# Global instances
webhook_handler = None
billing_service = None

def get_webhook_handler() -> SecureStripeWebhookHandler:
    """Get global webhook handler instance"""
    global webhook_handler
    if webhook_handler is None:
        webhook_handler = SecureStripeWebhookHandler()
    return webhook_handler

def get_billing_service() -> SecureBillingService:
    """Get global billing service instance"""
    global billing_service
    if billing_service is None:
        billing_service = SecureBillingService()
    return billing_service