"""
Stripe service for Platform Forge billing
"""
import os
import logging
from typing import Dict, Any, Optional
import stripe
from datetime import datetime

from ..core.config import settings

logger = logging.getLogger(__name__)


class StripeService:
    """Service for handling Stripe operations."""
    
    def __init__(self):
        self.api_key = settings.STRIPE_API_KEY or os.getenv("STRIPE_API_KEY")
        self.webhook_secret = settings.STRIPE_WEBHOOK_SECRET or os.getenv("STRIPE_WEBHOOK_SECRET")
        
        if self.api_key:
            stripe.api_key = self.api_key
            logger.info("Stripe API initialized")
        else:
            logger.warning("Stripe API key not configured")
    
    def create_customer(self, email: str, name: str, metadata: Dict[str, Any] = None) -> "stripe.Customer":
        """Create a new Stripe customer."""
        try:
            return stripe.Customer.create(
                email=email,
                name=name,
                metadata=metadata or {}
            )
        except stripe.error.StripeError as e:
            logger.error(f"Error creating Stripe customer: {e}")
            raise
    
    def create_checkout_session(
        self,
        customer_id: str,
        price_id: str,
        success_url: str,
        cancel_url: str,
        metadata: Dict[str, Any] = None
    ) -> "stripe.checkout.Session":
        """Create a Stripe checkout session."""
        try:
            return stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=["card"],
                line_items=[{
                    "price": price_id,
                    "quantity": 1,
                }],
                mode="subscription",
                success_url=success_url,
                cancel_url=cancel_url,
                metadata=metadata or {}
            )
        except stripe.error.StripeError as e:
            logger.error(f"Error creating checkout session: {e}")
            raise
    
    def create_portal_session(self, customer_id: str, return_url: str) -> "stripe.billing_portal.Session":
        """Create a billing portal session."""
        try:
            return stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url
            )
        except stripe.error.StripeError as e:
            logger.error(f"Error creating portal session: {e}")
            raise
    
    def process_webhook(self, payload: bytes, signature: str) -> "stripe.Event":
        """Process and verify a Stripe webhook."""
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
            return event
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            raise
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            raise
    
    def cancel_subscription(self, subscription_id: str) -> "stripe.Subscription":
        """Cancel a subscription."""
        try:
            return stripe.Subscription.delete(subscription_id)
        except stripe.error.StripeError as e:
            logger.error(f"Error canceling subscription: {e}")
            raise
    
    def update_subscription(self, subscription_id: str, price_id: str, tenant_id: str = None) -> "stripe.Subscription":
        """
        Update a subscription to a new price with server-side validation.
        Addresses CRITICAL-004: Price Validation Bypass
        """
        try:
            # CRITICAL SECURITY FIX: Validate price_id before updating subscription
            if tenant_id:
                # Import here to avoid circular imports
                from .routes import _validate_and_get_price_details
                import asyncio
                
                # Validate price on server-side (same validation as checkout)
                validated_price = asyncio.run(_validate_and_get_price_details(price_id, tenant_id))
                if not validated_price:
                    logger.warning(
                        f"SECURITY: Invalid price_id attempted in subscription update: {price_id} "
                        f"for tenant {tenant_id}"
                    )
                    raise stripe.error.InvalidRequestError(
                        message="Invalid price ID - not authorized for this tenant",
                        param="price_id"
                    )
                
                # Log successful price validation for audit trail
                logger.info(
                    f"Subscription update price validated: subscription={subscription_id}, "
                    f"price_id={validated_price['id']}, amount={validated_price['unit_amount']}, "
                    f"tenant={tenant_id}"
                )
            else:
                # If no tenant_id provided, still validate that price exists in Stripe
                try:
                    stripe_price = stripe.Price.retrieve(price_id)
                    logger.info(f"Subscription update: Stripe price {price_id} exists")
                except stripe.error.InvalidRequestError:
                    logger.warning(f"SECURITY: Invalid Stripe price_id attempted: {price_id}")
                    raise
            
            # Proceed with validated price update
            subscription = stripe.Subscription.retrieve(subscription_id)
            updated_subscription = stripe.Subscription.modify(
                subscription_id,
                items=[{
                    "id": subscription["items"]["data"][0].id,
                    "price": price_id,  # Now validated
                }]
            )
            
            # Log successful update for audit trail
            logger.info(
                f"Subscription updated successfully: id={subscription_id}, "
                f"new_price={price_id}, tenant={tenant_id or 'unknown'}"
            )
            
            return updated_subscription
            
        except stripe.error.StripeError as e:
            logger.error(f"Error updating subscription: {e}")
            raise


# Create singleton instance
stripe_service = StripeService()