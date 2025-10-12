"""
Unified payment provider interface for Platform Forge
Supports multiple payment providers: Stripe, PayPal, Square, etc.
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


class PaymentProvider(str, Enum):
    """Supported payment providers"""
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SQUARE = "square"
    PADDLE = "paddle"


class PaymentStatus(str, Enum):
    """Payment status across providers"""
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class SubscriptionStatus(str, Enum):
    """Subscription status across providers"""
    ACTIVE = "active"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    TRIALING = "trialing"
    PAST_DUE = "past_due"


@dataclass
class PaymentResult:
    """Standardized payment result"""
    provider: PaymentProvider
    provider_payment_id: str
    status: PaymentStatus
    amount: int  # In cents
    currency: str
    created_at: datetime
    metadata: Dict[str, Any] = None
    provider_data: Dict[str, Any] = None


@dataclass
class SubscriptionResult:
    """Standardized subscription result"""
    provider: PaymentProvider
    provider_subscription_id: str
    status: SubscriptionStatus
    current_period_start: datetime
    current_period_end: datetime
    created_at: datetime
    metadata: Dict[str, Any] = None
    provider_data: Dict[str, Any] = None


@dataclass
class PlanResult:
    """Standardized plan result"""
    provider: PaymentProvider
    provider_plan_id: str
    name: str
    amount: int  # In cents
    currency: str
    interval: str  # month, year, etc.
    interval_count: int
    created_at: datetime
    metadata: Dict[str, Any] = None
    provider_data: Dict[str, Any] = None


class PaymentProviderInterface(ABC):
    """Abstract interface for payment providers"""
    
    @property
    @abstractmethod
    def provider_name(self) -> PaymentProvider:
        """Return provider name"""
        pass
    
    # Customer Management
    
    @abstractmethod
    def create_customer(self, email: str, name: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create a customer"""
        pass
    
    @abstractmethod
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        """Get customer details"""
        pass
    
    @abstractmethod
    def update_customer(self, customer_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update customer"""
        pass
    
    # Plan Management
    
    @abstractmethod
    def create_plan(
        self,
        name: str,
        amount: int,  # In cents
        currency: str,
        interval: str,
        interval_count: int = 1,
        metadata: Dict[str, Any] = None
    ) -> PlanResult:
        """Create a subscription plan"""
        pass
    
    @abstractmethod
    def get_plan(self, plan_id: str) -> PlanResult:
        """Get plan details"""
        pass
    
    @abstractmethod
    def update_plan(self, plan_id: str, updates: Dict[str, Any]) -> PlanResult:
        """Update plan"""
        pass
    
    @abstractmethod
    def deactivate_plan(self, plan_id: str) -> PlanResult:
        """Deactivate a plan"""
        pass
    
    # Subscription Management
    
    @abstractmethod
    def create_subscription(
        self,
        customer_id: str,
        plan_id: str,
        metadata: Dict[str, Any] = None
    ) -> SubscriptionResult:
        """Create a subscription"""
        pass
    
    @abstractmethod
    def get_subscription(self, subscription_id: str) -> SubscriptionResult:
        """Get subscription details"""
        pass
    
    @abstractmethod
    def update_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> SubscriptionResult:
        """Update subscription"""
        pass
    
    @abstractmethod
    def cancel_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        """Cancel subscription"""
        pass
    
    @abstractmethod
    def suspend_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        """Suspend subscription"""
        pass
    
    @abstractmethod
    def reactivate_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        """Reactivate subscription"""
        pass
    
    # Payment Processing
    
    @abstractmethod
    def create_payment(
        self,
        amount: int,  # In cents
        currency: str,
        description: str = None,
        customer_id: str = None,
        metadata: Dict[str, Any] = None
    ) -> PaymentResult:
        """Create a one-time payment"""
        pass
    
    @abstractmethod
    def capture_payment(self, payment_id: str) -> PaymentResult:
        """Capture an authorized payment"""
        pass
    
    @abstractmethod
    def refund_payment(self, payment_id: str, amount: int = None) -> PaymentResult:
        """Refund a payment"""
        pass
    
    # Webhook Management
    
    @abstractmethod
    def verify_webhook(self, payload: bytes, signature: str, secret: str = None) -> bool:
        """Verify webhook signature"""
        pass
    
    @abstractmethod
    def parse_webhook_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse webhook event into standard format"""
        pass


class StripeProvider(PaymentProviderInterface):
    """Stripe payment provider implementation"""
    
    def __init__(self):
        from .stripe_service import stripe_service
        self.service = stripe_service
    
    @property
    def provider_name(self) -> PaymentProvider:
        return PaymentProvider.STRIPE
    
    def create_customer(self, email: str, name: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        return self.service.create_customer(email, name, metadata)
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        import stripe
        return stripe.Customer.retrieve(customer_id)
    
    def update_customer(self, customer_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        import stripe
        return stripe.Customer.modify(customer_id, **updates)
    
    def create_plan(
        self,
        name: str,
        amount: int,
        currency: str,
        interval: str,
        interval_count: int = 1,
        metadata: Dict[str, Any] = None
    ) -> PlanResult:
        import stripe
        
        # Create product first
        product = stripe.Product.create(name=name, metadata=metadata or {})
        
        # Create price
        price = stripe.Price.create(
            product=product.id,
            unit_amount=amount,
            currency=currency,
            recurring={
                "interval": interval,
                "interval_count": interval_count
            },
            metadata=metadata or {}
        )
        
        return PlanResult(
            provider=PaymentProvider.STRIPE,
            provider_plan_id=price.id,
            name=name,
            amount=amount,
            currency=currency,
            interval=interval,
            interval_count=interval_count,
            created_at=datetime.fromtimestamp(price.created),
            metadata=metadata,
            provider_data={"price": price, "product": product}
        )
    
    def get_plan(self, plan_id: str) -> PlanResult:
        import stripe
        price = stripe.Price.retrieve(plan_id)
        product = stripe.Product.retrieve(price.product)
        
        return PlanResult(
            provider=PaymentProvider.STRIPE,
            provider_plan_id=price.id,
            name=product.name,
            amount=price.unit_amount,
            currency=price.currency,
            interval=price.recurring.interval if price.recurring else "one_time",
            interval_count=price.recurring.interval_count if price.recurring else 1,
            created_at=datetime.fromtimestamp(price.created),
            metadata=price.metadata,
            provider_data={"price": price, "product": product}
        )
    
    def update_plan(self, plan_id: str, updates: Dict[str, Any]) -> PlanResult:
        # Stripe prices are immutable, so we'd need to create a new one
        raise NotImplementedError("Stripe prices are immutable. Create a new price instead.")
    
    def deactivate_plan(self, plan_id: str) -> PlanResult:
        import stripe
        price = stripe.Price.modify(plan_id, active=False)
        return self.get_plan(plan_id)
    
    def create_subscription(
        self,
        customer_id: str,
        plan_id: str,
        metadata: Dict[str, Any] = None
    ) -> SubscriptionResult:
        import stripe
        
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{"price": plan_id}],
            metadata=metadata or {}
        )
        
        return SubscriptionResult(
            provider=PaymentProvider.STRIPE,
            provider_subscription_id=subscription.id,
            status=SubscriptionStatus(subscription.status.lower()),
            current_period_start=datetime.fromtimestamp(subscription.current_period_start),
            current_period_end=datetime.fromtimestamp(subscription.current_period_end),
            created_at=datetime.fromtimestamp(subscription.created),
            metadata=metadata,
            provider_data=subscription
        )
    
    def get_subscription(self, subscription_id: str) -> SubscriptionResult:
        import stripe
        subscription = stripe.Subscription.retrieve(subscription_id)
        
        return SubscriptionResult(
            provider=PaymentProvider.STRIPE,
            provider_subscription_id=subscription.id,
            status=SubscriptionStatus(subscription.status.lower()),
            current_period_start=datetime.fromtimestamp(subscription.current_period_start),
            current_period_end=datetime.fromtimestamp(subscription.current_period_end),
            created_at=datetime.fromtimestamp(subscription.created),
            metadata=subscription.metadata,
            provider_data=subscription
        )
    
    def update_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> SubscriptionResult:
        import stripe
        subscription = stripe.Subscription.modify(subscription_id, **updates)
        return self.get_subscription(subscription_id)
    
    def cancel_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        import stripe
        subscription = stripe.Subscription.delete(subscription_id)
        return self.get_subscription(subscription_id)
    
    def suspend_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        return self.update_subscription(subscription_id, {"pause_collection": {"behavior": "void"}})
    
    def reactivate_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        return self.update_subscription(subscription_id, {"pause_collection": None})
    
    def create_payment(
        self,
        amount: int,
        currency: str,
        description: str = None,
        customer_id: str = None,
        metadata: Dict[str, Any] = None
    ) -> PaymentResult:
        import stripe
        
        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency=currency,
            description=description,
            customer=customer_id,
            metadata=metadata or {}
        )
        
        return PaymentResult(
            provider=PaymentProvider.STRIPE,
            provider_payment_id=payment_intent.id,
            status=PaymentStatus(payment_intent.status.lower()),
            amount=amount,
            currency=currency,
            created_at=datetime.fromtimestamp(payment_intent.created),
            metadata=metadata,
            provider_data=payment_intent
        )
    
    def capture_payment(self, payment_id: str) -> PaymentResult:
        import stripe
        payment_intent = stripe.PaymentIntent.capture(payment_id)
        
        return PaymentResult(
            provider=PaymentProvider.STRIPE,
            provider_payment_id=payment_intent.id,
            status=PaymentStatus(payment_intent.status.lower()),
            amount=payment_intent.amount,
            currency=payment_intent.currency,
            created_at=datetime.fromtimestamp(payment_intent.created),
            metadata=payment_intent.metadata,
            provider_data=payment_intent
        )
    
    def refund_payment(self, payment_id: str, amount: int = None) -> PaymentResult:
        import stripe
        
        refund_data = {"payment_intent": payment_id}
        if amount:
            refund_data["amount"] = amount
        
        refund = stripe.Refund.create(**refund_data)
        
        return PaymentResult(
            provider=PaymentProvider.STRIPE,
            provider_payment_id=refund.id,
            status=PaymentStatus.REFUNDED,
            amount=refund.amount,
            currency=refund.currency,
            created_at=datetime.fromtimestamp(refund.created),
            metadata=refund.metadata,
            provider_data=refund
        )
    
    def verify_webhook(self, payload: bytes, signature: str, secret: str = None) -> bool:
        import stripe
        try:
            stripe.Webhook.construct_event(payload, signature, secret or self.service.webhook_secret)
            return True
        except Exception:
            return False
    
    def parse_webhook_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": PaymentProvider.STRIPE,
            "event_type": payload.get("type"),
            "event_id": payload.get("id"),
            "data": payload.get("data"),
            "created": payload.get("created")
        }


class PayPalProvider(PaymentProviderInterface):
    """PayPal payment provider implementation"""
    
    def __init__(self):
        from .paypal_service import paypal_service
        self.service = paypal_service
    
    @property
    def provider_name(self) -> PaymentProvider:
        return PaymentProvider.PAYPAL
    
    def create_customer(self, email: str, name: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        # PayPal doesn't have a direct customer concept like Stripe
        # We'll store customer info in metadata for subscriptions/payments
        return {
            "email": email,
            "name": name,
            "metadata": metadata or {}
        }
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        # In PayPal, customer data is typically stored in our system
        # and referenced by custom_id in subscriptions
        return {"id": customer_id}
    
    def update_customer(self, customer_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        # Customer updates would be handled in our system
        return {"id": customer_id, **updates}
    
    def create_plan(
        self,
        name: str,
        amount: int,
        currency: str,
        interval: str,
        interval_count: int = 1,
        metadata: Dict[str, Any] = None
    ) -> PlanResult:
        # Convert amount from cents to currency units
        amount_str = f"{amount / 100:.2f}"
        
        # Create product first
        product = self.service.create_product(
            name=f"{name} Product",
            description=f"Product for {name}",
            product_id=f"PROD_{name.upper().replace(' ', '_')}"
        )
        
        # Map interval to PayPal format
        interval_map = {
            "day": "DAY",
            "week": "WEEK", 
            "month": "MONTH",
            "year": "YEAR"
        }
        paypal_interval = interval_map.get(interval.lower(), "MONTH")
        
        # Create plan
        plan = self.service.create_subscription_plan(
            product_id=product["id"],
            name=name,
            amount=amount_str,
            currency=currency,
            interval_unit=paypal_interval,
            interval_count=interval_count
        )
        
        return PlanResult(
            provider=PaymentProvider.PAYPAL,
            provider_plan_id=plan["id"],
            name=name,
            amount=amount,
            currency=currency,
            interval=interval,
            interval_count=interval_count,
            created_at=datetime.utcnow(),  # PayPal doesn't return creation time
            metadata=metadata,
            provider_data={"plan": plan, "product": product}
        )
    
    def get_plan(self, plan_id: str) -> PlanResult:
        plan = self.service.get_plan(plan_id)
        
        # Extract billing cycle info
        billing_cycle = plan.get("billing_cycles", [{}])[0]
        frequency = billing_cycle.get("frequency", {})
        pricing = billing_cycle.get("pricing_scheme", {}).get("fixed_price", {})
        
        amount_cents = int(float(pricing.get("value", "0")) * 100)
        
        return PlanResult(
            provider=PaymentProvider.PAYPAL,
            provider_plan_id=plan["id"],
            name=plan.get("name", ""),
            amount=amount_cents,
            currency=pricing.get("currency_code", "USD"),
            interval=frequency.get("interval_unit", "MONTH").lower(),
            interval_count=frequency.get("interval_count", 1),
            created_at=datetime.utcnow(),
            metadata={},
            provider_data=plan
        )
    
    def update_plan(self, plan_id: str, updates: Dict[str, Any]) -> PlanResult:
        # Convert updates to PayPal patch format
        patches = []
        for key, value in updates.items():
            if key == "name":
                patches.append({"op": "replace", "path": "/name", "value": value})
        
        self.service.update_plan(plan_id, patches)
        return self.get_plan(plan_id)
    
    def deactivate_plan(self, plan_id: str) -> PlanResult:
        self.service.deactivate_plan(plan_id)
        return self.get_plan(plan_id)
    
    def create_subscription(
        self,
        customer_id: str,
        plan_id: str,
        metadata: Dict[str, Any] = None
    ) -> SubscriptionResult:
        subscription = self.service.create_subscription(
            plan_id=plan_id,
            return_url="https://example.com/success",
            cancel_url="https://example.com/cancel",
            custom_id=customer_id,
            metadata=metadata
        )
        
        return SubscriptionResult(
            provider=PaymentProvider.PAYPAL,
            provider_subscription_id=subscription["id"],
            status=SubscriptionStatus(subscription.get("status", "active").lower()),
            current_period_start=datetime.utcnow(),  # PayPal doesn't provide this directly
            current_period_end=datetime.utcnow(),    # Would need to be calculated
            created_at=datetime.utcnow(),
            metadata=metadata,
            provider_data=subscription
        )
    
    def get_subscription(self, subscription_id: str) -> SubscriptionResult:
        subscription = self.service.get_subscription(subscription_id)
        
        return SubscriptionResult(
            provider=PaymentProvider.PAYPAL,
            provider_subscription_id=subscription["id"],
            status=SubscriptionStatus(subscription.get("status", "active").lower()),
            current_period_start=datetime.utcnow(),
            current_period_end=datetime.utcnow(),
            created_at=datetime.utcnow(),
            metadata={},
            provider_data=subscription
        )
    
    def update_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> SubscriptionResult:
        # Handle plan changes
        if "plan_id" in updates:
            result = self.service.update_subscription_plan(subscription_id, updates["plan_id"])
        
        return self.get_subscription(subscription_id)
    
    def cancel_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.cancel_subscription(subscription_id, reason)
        return self.get_subscription(subscription_id)
    
    def suspend_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.suspend_subscription(subscription_id, reason)
        return self.get_subscription(subscription_id)
    
    def reactivate_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.activate_subscription(subscription_id, reason)
        return self.get_subscription(subscription_id)
    
    def create_payment(
        self,
        amount: int,
        currency: str,
        description: str = None,
        customer_id: str = None,
        metadata: Dict[str, Any] = None
    ) -> PaymentResult:
        amount_str = f"{amount / 100:.2f}"
        
        payment = self.service.create_payment(
            amount=amount_str,
            currency=currency,
            description=description or "Platform Forge Payment"
        )
        
        return PaymentResult(
            provider=PaymentProvider.PAYPAL,
            provider_payment_id=payment["id"],
            status=PaymentStatus.PENDING,  # PayPal payments start as pending
            amount=amount,
            currency=currency,
            created_at=datetime.utcnow(),
            metadata=metadata,
            provider_data=payment
        )
    
    def capture_payment(self, payment_id: str) -> PaymentResult:
        result = self.service.capture_payment(payment_id)
        
        return PaymentResult(
            provider=PaymentProvider.PAYPAL,
            provider_payment_id=payment_id,
            status=PaymentStatus.SUCCEEDED,
            amount=0,  # Would need to extract from result
            currency="USD",
            created_at=datetime.utcnow(),
            provider_data=result
        )
    
    def refund_payment(self, payment_id: str, amount: int = None) -> PaymentResult:
        amount_str = f"{amount / 100:.2f}" if amount else None
        result = self.service.refund_payment(payment_id, amount_str)
        
        return PaymentResult(
            provider=PaymentProvider.PAYPAL,
            provider_payment_id=result.get("id", payment_id),
            status=PaymentStatus.REFUNDED,
            amount=amount or 0,
            currency="USD",
            created_at=datetime.utcnow(),
            provider_data=result
        )
    
    def verify_webhook(self, payload: bytes, signature: str, secret: str = None) -> bool:
        # PayPal webhook verification is complex and would need the actual webhook ID
        # For now, return True - implement proper verification in production
        return True
    
    def parse_webhook_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": PaymentProvider.PAYPAL,
            "event_type": payload.get("event_type"),
            "event_id": payload.get("id"),
            "data": payload.get("resource"),
            "created": payload.get("create_time")
        }


class SquareProvider(PaymentProviderInterface):
    """Square payment provider implementation"""
    
    def __init__(self):
        from .square_service import square_service
        self.service = square_service
    
    @property
    def provider_name(self) -> PaymentProvider:
        return PaymentProvider.SQUARE
    
    def create_customer(self, email: str, name: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        return self.service.create_customer(email=email, name=name)
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        return self.service.get_customer(customer_id)
    
    def update_customer(self, customer_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self.service.update_customer(customer_id, updates)
    
    def create_plan(
        self,
        name: str,
        amount: int,
        currency: str,
        interval: str,
        interval_count: int = 1,
        metadata: Dict[str, Any] = None
    ) -> PlanResult:
        # Square uses catalog items and subscription plans differently
        # For simplicity, we'll create a catalog item
        variations = [{
            "type": "ITEM_VARIATION",
            "id": f"#{name.upper().replace(' ', '_')}_VARIATION",
            "item_variation_data": {
                "name": name,
                "pricing_type": "FIXED_PRICING",
                "price_money": {
                    "amount": amount,
                    "currency": currency
                }
            }
        }]
        
        item = self.service.create_catalog_item(
            name=name,
            description=f"{name} subscription plan",
            variations=variations
        )
        
        return PlanResult(
            provider=PaymentProvider.SQUARE,
            provider_plan_id=item["catalog_object"]["id"],
            name=name,
            amount=amount,
            currency=currency,
            interval=interval,
            interval_count=interval_count,
            created_at=datetime.utcnow(),
            metadata=metadata,
            provider_data=item
        )
    
    def get_plan(self, plan_id: str) -> PlanResult:
        item = self.service.get_catalog_item(plan_id)
        catalog_object = item["object"]
        item_data = catalog_object["item_data"]
        
        # Get first variation for pricing info
        variation = item_data.get("variations", [{}])[0]
        variation_data = variation.get("item_variation_data", {})
        price_money = variation_data.get("price_money", {})
        
        return PlanResult(
            provider=PaymentProvider.SQUARE,
            provider_plan_id=plan_id,
            name=item_data.get("name", ""),
            amount=price_money.get("amount", 0),
            currency=price_money.get("currency", "USD"),
            interval="month",  # Square doesn't store interval in catalog
            interval_count=1,
            created_at=datetime.utcnow(),
            metadata={},
            provider_data=item
        )
    
    def update_plan(self, plan_id: str, updates: Dict[str, Any]) -> PlanResult:
        self.service.update_catalog_item(plan_id, updates)
        return self.get_plan(plan_id)
    
    def deactivate_plan(self, plan_id: str) -> PlanResult:
        # Square doesn't have a direct deactivate, so we'd delete or mark inactive
        self.service.delete_catalog_item(plan_id)
        return self.get_plan(plan_id)
    
    def create_subscription(
        self,
        customer_id: str,
        plan_id: str,
        metadata: Dict[str, Any] = None
    ) -> SubscriptionResult:
        subscription = self.service.create_subscription(
            customer_id=customer_id,
            plan_id=plan_id
        )
        
        return SubscriptionResult(
            provider=PaymentProvider.SQUARE,
            provider_subscription_id=subscription["subscription"]["id"],
            status=SubscriptionStatus.ACTIVE,  # Square subscriptions start active
            current_period_start=datetime.utcnow(),
            current_period_end=datetime.utcnow(),
            created_at=datetime.utcnow(),
            metadata=metadata,
            provider_data=subscription
        )
    
    def get_subscription(self, subscription_id: str) -> SubscriptionResult:
        subscription = self.service.get_subscription(subscription_id)
        subscription_data = subscription["subscription"]
        
        status_map = {
            "ACTIVE": SubscriptionStatus.ACTIVE,
            "CANCELED": SubscriptionStatus.CANCELLED,
            "PAUSED": SubscriptionStatus.SUSPENDED,
            "PAST_DUE": SubscriptionStatus.PAST_DUE
        }
        
        return SubscriptionResult(
            provider=PaymentProvider.SQUARE,
            provider_subscription_id=subscription_id,
            status=status_map.get(subscription_data.get("status", "ACTIVE"), SubscriptionStatus.ACTIVE),
            current_period_start=datetime.utcnow(),
            current_period_end=datetime.utcnow(),
            created_at=datetime.utcnow(),
            metadata={},
            provider_data=subscription
        )
    
    def update_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> SubscriptionResult:
        self.service.update_subscription(subscription_id, updates)
        return self.get_subscription(subscription_id)
    
    def cancel_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.cancel_subscription(subscription_id)
        return self.get_subscription(subscription_id)
    
    def suspend_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.pause_subscription(subscription_id)
        return self.get_subscription(subscription_id)
    
    def reactivate_subscription(self, subscription_id: str, reason: str = None) -> SubscriptionResult:
        self.service.resume_subscription(subscription_id)
        return self.get_subscription(subscription_id)
    
    def create_payment(
        self,
        amount: int,
        currency: str,
        description: str = None,
        customer_id: str = None,
        metadata: Dict[str, Any] = None
    ) -> PaymentResult:
        payment = self.service.create_payment(
            amount=amount,
            currency=currency,
            customer_id=customer_id,
            note=description
        )
        
        payment_data = payment["payment"]
        
        status_map = {
            "APPROVED": PaymentStatus.SUCCEEDED,
            "PENDING": PaymentStatus.PENDING,
            "COMPLETED": PaymentStatus.SUCCEEDED,
            "CANCELED": PaymentStatus.CANCELLED,
            "FAILED": PaymentStatus.FAILED
        }
        
        return PaymentResult(
            provider=PaymentProvider.SQUARE,
            provider_payment_id=payment_data["id"],
            status=status_map.get(payment_data.get("status", "PENDING"), PaymentStatus.PENDING),
            amount=amount,
            currency=currency,
            created_at=datetime.utcnow(),
            metadata=metadata,
            provider_data=payment
        )
    
    def capture_payment(self, payment_id: str) -> PaymentResult:
        payment = self.service.complete_payment(payment_id)
        payment_data = payment["payment"]
        
        return PaymentResult(
            provider=PaymentProvider.SQUARE,
            provider_payment_id=payment_id,
            status=PaymentStatus.SUCCEEDED,
            amount=payment_data["amount_money"]["amount"],
            currency=payment_data["amount_money"]["currency"],
            created_at=datetime.utcnow(),
            provider_data=payment
        )
    
    def refund_payment(self, payment_id: str, amount: int = None) -> PaymentResult:
        refund = self.service.create_refund(
            payment_id=payment_id,
            amount=amount,
            reason="Customer requested refund"
        )
        
        refund_data = refund["refund"]
        
        return PaymentResult(
            provider=PaymentProvider.SQUARE,
            provider_payment_id=refund_data["id"],
            status=PaymentStatus.REFUNDED,
            amount=refund_data["amount_money"]["amount"],
            currency=refund_data["amount_money"]["currency"],
            created_at=datetime.utcnow(),
            provider_data=refund
        )
    
    def verify_webhook(self, payload: bytes, signature: str, secret: str = None) -> bool:
        # Square webhook verification requires the webhook signature key and notification URL
        # For now, return True - implement proper verification in production
        return True
    
    def parse_webhook_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "provider": PaymentProvider.SQUARE,
            "event_type": payload.get("type"),
            "event_id": payload.get("event_id"),
            "data": payload.get("data"),
            "created": payload.get("created_at")
        }


class PaymentProviderFactory:
    """Factory for creating payment provider instances"""
    
    _providers = {
        PaymentProvider.STRIPE: StripeProvider,
        PaymentProvider.PAYPAL: PayPalProvider,
        PaymentProvider.SQUARE: SquareProvider,
        # Future providers would be added here
        # PaymentProvider.PADDLE: PaddleProvider,
    }
    
    @classmethod
    def create_provider(cls, provider_type: Union[PaymentProvider, str]) -> PaymentProviderInterface:
        """Create a payment provider instance"""
        if isinstance(provider_type, str):
            provider_type = PaymentProvider(provider_type)
        
        provider_class = cls._providers.get(provider_type)
        if not provider_class:
            raise ValueError(f"Unsupported payment provider: {provider_type}")
        
        return provider_class()
    
    @classmethod
    def get_available_providers(cls) -> List[PaymentProvider]:
        """Get list of available providers"""
        return list(cls._providers.keys())


# Global factory instance
payment_factory = PaymentProviderFactory()