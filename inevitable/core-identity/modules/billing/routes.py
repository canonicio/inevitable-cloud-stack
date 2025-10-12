"""
Billing API routes
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, field_validator

from ..core.database import get_db
from ..core.enhanced_validators import SecureBaseModel, APIParameterValidator
from ..auth.dependencies import get_current_user
from ..auth.models import User
from .models import Customer, Package
from .stripe_service import stripe_service
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


class CheckoutRequest(SecureBaseModel):
    price_id: str = Field(..., pattern=r'^price_[A-Za-z0-9]{14,}$', description="Stripe price ID")
    success_url: str = Field(..., max_length=2048, description="Success redirect URL")
    cancel_url: str = Field(..., max_length=2048, description="Cancel redirect URL")
    
    @field_validator('success_url', 'cancel_url')
    @classmethod
    def validate_urls(cls, v, field):
        return APIParameterValidator.validate_url(v, field_name=field.name)
    
    @field_validator('price_id')
    @classmethod
    def validate_price_id(cls, v):
        return APIParameterValidator.validate_pattern(v, 'stripe_id', 'price_id')


class CheckoutResponse(SecureBaseModel):
    checkout_url: str
    session_id: str


class SubscriptionInfo(SecureBaseModel):
    subscription_id: Optional[str]
    status: str
    current_period_end: Optional[datetime]
    plan_name: Optional[str]


class BillingPortalResponse(SecureBaseModel):
    portal_url: str


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_session(
    request: CheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a Stripe checkout session with server-side price validation and race condition protection.
    Addresses CRITICAL-004: Subscription Price Manipulation
    Addresses HIGH-BILLING-001: Checkout Race Conditions
    """
    import redis
    import hashlib
    from contextlib import contextmanager
    
    # CRITICAL FIX: Implement distributed locking to prevent race conditions
    @contextmanager
    def distributed_lock(redis_client, lock_key, timeout=30):
        """Acquire a distributed lock using Redis with automatic release"""
        import uuid
        import time
        
        lock_id = str(uuid.uuid4())
        lock_acquired = False
        
        try:
            # Try to acquire lock with timeout
            start_time = time.time()
            while time.time() - start_time < 5:  # 5 second acquisition timeout
                if redis_client.set(lock_key, lock_id, nx=True, ex=timeout):
                    lock_acquired = True
                    break
                time.sleep(0.1)  # Small delay before retry
            
            if not lock_acquired:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Unable to process checkout - please try again"
                )
            
            yield
            
        finally:
            # Only release if we acquired the lock
            if lock_acquired:
                # Use Lua script for atomic check-and-delete
                lua_script = """
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                """
                try:
                    redis_client.eval(lua_script, 1, lock_key, lock_id)
                except:
                    pass  # Best effort cleanup
    
    try:
        # Initialize Redis for distributed locking
        try:
            from ..core.config import settings
            redis_client = redis.Redis.from_url(
                settings.REDIS_URL or "redis://localhost:6379",
                decode_responses=True
            )
            redis_client.ping()  # Test connection
        except Exception as e:
            logger.warning(f"Redis not available for distributed locking: {e}")
            redis_client = None
        
        # Create unique lock key for this user's checkout
        lock_key = f"checkout_lock:{current_user.tenant_id}:{current_user.id}"
        
        # Use distributed lock if Redis is available
        if redis_client:
            with distributed_lock(redis_client, lock_key):
                # Check for existing active checkout session
                existing_session_key = f"checkout_session:{current_user.tenant_id}:{current_user.id}"
                existing_session = redis_client.get(existing_session_key)
                
                if existing_session:
                    # Check if session is still valid (within 1 hour)
                    logger.info(f"Existing checkout session found for user {current_user.id}")
                    # Return existing session to prevent duplicates
                    import json
                    session_data = json.loads(existing_session)
                    return CheckoutResponse(
                        checkout_url=session_data['url'],
                        session_id=session_data['id']
                    )
                
                # Proceed with checkout creation (inside lock)
                return await _create_checkout_with_validation(
                    request, current_user, db, redis_client, existing_session_key
                )
        else:
            # Fallback to database-level locking if Redis not available
            logger.warning("Using database-level locking as Redis is not available")
            
            # Use SELECT ... FOR UPDATE to lock the customer row
            customer = db.query(Customer).filter(
                Customer.email == current_user.email,
                Customer.tenant_id == current_user.tenant_id
            ).with_for_update().first()
            
            return await _create_checkout_with_validation(
                request, current_user, db, None, None
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create checkout session")


async def _create_checkout_with_validation(
    request: CheckoutRequest,
    current_user: User,
    db: Session,
    redis_client=None,
    session_cache_key=None
):
    """Helper function to create checkout with all validations"""
    try:
        # SECURITY FIX: Validate price_id on server-side before processing
        validated_price = await _validate_and_get_price_details(request.price_id, current_user.tenant_id)
        if not validated_price:
            logger.warning(
                f"SECURITY: Invalid price_id attempted: {request.price_id} "
                f"by user {current_user.id} in tenant {current_user.tenant_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid price ID"
            )
        
        # Check user's eligibility for this price tier
        if not await _check_user_price_eligibility(current_user, validated_price, db):
            logger.warning(
                f"SECURITY: Unauthorized price tier access attempted: {request.price_id} "
                f"by user {current_user.id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized for this pricing tier"
            )
        
        # Get or create customer
        customer = db.query(Customer).filter(
            Customer.email == current_user.email,
            Customer.tenant_id == current_user.tenant_id
        ).first()
        
        if not customer:
            # Create customer in Stripe
            stripe_customer = stripe_service.create_customer(
                email=current_user.email,
                name=current_user.username,
                metadata={"user_id": str(current_user.id), "tenant_id": current_user.tenant_id}
            )
            
            # Save to database
            customer = Customer(
                stripe_customer_id=stripe_customer.id,
                email=current_user.email,
                name=current_user.username,
                tenant_id=current_user.tenant_id
            )
            db.add(customer)
            db.commit()
        
        # Create checkout session with validated price
        session = stripe_service.create_checkout_session(
            customer_id=customer.stripe_customer_id,
            price_id=validated_price["id"],  # Use validated price ID
            success_url=request.success_url,
            cancel_url=request.cancel_url,
            metadata={
                "user_id": str(current_user.id), 
                "tenant_id": current_user.tenant_id,
                "validated_price": str(validated_price["unit_amount"]),  # Record actual price
                "plan_name": validated_price["plan_name"]
            }
        )
        
        # Cache the session if Redis is available (prevent duplicate checkouts)
        if redis_client and session_cache_key:
            import json
            session_data = {
                'id': session.id,
                'url': session.url,
                'created_at': str(datetime.now())
            }
            # Cache for 1 hour (Stripe checkout sessions expire after 24 hours)
            redis_client.setex(session_cache_key, 3600, json.dumps(session_data))
        
        # Log successful checkout creation for audit
        logger.info(
            f"Checkout session created: user={current_user.id}, "
            f"price_id={validated_price['id']}, amount={validated_price['unit_amount']}, "
            f"session_id={session.id}"
        )
        
        return CheckoutResponse(
            checkout_url=session.url,
            session_id=session.id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in checkout creation: {e}")
        raise HTTPException(status_code=500, detail="Failed to create checkout session")


@router.get("/subscription", response_model=SubscriptionInfo)
async def get_subscription_info(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current subscription information."""
    try:
        customer = db.query(Customer).filter(
            Customer.email == current_user.email,
            Customer.tenant_id == current_user.tenant_id
        ).first()
        
        if not customer:
            return SubscriptionInfo(
                subscription_id=None,
                status="no_subscription",
                current_period_end=None,
                plan_name=None
            )
        
        # Get active subscription
        active_package = db.query(Package).filter(
            Package.customer_id == customer.id,
            Package.status == "active",
            Package.tenant_id == current_user.tenant_id
        ).first()
        
        if not active_package:
            return SubscriptionInfo(
                subscription_id=None,
                status="no_subscription",
                current_period_end=None,
                plan_name=None
            )
        
        return SubscriptionInfo(
            subscription_id=active_package.stripe_subscription_id,
            status=active_package.status,
            current_period_end=active_package.current_period_end,
            plan_name=active_package.plan_id
        )
        
    except Exception as e:
        logger.error(f"Error getting subscription info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get subscription information")


@router.post("/portal", response_model=BillingPortalResponse)
async def create_billing_portal_session(
    return_url: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a billing portal session."""
    try:
        customer = db.query(Customer).filter(
            Customer.email == current_user.email,
            Customer.tenant_id == current_user.tenant_id
        ).first()
        
        if not customer:
            raise HTTPException(status_code=404, detail="No billing account found")
        
        session = stripe_service.create_portal_session(
            customer_id=customer.stripe_customer_id,
            return_url=return_url
        )
        
        return BillingPortalResponse(portal_url=session.url)
        
    except Exception as e:
        logger.error(f"Error creating portal session: {e}")
        raise HTTPException(status_code=500, detail="Failed to create billing portal session")


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: Session = Depends(get_db)
):
    """Handle Stripe webhooks with signature validation."""
    from .webhooks import get_webhook_handler
    
    handler = get_webhook_handler()
    return await handler.handle_webhook(request, db)


# Security validation functions for CRITICAL-004 fix
async def _validate_and_get_price_details(price_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    """
    Validate price_id against server-side pricing rules and return price details.
    Addresses CRITICAL-004: Subscription Price Manipulation
    """
    import stripe
    
    # Define allowed pricing tiers with validation rules
    # In production, this should come from database configuration
    ALLOWED_PRICES = {
        # Basic tier
        "price_basic_monthly": {
            "id": "price_basic_monthly",
            "plan_name": "Basic Monthly",
            "unit_amount": 999,  # $9.99
            "currency": "usd",
            "interval": "month",
            "features": ["basic_features"],
            "max_users": 5
        },
        "price_basic_annual": {
            "id": "price_basic_annual", 
            "plan_name": "Basic Annual",
            "unit_amount": 9999,  # $99.99
            "currency": "usd",
            "interval": "year",
            "features": ["basic_features"],
            "max_users": 5
        },
        # Pro tier
        "price_pro_monthly": {
            "id": "price_pro_monthly",
            "plan_name": "Pro Monthly", 
            "unit_amount": 2999,  # $29.99
            "currency": "usd",
            "interval": "month",
            "features": ["basic_features", "pro_features"],
            "max_users": 25
        },
        "price_pro_annual": {
            "id": "price_pro_annual",
            "plan_name": "Pro Annual",
            "unit_amount": 29999,  # $299.99
            "currency": "usd", 
            "interval": "year",
            "features": ["basic_features", "pro_features"],
            "max_users": 25
        },
        # Enterprise tier
        "price_enterprise_monthly": {
            "id": "price_enterprise_monthly",
            "plan_name": "Enterprise Monthly",
            "unit_amount": 9999,  # $99.99
            "currency": "usd",
            "interval": "month", 
            "features": ["basic_features", "pro_features", "enterprise_features"],
            "max_users": 100
        }
    }
    
    # Validate against allowed prices
    if price_id not in ALLOWED_PRICES:
        logger.warning(f"SECURITY: Unknown price_id attempted: {price_id}")
        return None
    
    price_config = ALLOWED_PRICES[price_id]
    
    try:
        # Double-check with Stripe to ensure price exists and matches our config
        stripe_price = stripe.Price.retrieve(price_id)
        
        # Validate critical price parameters match our server-side config
        if (stripe_price.unit_amount != price_config["unit_amount"] or
            stripe_price.currency != price_config["currency"] or
            stripe_price.recurring.interval != price_config["interval"]):
            
            logger.error(
                f"SECURITY: Price mismatch detected! "
                f"price_id={price_id}, "
                f"stripe_amount={stripe_price.unit_amount}, "
                f"config_amount={price_config['unit_amount']}"
            )
            return None
        
        return price_config
        
    except stripe.error.InvalidRequestError:
        logger.warning(f"SECURITY: Invalid Stripe price_id: {price_id}")
        return None
    except Exception as e:
        logger.error(f"Error validating price with Stripe: {e}")
        return None


async def _check_user_price_eligibility(user: User, price_details: Dict[str, Any], db: Session) -> bool:
    """
    Check if user is eligible for the requested price tier.
    Implement business logic to prevent unauthorized tier access.
    """
    # Basic eligibility checks
    if not user or not user.is_active:
        return False
    
    # Check if user already has an active subscription
    existing_customer = db.query(Customer).filter(
        Customer.email == user.email,
        Customer.tenant_id == user.tenant_id
    ).first()
    
    if existing_customer:
        # Check for existing active subscriptions
        active_packages = db.query(Package).filter(
            Package.customer_id == existing_customer.id,
            Package.status == "active"
        ).all()
        
        # Allow upgrade/downgrade logic here
        # For now, allow if no active subscription or if it's an upgrade
        plan_hierarchy = {
            "Basic Monthly": 1,
            "Basic Annual": 1, 
            "Pro Monthly": 2,
            "Pro Annual": 2,
            "Enterprise Monthly": 3
        }
        
        current_tier = 0
        for package in active_packages:
            # Get tier level for existing subscription
            for plan_name, tier in plan_hierarchy.items():
                if plan_name.lower() in package.plan_id.lower():
                    current_tier = max(current_tier, tier)
        
        requested_tier = plan_hierarchy.get(price_details["plan_name"], 0)
        
        # Allow same tier or upgrades
        if requested_tier < current_tier:
            logger.warning(
                f"SECURITY: Downgrade attempt blocked - "
                f"user {user.id} trying to downgrade from tier {current_tier} to {requested_tier}"
            )
            return False
    
    # Additional business logic can be added here:
    # - Account age requirements for enterprise plans
    # - Team size validation
    # - Payment history checks
    # - Geographic restrictions
    
    return True