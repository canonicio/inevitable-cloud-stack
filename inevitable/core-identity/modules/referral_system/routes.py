"""
API routes for referral and credit system
"""
from typing import Dict, Any, Optional, List
from datetime import datetime, date
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from modules.core.secure_error_messages import create_api_error, create_auth_error, create_billing_error, create_admin_error
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db
from ..core.enhanced_validators import SecureBaseModel, APIParameterValidator
from modules.auth.dependencies import get_current_user, require_tenant
from modules.auth.models import User
from ..core.security import SecurityUtils

from .credit_engine import DynamicCreditEngine
from .referral_tracker import ReferralTracker
from .product_hunt import ProductHuntCampaign, LeaderboardManager
from .social_verifier import SocialShareTracker, XComVerifier, LinkedInVerifier
from .commission_manager import CommissionCalculator, PayoutManager, PaymentMethod
from .fraud_prevention import FraudDetector
from .analytics import ReferralAnalytics, CreditAnalytics

# Initialize components
credit_engine = None
referral_tracker = None
product_hunt_campaign = None
social_tracker = None
commission_calculator = None
payout_manager = None
fraud_detector = None
referral_analytics = None
credit_analytics = None

def init_components(db_factory, payment_processors=None):
    """Initialize all referral system components"""
    global credit_engine, referral_tracker, product_hunt_campaign
    global social_tracker, commission_calculator, payout_manager
    global fraud_detector, referral_analytics, credit_analytics
    
    # Basic credit engine configuration
    credit_config = {
        'anti_fraud': {'enabled': True},
        'default_actions': {},
        'rate_limits': {'max_daily_awards': 100}
    }
    credit_engine = DynamicCreditEngine(db_factory, credit_config)
    referral_tracker = ReferralTracker(db_factory)
    
    # Product Hunt campaign config
    ph_config = {
        'credit_actions': {
            'ph_upvote': {'value': 10, 'multipliers': {'top_hunter': 2.0}},
            'ph_review': {'value': 50, 'multipliers': {'with_screenshot': 1.5}},
            'ph_share': {'value': 20, 'multipliers': {'viral': 3.0}}
        }
    }
    product_hunt_campaign = ProductHuntCampaign(db_factory, credit_engine, ph_config)
    
    # Social verifiers
    x_verifier = XComVerifier()
    linkedin_verifier = LinkedInVerifier()
    social_tracker = SocialShareTracker(x_verifier, linkedin_verifier)
    
    # Commission and payouts
    commission_calculator = CommissionCalculator(db_factory)
    payout_manager = PayoutManager(db_factory, payment_processors or {})
    
    # Fraud and analytics
    fraud_detector = FraudDetector(db_factory)
    referral_analytics = ReferralAnalytics(db_factory)
    credit_analytics = CreditAnalytics(db_factory)

# Create router
router = APIRouter(prefix="/api/referral", tags=["referral"])

# Pydantic models for requests/responses
class CreditActionCreate(SecureBaseModel):
    action_key: str = Field(..., pattern="^[a-zA-Z0-9_-]+$")
    name: str
    description: str
    value_formula: str
    is_active: bool = True
    max_daily: Optional[int] = None
    max_total: Optional[int] = None
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = {}

    @validator('name')
    def validate_name(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'name')
                        return v

    @validator('description')
    def validate_description(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'description')
                        return v

class CreditMultiplierCreate(SecureBaseModel):
    multiplier_key: str = Field(..., pattern="^[a-zA-Z0-9_-]+$")
    name: str
    description: str
    multiplier: float = Field(..., ge=0.1, le=10.0)
    condition_formula: str
    is_active: bool = True
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    @validator('name')
    def validate_name(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'name')
                        return v

    @validator('description')
    def validate_description(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'description')
                        return v

class ReferralCampaignCreate(SecureBaseModel):
    name: str
    description: str
    campaign_type: str = Field(..., pattern="^(customer|affiliate|partner|influencer)$")
    commission_type: str
    commission_config: Dict[str, Any]
    attribution_model: str = "last_touch"
    cookie_duration_days: int = 30
    is_active: bool = True
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = {}

    @validator('name')
    def validate_name(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'name')
                        return v

    @validator('description')
    def validate_description(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'description')
                        return v

class ReferralCreate(SecureBaseModel):
    campaign_id: str
    referred_email: str
    referral_source: Optional[str] = None
    utm_source: Optional[str] = None
    utm_medium: Optional[str] = None
    utm_campaign: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

class ProductHuntActivityCreate(SecureBaseModel):
    activity_type: str = Field(..., pattern="^(upvote|review|share|hunter_recommend)$")
    ph_username: str
    proof_url: Optional[str] = None
    content: Optional[str] = None
    share_platform: Optional[str] = None
    is_top_hunter: bool = False
    product_id: str = "platform-forge"

class SocialShareVerify(SecureBaseModel):
    platform: str = Field(..., pattern="^(x_com|twitter|linkedin|facebook|reddit)$")
    share_url: str
    required_content: Optional[Dict[str, List[str]]] = None

class PayoutRequestCreate(SecureBaseModel):
    payment_method: PaymentMethod
    payment_details: Optional[Dict[str, Any]] = None

class PartnerApplicationCreate(SecureBaseModel):
    company_name: str
    contact_name: str
    email: str
    website: Optional[str] = None
    expected_monthly_referrals: int
    marketing_channels: List[str]
    notes: Optional[str] = None

# Credit System Routes
@router.post("/credits/actions")
async def create_credit_action(
    action: CreditActionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Create a new credit action (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Validate formula
    try:
        await credit_engine.validate_formula(action.value_formula)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid formula: Operation failed. Please try again later.")
    
    result = await credit_engine.create_credit_action(
        tenant_id=tenant_id,
        **action.dict()
    )
    
    return {"success": True, "action": result}

@router.get("/credits/actions")
async def list_credit_actions(
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """List all credit actions"""
    actions = await credit_engine.get_credit_actions(
        tenant_id=tenant_id,
        is_active=is_active
    )
    
    return {"actions": actions}

@router.post("/credits/award")
async def award_credits(
    user_id: str,
    action_key: str,
    context: Optional[Dict[str, Any]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Award credits to a user"""
    # Check fraud risk
    risk_analysis = await fraud_detector.analyze_risk(
        user_id=user_id,
        activity_type="credit_action",
        activity_data={
            "action_key": action_key,
            "context": context,
            "ip_address": context.get("ip_address") if context else None
        },
        tenant_id=tenant_id
    )
    
    if risk_analysis["risk_level"] == "critical":
        raise HTTPException(status_code=403, detail="Activity blocked due to high risk")
    
    try:
        transaction = await credit_engine.award_credits(
            user_id=user_id,
            action_key=action_key,
            tenant_id=tenant_id,
            context=context or {}
        )
        
        return {
            "success": True,
            "transaction_id": transaction.transaction_id,
            "credits_awarded": float(transaction.amount),
            "new_balance": float(transaction.balance_after),
            "risk_analysis": risk_analysis if risk_analysis["risk_level"] != "low" else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

@router.get("/credits/balance/{user_id}")
async def get_credit_balance(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get user's credit balance"""
    # Users can only check their own balance unless admin
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    
    balance = await credit_engine.get_user_balance(user_id, tenant_id)
    
    return {
        "user_id": user_id,
        "balance": float(balance.balance),
        "lifetime_earned": float(balance.lifetime_earned),
        "lifetime_spent": float(balance.lifetime_spent),
        "last_earned_at": balance.last_earned_at,
        "last_spent_at": balance.last_spent_at
    }

@router.get("/credits/history/{user_id}")
async def get_credit_history(
    user_id: str,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get user's credit transaction history"""
    # Users can only check their own history unless admin
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")
    
    transactions = await credit_engine.get_transaction_history(
        user_id=user_id,
        tenant_id=tenant_id,
        limit=limit,
        offset=offset
    )
    
    return {
        "user_id": user_id,
        "transactions": [
            {
                "transaction_id": t.transaction_id,
                "type": t.transaction_type.value,
                "amount": float(t.amount),
                "balance_after": float(t.balance_after),
                "action_key": t.action_key,
                "description": t.description,
                "metadata": t.metadata,
                "created_at": t.created_at
            }
            for t in transactions
        ]
    }

# Referral System Routes
@router.post("/campaigns")
async def create_referral_campaign(
    campaign: ReferralCampaignCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Create a new referral campaign (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    result = await referral_tracker.create_campaign(
        tenant_id=tenant_id,
        **campaign.dict()
    )
    
    return {"success": True, "campaign": result}

@router.get("/campaigns")
async def list_referral_campaigns(
    is_active: Optional[bool] = None,
    campaign_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """List referral campaigns"""
    campaigns = await referral_tracker.get_campaigns(
        tenant_id=tenant_id,
        is_active=is_active,
        campaign_type=campaign_type
    )
    
    return {"campaigns": campaigns}

@router.post("/generate-code")
async def generate_referral_code(
    campaign_id: str,
    custom_code: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Generate a referral code for current user"""
    try:
        code = await referral_tracker.generate_referral_code(
            user_id=current_user.id,
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            custom_code=custom_code
        )
        
        # Generate share links
        base_url = "https://platform-forge.com/signup"
        share_links = {
            "direct": f"{base_url}?ref={code}",
            "x_com": f"https://x.com/intent/tweet?text=Check%20out%20Platform%20Forge!&url={base_url}?ref={code}",
            "linkedin": f"https://www.linkedin.com/sharing/share-offsite/?url={base_url}?ref={code}"
        }
        
        return {
            "success": True,
            "referral_code": code,
            "share_links": share_links
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

@router.post("/track")
async def track_referral(
    referral: ReferralCreate,
    request_metadata: Dict[str, Any] = Body(default={}),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Track a new referral"""
    # Add request metadata
    metadata = referral.metadata or {}
    metadata.update(request_metadata)
    
    # Check fraud
    risk_analysis = await fraud_detector.analyze_risk(
        user_id=current_user.id,
        activity_type="referral",
        activity_data={
            **referral.dict(),
            "ip_address": request_metadata.get("ip_address"),
            "device_fingerprint": request_metadata.get("device_fingerprint")
        },
        tenant_id=tenant_id
    )
    
    if risk_analysis["risk_level"] == "critical":
        raise HTTPException(status_code=403, detail="Referral blocked due to high risk")
    
    result = await referral_tracker.track_referral(
        referrer_id=current_user.id,
        tenant_id=tenant_id,
        **referral.dict(),
        metadata=metadata
    )
    
    return {
        "success": True,
        "referral_id": result.id,
        "status": result.status.value,
        "risk_analysis": risk_analysis if risk_analysis["risk_level"] != "low" else None
    }

@router.post("/referrals/{referral_id}/convert")
async def convert_referral(
    referral_id: str,
    conversion_value: float,
    metadata: Optional[Dict[str, Any]] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Mark a referral as converted"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        result = await referral_tracker.convert_referral(
            referral_id=referral_id,
            conversion_value=Decimal(str(conversion_value)),
            tenant_id=tenant_id,
            metadata=metadata
        )
        
        # Calculate commission if applicable
        if result.campaign.commission_type:
            commission = await commission_calculator.calculate_commission(
                referral=result,
                campaign=result.campaign
            )
            
            return {
                "success": True,
                "referral_id": referral_id,
                "conversion_value": float(conversion_value),
                "commission": {
                    "amount": float(commission.commission_amount),
                    "type": commission.commission_type.value
                }
            }
        
        return {
            "success": True,
            "referral_id": referral_id,
            "conversion_value": float(conversion_value)
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

@router.get("/my-referrals")
async def get_my_referrals(
    status: Optional[str] = None,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get current user's referrals"""
    referrals = await referral_tracker.get_user_referrals(
        user_id=current_user.id,
        tenant_id=tenant_id,
        status=status,
        limit=limit,
        offset=offset
    )
    
    stats = await referral_tracker.get_user_stats(
        user_id=current_user.id,
        tenant_id=tenant_id
    )
    
    return {
        "referrals": referrals,
        "stats": stats
    }

# Product Hunt Routes
@router.post("/product-hunt/activity")
async def submit_product_hunt_activity(
    activity: ProductHuntActivityCreate,
    request_metadata: Dict[str, Any] = Body(default={}),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Submit Product Hunt activity for credits"""
    # Check fraud
    activity_data = activity.dict()
    activity_data.update(request_metadata)
    
    risk_analysis = await fraud_detector.analyze_risk(
        user_id=current_user.id,
        activity_type="product_hunt",
        activity_data=activity_data,
        tenant_id=tenant_id
    )
    
    if risk_analysis["risk_level"] == "critical":
        raise HTTPException(status_code=403, detail="Activity blocked due to high risk")
    
    try:
        result = await product_hunt_campaign.process_activity(
            user_id=current_user.id,
            activity_type=activity.activity_type,
            activity_data=activity_data,
            tenant_id=tenant_id
        )
        
        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

@router.get("/product-hunt/leaderboard")
async def get_product_hunt_leaderboard(
    limit: int = Query(50, le=100),
    activity_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant)
):
    """Get Product Hunt campaign leaderboard"""
    leaderboard = await product_hunt_campaign.leaderboard.get_leaderboard(
        tenant_id=tenant_id,
        limit=limit,
        activity_type=activity_type
    )
    
    return {"leaderboard": leaderboard}

@router.get("/product-hunt/my-rank")
async def get_my_product_hunt_rank(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get current user's Product Hunt rank"""
    rank_info = await product_hunt_campaign.leaderboard.get_user_rank(
        user_id=current_user.id,
        tenant_id=tenant_id
    )
    
    if not rank_info:
        return {
            "ranked": False,
            "message": "No Product Hunt activities yet"
        }
    
    return {
        "ranked": True,
        **rank_info
    }

# Social Share Routes
@router.post("/social/verify")
async def verify_social_share(
    share: SocialShareVerify,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Verify a social media share"""
    result = await social_tracker.verify_share(
        platform=share.platform,
        share_url=share.share_url,
        requirements=share.required_content
    )
    
    if result.get("verified"):
        # Award credits for verified share
        try:
            credits = await credit_engine.award_credits(
                user_id=current_user.id,
                action_key=f"social_share_{share.platform}",
                tenant_id=tenant_id,
                context={
                    "share_url": share.share_url,
                    "influence_score": result.get("influence_score", 0.5)
                }
            )
            
            result["credits_earned"] = float(credits.amount)
            
        except Exception as e:
            logger.error(f"Failed to award credits for social share: {e}")
    
    return result

@router.get("/social/templates/{platform}")
async def get_share_templates(
    platform: str,
    product_name: str = Query("Platform Forge"),
    product_url: str = Query("https://producthunt.com/products/platform-forge"),
    custom_message: Optional[str] = None
):
    """Get social media share templates"""
    templates = social_tracker.generate_share_templates(
        platform=platform,
        product_name=product_name,
        product_url=product_url,
        custom_message=custom_message
    )
    
    optimal_times = social_tracker.get_optimal_share_times(platform)
    
    return {
        "templates": templates,
        "optimal_times": optimal_times
    }

# Commission & Payout Routes
@router.post("/payouts/request")
async def request_payout(
    payout: PayoutRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Request a commission payout"""
    try:
        # Check if user is a partner
        partner = await referral_tracker.get_partner_by_user_id(
            user_id=current_user.id,
            tenant_id=tenant_id
        )
        
        if not partner:
            raise HTTPException(status_code=403, detail="Not registered as affiliate partner")
        
        result = await payout_manager.create_payout_request(
            partner_id=partner.partner_id,
            payment_method=payout.payment_method,
            tenant_id=tenant_id
        )
        
        return {
            "success": True,
            "payout_id": result.payout_id,
            "amount_requested": float(result.amount_requested),
            "processing_fee": float(result.processing_fee),
            "net_amount": float(result.net_amount),
            "status": result.status.value
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

@router.get("/payouts/history")
async def get_payout_history(
    limit: int = Query(50, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get payout history"""
    # Check if user is a partner
    partner = await referral_tracker.get_partner_by_user_id(
        user_id=current_user.id,
        tenant_id=tenant_id
    )
    
    if not partner:
        return {"payouts": []}
    
    history = await payout_manager.get_payout_history(
        partner_id=partner.partner_id,
        tenant_id=tenant_id,
        limit=limit
    )
    
    return {"payouts": history}

@router.post("/partners/apply")
async def apply_as_partner(
    application: PartnerApplicationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Apply to become an affiliate partner"""
    try:
        partner = await referral_tracker.create_partner(
            user_id=current_user.id,
            tenant_id=tenant_id,
            **application.dict()
        )
        
        return {
            "success": True,
            "partner_id": partner.partner_id,
            "status": "pending_approval"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail="Operation failed. Please try again later.")

# Analytics Routes
@router.get("/analytics/overview")
async def get_referral_analytics(
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get referral system analytics (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get various analytics
    credit_metrics = await credit_analytics.get_credit_metrics(
        tenant_id=tenant_id,
        start_date=datetime.combine(start_date, datetime.min.time()) if start_date else None,
        end_date=datetime.combine(end_date, datetime.max.time()) if end_date else None
    )
    
    # Get top campaigns
    campaigns = await referral_tracker.get_campaigns(tenant_id=tenant_id, is_active=True)
    campaign_performance = []
    
    for campaign in campaigns[:5]:  # Top 5 campaigns
        perf = await referral_analytics.get_campaign_performance(
            campaign_id=campaign.id,
            tenant_id=tenant_id
        )
        campaign_performance.append(perf)
    
    # Get cohort analysis
    cohort_analysis = await referral_analytics.cohorts.analyze_referral_cohorts(
        tenant_id=tenant_id,
        cohort_period="month",
        lookback_periods=6
    )
    
    return {
        "credit_metrics": credit_metrics,
        "campaign_performance": campaign_performance,
        "cohort_analysis": cohort_analysis
    }

@router.get("/analytics/funnel/{campaign_id}")
async def get_conversion_funnel(
    campaign_id: str,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Get conversion funnel for a campaign"""
    funnel = await referral_analytics.funnel.analyze_funnel(
        campaign_id=campaign_id,
        tenant_id=tenant_id,
        start_date=datetime.combine(start_date, datetime.min.time()) if start_date else None,
        end_date=datetime.combine(end_date, datetime.max.time()) if end_date else None
    )
    
    # Get funnel by source
    funnel_by_source = await referral_analytics.funnel.get_funnel_by_source(
        campaign_id=campaign_id,
        tenant_id=tenant_id
    )
    
    return {
        "overall_funnel": funnel,
        "funnel_by_source": funnel_by_source
    }

# Admin Routes
@router.post("/admin/process-payouts")
async def process_pending_payouts(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Process all pending payouts (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get pending payouts
    pending = await payout_manager.get_pending_payouts(tenant_id)
    
    results = []
    for payout in pending:
        try:
            result = await payout_manager.process_payout(
                payout_id=payout.payout_id,
                tenant_id=tenant_id
            )
            results.append({
                "payout_id": payout.payout_id,
                "status": "success",
                **result
            })
        except Exception as e:
            results.append({
                "payout_id": payout.payout_id,
                "status": "failed",
                "error": str(e)
            })
    
    return {
        "processed": len(results),
        "results": results
    }

@router.post("/admin/fraud-review/{user_id}")
async def review_user_fraud_risk(
    user_id: str,
    action: str = Body(..., pattern="^(clear|flag|block)$"),
    notes: Optional[str] = Body(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant)
):
    """Review and update user fraud status (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Update fraud status
    result = await fraud_detector.update_user_status(
        user_id=user_id,
        action=action,
        admin_id=current_user.id,
        notes=notes,
        tenant_id=tenant_id
    )
    
    return {
        "success": True,
        "user_id": user_id,
        "new_status": result["status"],
        "action": action
    }