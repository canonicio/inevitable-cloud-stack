"""
Referral and Affiliate Tracking System for Platform Forge

Provides comprehensive referral tracking, affiliate management, and a flexible
credit system that customers can configure for their specific needs.

Key Features:
- Multi-type tracking (customer referrals, affiliates, partners)
- Flexible credit system with customer-definable actions
- Product Hunt launch tools
- Integration with multiple payment providers
- Commission management and payouts
- Fraud prevention
- Real-time analytics
"""

from .models import (
    ReferralType,
    ReferralStatus,
    CommissionType,
    AttributionModel,
    CreditTransactionType,
    Referral,
    ReferralCampaign,
    Commission,
    CreditAction,
    CreditTransaction,
    UserCredit,
    ProductHuntActivity,
    AffiliatePartner,
    PayoutRequest
)

from .referral_tracker import (
    ReferralTracker,
    AttributionEngine,
    ReferralCodeGenerator
)

from .credit_engine import (
    DynamicCreditEngine,
    ValueCalculator,
    CreditMultiplier,
    CreditValidator
)

from .commission_manager import (
    CommissionCalculator,
    PayoutManager,
    TaxDocumentGenerator
)

from .product_hunt import (
    ProductHuntCampaign,
    ProductHuntVerifier,
    LaunchDayAutomation,
    LeaderboardManager
)

from .fraud_prevention import (
    FraudDetector,
    VelocityChecker,
    DeviceFingerprinter,
    SuspiciousPatternDetector
)

from .analytics import (
    ReferralAnalytics,
    CreditAnalytics,
    ConversionFunnel,
    CohortAnalyzer
)

from .social_verifier import (
    XComVerifier,
    LinkedInVerifier,
    SocialShareTracker
)

from .routes import router, init_components

__all__ = [
    # Models
    'ReferralType',
    'ReferralStatus',
    'CommissionType',
    'AttributionModel',
    'CreditTransactionType',
    'Referral',
    'ReferralCampaign',
    'Commission',
    'CreditAction',
    'CreditTransaction',
    'UserCredit',
    'ProductHuntActivity',
    'AffiliatePartner',
    'PayoutRequest',
    
    # Referral System
    'ReferralTracker',
    'AttributionEngine',
    'ReferralCodeGenerator',
    
    # Credit System
    'DynamicCreditEngine',
    'ValueCalculator',
    'CreditMultiplier',
    'CreditValidator',
    
    # Commission Management
    'CommissionCalculator',
    'PayoutManager',
    'TaxDocumentGenerator',
    
    # Product Hunt Tools
    'ProductHuntCampaign',
    'ProductHuntVerifier',
    'LaunchDayAutomation',
    'LeaderboardManager',
    
    # Fraud Prevention
    'FraudDetector',
    'VelocityChecker',
    'DeviceFingerprinter',
    'SuspiciousPatternDetector',
    
    # Analytics
    'ReferralAnalytics',
    'CreditAnalytics',
    'ConversionFunnel',
    'CohortAnalyzer',
    
    # Social Verification
    'XComVerifier',
    'LinkedInVerifier',
    'SocialShareTracker',
    
    # Routes
    'router',
    'init_components'
]