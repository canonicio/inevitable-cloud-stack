"""
Database models for referral and credit system
"""
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from decimal import Decimal
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, Text, JSON,
    ForeignKey, UniqueConstraint, Index, Enum as SQLEnum,
    Float, Numeric, Date, CheckConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid

from modules.core.database import Base, TimestampMixin, TenantMixin


class ReferralType(str, Enum):
    """Types of referrals"""
    CUSTOMER = "customer"
    AFFILIATE = "affiliate"
    PARTNER = "partner"
    INFLUENCER = "influencer"
    EMPLOYEE = "employee"


class ReferralStatus(str, Enum):
    """Referral status"""
    PENDING = "pending"
    CLICKED = "clicked"
    SIGNED_UP = "signed_up"
    CONVERTED = "converted"
    EXPIRED = "expired"
    FRAUDULENT = "fraudulent"


class CommissionType(str, Enum):
    """Commission calculation types"""
    PERCENTAGE = "percentage"
    FIXED = "fixed"
    TIERED = "tiered"
    RECURRING = "recurring"
    HYBRID = "hybrid"


class AttributionModel(str, Enum):
    """Attribution models"""
    FIRST_TOUCH = "first_touch"
    LAST_TOUCH = "last_touch"
    LINEAR = "linear"
    TIME_DECAY = "time_decay"
    POSITION_BASED = "position_based"
    CUSTOM = "custom"


class CreditTransactionType(str, Enum):
    """Credit transaction types"""
    EARNED = "earned"
    SPENT = "spent"
    EXPIRED = "expired"
    REFUNDED = "refunded"
    TRANSFERRED = "transferred"
    ADJUSTMENT = "adjustment"


class PayoutStatus(str, Enum):
    """Payout status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReferralCampaign(Base, TimestampMixin, TenantMixin):
    """Referral campaign configuration"""
    __tablename__ = "referral_campaigns"
    
    id = Column(Integer, primary_key=True)
    campaign_id = Column(String(100), unique=True, nullable=False, default=lambda: f"camp_{uuid.uuid4().hex[:8]}")
    name = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Campaign settings
    campaign_type = Column(SQLEnum(ReferralType), nullable=False)
    attribution_model = Column(SQLEnum(AttributionModel), default=AttributionModel.LAST_TOUCH)
    attribution_window_days = Column(Integer, default=30)
    
    # Commission structure
    commission_type = Column(SQLEnum(CommissionType), nullable=False)
    commission_config = Column(JSON, nullable=False)  # Rates, tiers, etc.
    
    # Campaign period
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime)
    
    # Limits and quotas
    max_referrals_per_user = Column(Integer)
    max_total_referrals = Column(Integer)
    min_purchase_amount = Column(Numeric(10, 2))
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Tracking
    total_clicks = Column(Integer, default=0)
    total_signups = Column(Integer, default=0)
    total_conversions = Column(Integer, default=0)
    total_revenue = Column(Numeric(10, 2), default=0)
    total_commission_paid = Column(Numeric(10, 2), default=0)
    
    # Metadata
    tags = Column(JSON, default=list)
    extra_metadata = Column(JSON, default=dict)
    
    # Relationships
    referrals = relationship("Referral", back_populates="campaign")
    
    __table_args__ = (
        Index('idx_campaign_active', 'is_active', 'start_date', 'end_date'),
        Index('idx_campaign_type', 'campaign_type'),
    )


class Referral(Base, TimestampMixin, TenantMixin):
    """Individual referral tracking"""
    __tablename__ = "referrals"
    
    id = Column(Integer, primary_key=True)
    referral_code = Column(String(50), unique=True, nullable=False, index=True)
    
    # Participants
    referrer_id = Column(String(100), nullable=False, index=True)
    referred_id = Column(String(100), index=True)  # Null until signup
    
    # Campaign
    campaign_id = Column(String(100), ForeignKey("referral_campaigns.campaign_id"), nullable=False)
    
    # Tracking
    status = Column(SQLEnum(ReferralStatus), default=ReferralStatus.PENDING, nullable=False)
    click_count = Column(Integer, default=0)
    first_click_at = Column(DateTime)
    signup_at = Column(DateTime)
    conversion_at = Column(DateTime)
    conversion_value = Column(Numeric(10, 2))
    
    # Attribution
    attribution_data = Column(JSON, default=dict)  # UTM params, etc.
    referral_source = Column(String(100))  # email, social, direct
    
    # Commission
    commission_amount = Column(Numeric(10, 2))
    commission_paid = Column(Boolean, default=False)
    commission_paid_at = Column(DateTime)
    
    # Fraud detection
    risk_score = Column(Float, default=0)
    fraud_checks = Column(JSON, default=dict)
    is_fraudulent = Column(Boolean, default=False)
    
    # Device/IP tracking
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(100))
    
    # Expiration
    expires_at = Column(DateTime)
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    
    # Relationships
    campaign = relationship("ReferralCampaign", back_populates="referrals")
    commission = relationship("Commission", back_populates="referral", uselist=False)
    
    __table_args__ = (
        Index('idx_referral_status', 'status', 'created_at'),
        Index('idx_referral_referrer', 'referrer_id', 'status'),
        Index('idx_referral_conversion', 'conversion_at', 'commission_paid'),
    )


class AffiliatePartner(Base, TimestampMixin, TenantMixin):
    """Affiliate partner management"""
    __tablename__ = "affiliate_partners"
    
    id = Column(Integer, primary_key=True)
    partner_id = Column(String(100), unique=True, nullable=False)
    
    # Partner information
    company_name = Column(String(200))
    contact_name = Column(String(200), nullable=False)
    email = Column(String(200), nullable=False)
    phone = Column(String(50))
    website = Column(String(500))
    
    # Commission settings
    default_commission_type = Column(SQLEnum(CommissionType), default=CommissionType.PERCENTAGE)
    default_commission_rate = Column(Numeric(5, 2))  # Percentage or fixed amount
    custom_commission_config = Column(JSON)
    
    # Payment information
    payment_method = Column(String(50))  # stripe, paypal, wire
    payment_details = Column(JSON)  # Encrypted
    tax_id = Column(String(50))
    tax_form_on_file = Column(Boolean, default=False)
    
    # Performance
    lifetime_referrals = Column(Integer, default=0)
    lifetime_revenue = Column(Numeric(12, 2), default=0)
    lifetime_commission = Column(Numeric(12, 2), default=0)
    current_balance = Column(Numeric(10, 2), default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    approved_at = Column(DateTime)
    suspended_at = Column(DateTime)
    suspension_reason = Column(Text)
    
    # Tier/Level
    tier = Column(String(50), default="bronze")
    performance_multiplier = Column(Numeric(3, 2), default=1.0)
    
    # Metadata
    tags = Column(JSON, default=list)
    notes = Column(Text)
    custom_tracking_params = Column(JSON, default=dict)


class Commission(Base, TimestampMixin, TenantMixin):
    """Commission tracking and payouts"""
    __tablename__ = "commissions"
    
    id = Column(Integer, primary_key=True)
    commission_id = Column(String(100), unique=True, nullable=False)
    
    # Related entities
    referral_id = Column(Integer, ForeignKey("referrals.id"), nullable=False)
    partner_id = Column(String(100), ForeignKey("affiliate_partners.partner_id"))
    
    # Commission details
    commission_type = Column(SQLEnum(CommissionType), nullable=False)
    base_amount = Column(Numeric(10, 2), nullable=False)
    commission_rate = Column(Numeric(5, 2))
    commission_amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), default="USD")
    
    # Transaction details
    transaction_id = Column(String(200))  # Payment provider transaction
    transaction_amount = Column(Numeric(10, 2))
    transaction_date = Column(DateTime)
    
    # Recurring commission
    is_recurring = Column(Boolean, default=False)
    recurring_period = Column(String(20))  # monthly, quarterly, etc.
    recurring_end_date = Column(Date)
    
    # Payout
    payout_status = Column(SQLEnum(PayoutStatus), default=PayoutStatus.PENDING)
    payout_request_id = Column(Integer, ForeignKey("payout_requests.id"))
    paid_at = Column(DateTime)
    
    # Adjustments
    adjustments = Column(JSON, default=list)  # Refunds, chargebacks, etc.
    final_amount = Column(Numeric(10, 2))
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    
    # Relationships
    referral = relationship("Referral", back_populates="commission")
    
    __table_args__ = (
        Index('idx_commission_status', 'payout_status', 'created_at'),
        Index('idx_commission_partner', 'partner_id', 'payout_status'),
    )


class CreditAction(Base, TimestampMixin, TenantMixin):
    """Customer-defined credit actions"""
    __tablename__ = "credit_actions"
    
    id = Column(Integer, primary_key=True)
    action_key = Column(String(100), nullable=False)
    
    # Action configuration
    name = Column(String(200), nullable=False)
    description = Column(Text)
    value_formula = Column(String(500), nullable=False)  # "100" or "10% of purchase.total"
    
    # Requirements and validation
    requirements = Column(JSON, default=dict)  # min_words, has_screenshot, etc.
    validation_rules = Column(JSON, default=dict)
    
    # Limits
    one_time = Column(Boolean, default=False)
    daily_limit = Column(Integer)
    weekly_limit = Column(Integer)
    monthly_limit = Column(Integer)
    total_limit = Column(Integer)
    
    # Moderation
    requires_approval = Column(Boolean, default=False)
    requires_moderation = Column(Boolean, default=False)
    
    # Multipliers
    multiplier_rules = Column(JSON, default=list)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Analytics
    total_awarded = Column(Integer, default=0)
    total_credits = Column(Numeric(12, 2), default=0)
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'action_key'),
        Index('idx_credit_action_active', 'is_active', 'tenant_id'),
    )


class UserCredit(Base, TimestampMixin, TenantMixin):
    """User credit balances"""
    __tablename__ = "user_credits"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(100), nullable=False)
    
    # Balances
    balance = Column(Numeric(12, 2), default=0, nullable=False)
    lifetime_earned = Column(Numeric(12, 2), default=0)
    lifetime_spent = Column(Numeric(12, 2), default=0)
    lifetime_expired = Column(Numeric(12, 2), default=0)
    
    # Tier/Status
    tier = Column(String(50), default="standard")
    multiplier = Column(Numeric(3, 2), default=1.0)
    
    # Limits
    daily_earned_today = Column(Numeric(10, 2), default=0)
    daily_limit_reset = Column(DateTime)
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'user_id'),
        Index('idx_user_credit_balance', 'user_id', 'balance'),
        CheckConstraint('balance >= 0', name='check_positive_balance'),
    )


class CreditTransaction(Base, TimestampMixin, TenantMixin):
    """Credit transaction history"""
    __tablename__ = "credit_transactions"
    
    id = Column(Integer, primary_key=True)
    transaction_id = Column(String(100), unique=True, nullable=False, default=lambda: f"txn_{uuid.uuid4().hex}")
    
    # User and amount
    user_id = Column(String(100), nullable=False, index=True)
    amount = Column(Numeric(10, 2), nullable=False)
    balance_before = Column(Numeric(10, 2), nullable=False)
    balance_after = Column(Numeric(10, 2), nullable=False)
    
    # Transaction details
    transaction_type = Column(SQLEnum(CreditTransactionType), nullable=False)
    action_key = Column(String(100))  # References CreditAction.action_key
    description = Column(Text)
    
    # Related entities
    reference_type = Column(String(50))  # order, referral, achievement, etc.
    reference_id = Column(String(100))
    
    # Expiration
    expires_at = Column(DateTime)
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    
    __table_args__ = (
        Index('idx_credit_transaction_user', 'user_id', 'created_at'),
        Index('idx_credit_transaction_type', 'transaction_type', 'created_at'),
    )


class ProductHuntActivity(Base, TimestampMixin, TenantMixin):
    """Product Hunt specific activity tracking"""
    __tablename__ = "product_hunt_activities"
    
    id = Column(Integer, primary_key=True)
    activity_id = Column(String(100), unique=True, nullable=False, default=lambda: f"ph_{uuid.uuid4().hex[:8]}")
    
    # User information
    user_id = Column(String(100), nullable=False)
    ph_username = Column(String(100))
    ph_user_id = Column(String(100))
    
    # Activity details
    activity_type = Column(String(50), nullable=False)  # upvote, review, share
    activity_timestamp = Column(DateTime, nullable=False)
    
    # Verification
    verification_status = Column(String(50), default="pending")
    verification_data = Column(JSON, default=dict)
    proof_url = Column(String(500))
    
    # Credits
    credits_awarded = Column(Numeric(10, 2), default=0)
    credit_transaction_id = Column(String(100))
    
    # Content (for reviews)
    content = Column(Text)
    has_screenshot = Column(Boolean, default=False)
    word_count = Column(Integer)
    
    # Ranking
    product_position = Column(Integer)  # Position at time of activity
    is_top_hunter = Column(Boolean, default=False)
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    
    __table_args__ = (
        UniqueConstraint('tenant_id', 'user_id', 'activity_type'),  # One activity type per user
        Index('idx_ph_activity_user', 'user_id', 'activity_timestamp'),
        Index('idx_ph_activity_type', 'activity_type', 'verification_status'),
    )


class PayoutRequest(Base, TimestampMixin, TenantMixin):
    """Payout requests for affiliates"""
    __tablename__ = "payout_requests"
    
    id = Column(Integer, primary_key=True)
    payout_id = Column(String(100), unique=True, nullable=False, default=lambda: f"pay_{uuid.uuid4().hex[:8]}")
    
    # Recipient
    partner_id = Column(String(100), ForeignKey("affiliate_partners.partner_id"), nullable=False)
    
    # Amount
    amount_requested = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(3), default="USD")
    
    # Payment details
    payment_method = Column(String(50), nullable=False)
    payment_details = Column(JSON)  # Encrypted
    
    # Processing
    status = Column(SQLEnum(PayoutStatus), default=PayoutStatus.PENDING, nullable=False)
    processed_at = Column(DateTime)
    processor_reference = Column(String(200))  # External payment ID
    
    # Fees
    processing_fee = Column(Numeric(10, 2), default=0)
    net_amount = Column(Numeric(10, 2))
    
    # Tax
    tax_withheld = Column(Numeric(10, 2), default=0)
    tax_document_id = Column(String(100))
    
    # Notes
    notes = Column(Text)
    failure_reason = Column(Text)
    
    # Commissions included
    commission_ids = Column(JSON, default=list)
    
    __table_args__ = (
        Index('idx_payout_status', 'status', 'created_at'),
        Index('idx_payout_partner', 'partner_id', 'status'),
    )