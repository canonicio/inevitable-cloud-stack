"""
Subscription Management Models and Types

Handles admin subscription management, bulk migrations, and pricing plan transitions.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, JSON, Boolean, DateTime, ForeignKey, Index, UniqueConstraint, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from ..core.database import Base, TimestampMixin, TenantMixin


class PricingPlanStatus(str, Enum):
    """Status of a pricing plan"""
    ACTIVE = "active"
    DEPRECATED = "deprecated"  # Still works but not offered to new customers
    SUNSET = "sunset"  # Will be discontinued soon
    DISCONTINUED = "discontinued"  # No longer available
    GRANDFATHERED = "grandfathered"  # Special status for legacy customers


class MigrationStrategy(str, Enum):
    """Strategy for migrating subscriptions"""
    IMMEDIATE = "immediate"  # Migrate right away
    END_OF_BILLING_PERIOD = "end_of_billing_period"  # Migrate at period end
    MANUAL = "manual"  # Require manual intervention
    GRANDFATHERED = "grandfathered"  # Keep on old plan
    CUSTOM = "custom"  # Custom migration logic


class MigrationStatus(str, Enum):
    """Status of a migration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class PricingPlan(Base, TimestampMixin, TenantMixin):
    """Extended pricing plan information for management"""
    __tablename__ = "pricing_plans"
    
    id = Column(Integer, primary_key=True)
    
    # Plan identification
    stripe_price_id = Column(String(255), unique=True, nullable=False)
    stripe_product_id = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Pricing details
    amount = Column(Integer, nullable=False)  # In cents
    currency = Column(String(3), default="usd")
    interval = Column(String(20), nullable=False)  # month, year, etc.
    interval_count = Column(Integer, default=1)
    
    # Plan status
    status = Column(SQLEnum(PricingPlanStatus), default=PricingPlanStatus.ACTIVE)
    
    # Deprecation handling
    deprecated_at = Column(DateTime(timezone=True))
    sunset_date = Column(DateTime(timezone=True))
    discontinued_at = Column(DateTime(timezone=True))
    replacement_plan_id = Column(Integer, ForeignKey("pricing_plans.id"))
    migration_strategy = Column(SQLEnum(MigrationStrategy))
    
    # Features and limits
    features = Column(JSON, default=dict)
    limits = Column(JSON, default=dict)
    
    # Metadata
    plan_metadata = Column(JSON, default=dict)
    
    # Relationships
    replacement_plan = relationship("PricingPlan", remote_side=[id])
    migrations = relationship("SubscriptionMigration", foreign_keys="SubscriptionMigration.target_plan_id", back_populates="target_plan")
    
    # Indexes
    __table_args__ = (
        Index('idx_pricing_plans_status', 'status'),
        Index('idx_pricing_plans_stripe', 'stripe_price_id'),
    )


class SubscriptionMigration(Base, TimestampMixin, TenantMixin):
    """Track subscription migrations and transitions"""
    __tablename__ = "subscription_migrations"
    
    id = Column(Integer, primary_key=True)
    
    # Migration details
    migration_batch_id = Column(String(100))  # For grouping bulk migrations
    
    # Source and target
    subscription_id = Column(String(255), nullable=False)  # Stripe subscription ID
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    source_plan_id = Column(Integer, ForeignKey("pricing_plans.id"))
    target_plan_id = Column(Integer, ForeignKey("pricing_plans.id"))
    
    # Migration settings
    strategy = Column(SQLEnum(MigrationStrategy), nullable=False)
    status = Column(SQLEnum(MigrationStatus), default=MigrationStatus.PENDING)
    
    # Timing
    scheduled_for = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Billing impact
    prorated_amount = Column(Integer)  # Amount to prorate
    credit_amount = Column(Integer)  # Credit to apply
    preserve_billing_date = Column(Boolean, default=True)
    
    # Admin tracking
    initiated_by = Column(Integer, ForeignKey("users.id"))  # Admin who initiated
    approved_by = Column(Integer, ForeignKey("users.id"))  # Admin who approved
    cancelled_by = Column(Integer, ForeignKey("users.id"))  # Admin who cancelled
    
    # Communication
    customer_notified = Column(Boolean, default=False)
    notification_sent_at = Column(DateTime(timezone=True))
    customer_response = Column(Text)  # Accept, reject, feedback
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Audit
    changes_applied = Column(JSON)  # What actually changed
    rollback_data = Column(JSON)  # Data needed to rollback
    
    # Metadata
    reason = Column(Text)  # Why migration is happening
    notes = Column(Text)  # Admin notes
    migration_metadata = Column(JSON, default=dict)
    
    # Relationships
    customer = relationship("Customer")
    user = relationship("User", foreign_keys=[user_id])
    source_plan = relationship("PricingPlan", foreign_keys=[source_plan_id])
    target_plan = relationship("PricingPlan", foreign_keys=[target_plan_id], back_populates="migrations")
    initiated_by_user = relationship("User", foreign_keys=[initiated_by])
    approved_by_user = relationship("User", foreign_keys=[approved_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_subscription_migrations_status', 'status'),
        Index('idx_subscription_migrations_batch', 'migration_batch_id'),
        Index('idx_subscription_migrations_scheduled', 'scheduled_for', 'status'),
        Index('idx_subscription_migrations_customer', 'customer_id'),
    )


class BulkMigrationJob(Base, TimestampMixin, TenantMixin):
    """Track bulk migration operations"""
    __tablename__ = "bulk_migration_jobs"
    
    id = Column(Integer, primary_key=True)
    
    # Job identification
    job_id = Column(String(100), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Migration parameters
    source_plan_ids = Column(JSON, nullable=False)  # List of source plan IDs
    target_plan_id = Column(Integer, ForeignKey("pricing_plans.id"), nullable=False)
    
    # Selection criteria
    criteria = Column(JSON, default=dict)  # Additional filters
    total_subscriptions = Column(Integer, default=0)
    
    # Execution
    status = Column(SQLEnum(MigrationStatus), default=MigrationStatus.PENDING)
    strategy = Column(SQLEnum(MigrationStrategy), nullable=False)
    
    scheduled_for = Column(DateTime(timezone=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Progress tracking
    processed_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    skipped_count = Column(Integer, default=0)
    
    # Configuration
    dry_run = Column(Boolean, default=False)
    notify_customers = Column(Boolean, default=True)
    require_approval = Column(Boolean, default=False)
    
    # Admin tracking
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_by = Column(Integer, ForeignKey("users.id"))
    executed_by = Column(Integer, ForeignKey("users.id"))
    
    # Results
    summary = Column(JSON, default=dict)
    errors = Column(JSON, default=list)
    
    # Relationships
    target_plan = relationship("PricingPlan")
    created_by_user = relationship("User", foreign_keys=[created_by])
    approved_by_user = relationship("User", foreign_keys=[approved_by])
    executed_by_user = relationship("User", foreign_keys=[executed_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_bulk_migration_jobs_status', 'status'),
        Index('idx_bulk_migration_jobs_scheduled', 'scheduled_for'),
    )


class SubscriptionAuditLog(Base, TimestampMixin, TenantMixin):
    """Detailed audit log for all subscription changes"""
    __tablename__ = "subscription_audit_logs"
    
    id = Column(Integer, primary_key=True)
    
    # What changed
    subscription_id = Column(String(255), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    action = Column(String(100), nullable=False)  # created, updated, cancelled, migrated
    
    # Change details
    old_values = Column(JSON)
    new_values = Column(JSON)
    changes = Column(JSON)  # Diff of changes
    
    # Context
    initiated_by = Column(Integer, ForeignKey("users.id"))
    initiated_by_type = Column(String(50))  # admin, system, customer, webhook
    reason = Column(Text)
    
    # Related entities
    migration_id = Column(Integer, ForeignKey("subscription_migrations.id"))
    bulk_job_id = Column(Integer, ForeignKey("bulk_migration_jobs.id"))
    
    # Request tracking
    request_id = Column(String(100))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    
    # Stripe tracking
    stripe_event_id = Column(String(255))
    stripe_request_id = Column(String(255))
    
    # Metadata
    audit_metadata = Column(JSON, default=dict)
    
    # Relationships
    customer = relationship("Customer")
    user = relationship("User")
    migration = relationship("SubscriptionMigration")
    bulk_job = relationship("BulkMigrationJob")
    
    # Indexes
    __table_args__ = (
        Index('idx_subscription_audit_logs_subscription', 'subscription_id'),
        Index('idx_subscription_audit_logs_customer', 'customer_id'),
        Index('idx_subscription_audit_logs_action', 'action', 'created_at'),
    )


class PlanTransitionRule(Base, TimestampMixin, TenantMixin):
    """Rules for automatic plan transitions"""
    __tablename__ = "plan_transition_rules"
    
    id = Column(Integer, primary_key=True)
    
    # Rule details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    
    # Conditions
    source_plan_id = Column(Integer, ForeignKey("pricing_plans.id"))
    conditions = Column(JSON, default=dict)  # Additional conditions
    
    # Actions
    target_plan_id = Column(Integer, ForeignKey("pricing_plans.id"))
    strategy = Column(SQLEnum(MigrationStrategy), nullable=False)
    
    # Timing
    effective_date = Column(DateTime(timezone=True))
    expiration_date = Column(DateTime(timezone=True))
    
    # Configuration
    auto_approve = Column(Boolean, default=False)
    notify_customer = Column(Boolean, default=True)
    notification_template = Column(String(100))
    
    # Metadata
    priority = Column(Integer, default=0)  # Higher priority rules apply first
    rule_metadata = Column(JSON, default=dict)
    
    # Relationships
    source_plan = relationship("PricingPlan", foreign_keys=[source_plan_id])
    target_plan = relationship("PricingPlan", foreign_keys=[target_plan_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_plan_transition_rules_active', 'is_active', 'priority'),
        Index('idx_plan_transition_rules_source', 'source_plan_id'),
    )