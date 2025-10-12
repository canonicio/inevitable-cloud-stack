"""
Tenant models for multi-tenant SaaS and PaaS deployments
"""
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, JSON, Boolean, DateTime, Enum as SQLEnum
from sqlalchemy.orm import relationship

from .database import Base, TimestampMixin


class TenantType(str, Enum):
    """Types of tenant deployments"""
    SHARED = "shared"  # Shared database, row-level isolation
    SCHEMA = "schema"  # Database schema per tenant
    DATABASE = "database"  # Separate database per tenant
    ISOLATED = "isolated"  # Completely isolated infrastructure


class TenantStatus(str, Enum):
    """Tenant lifecycle status"""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    DELETED = "deleted"


class TenantPlan(str, Enum):
    """Tenant subscription plans"""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class Tenant(Base, TimestampMixin):
    """Central tenant registry for multi-tenant applications"""
    __tablename__ = "tenants"
    
    # Core fields
    id = Column(String(50), primary_key=True, index=True)  # Tenant ID used across all tables
    name = Column(String(255), nullable=False)
    display_name = Column(String(255))
    slug = Column(String(100), unique=True, index=True)  # URL-safe identifier
    
    # Deployment configuration
    tenant_type = Column(String(20), default=TenantType.SHARED)
    database_url = Column(Text, nullable=True)  # For DATABASE type tenants
    schema_name = Column(String(63), nullable=True)  # For SCHEMA type tenants
    
    # Status and lifecycle
    status = Column(String(20), default=TenantStatus.PENDING)
    plan = Column(String(20), default=TenantPlan.FREE)
    trial_ends_at = Column(DateTime, nullable=True)
    suspended_at = Column(DateTime, nullable=True)
    
    # Contact information
    admin_email = Column(String(255), nullable=False)
    admin_name = Column(String(255))
    admin_phone = Column(String(50))
    billing_email = Column(String(255))
    technical_email = Column(String(255))
    
    # Organization details
    company_name = Column(String(255))
    industry = Column(String(100))
    size = Column(String(50))  # 1-10, 11-50, 51-200, etc
    country = Column(String(2))  # ISO country code
    timezone = Column(String(50), default="UTC")
    
    # Resource limits
    max_users = Column(Integer, default=5)
    max_storage_gb = Column(Integer, default=10)
    max_api_calls_per_hour = Column(Integer, default=1000)
    max_projects = Column(Integer, default=3)
    
    # Feature flags
    features = Column(JSON, default=dict)  # {"feature_name": true/false}
    
    # Custom domain
    custom_domain = Column(String(255), unique=True, nullable=True)
    custom_domain_verified = Column(Boolean, default=False)
    
    # Metadata
    extra_metadata = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    
    # Provisioning details
    provisioned_at = Column(DateTime, nullable=True)
    provisioned_by = Column(String(255), nullable=True)
    
    # Deactivation/deletion
    deactivated_at = Column(DateTime, nullable=True)
    deactivation_reason = Column(Text, nullable=True)
    scheduled_deletion_at = Column(DateTime, nullable=True)


class TenantSettings(Base, TimestampMixin):
    """Tenant-specific settings and preferences"""
    __tablename__ = "tenant_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(50), unique=True, nullable=False, index=True)
    
    # Application settings
    app_settings = Column(JSON, default=dict)
    
    # Security settings
    security_settings = Column(JSON, default=dict)
    allowed_ip_ranges = Column(JSON, default=list)
    password_policy = Column(JSON, default=dict)
    
    # Integration settings
    integrations = Column(JSON, default=dict)
    webhook_urls = Column(JSON, default=list)
    api_keys = Column(JSON, default=list)  # Encrypted
    
    # Notification preferences
    notification_settings = Column(JSON, default=dict)
    
    # Data retention
    data_retention_days = Column(Integer, default=90)
    backup_enabled = Column(Boolean, default=True)
    backup_frequency = Column(String(20), default="daily")


class TenantDomain(Base, TimestampMixin):
    """Custom domains for tenants"""
    __tablename__ = "tenant_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    subdomain = Column(String(100), nullable=True)
    
    # Verification
    is_primary = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(255))
    verified_at = Column(DateTime, nullable=True)
    
    # SSL
    ssl_enabled = Column(Boolean, default=True)
    ssl_certificate_id = Column(String(255), nullable=True)
    ssl_expires_at = Column(DateTime, nullable=True)


class TenantUsage(Base, TimestampMixin):
    """Track tenant resource usage"""
    __tablename__ = "tenant_usage"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    
    # Usage metrics
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Resource usage
    user_count = Column(Integer, default=0)
    storage_gb_used = Column(Integer, default=0)
    api_calls = Column(Integer, default=0)
    bandwidth_gb = Column(Integer, default=0)
    
    # Feature usage
    feature_usage = Column(JSON, default=dict)  # {"feature": count}
    
    # Costs
    computed_cost = Column(Integer, default=0)  # In cents
    
    # Unique constraint on tenant + period
    __table_args__ = (
        UniqueConstraint('tenant_id', 'period_start', 'period_end'),
    )


class TenantAuditLog(Base, TimestampMixin):
    """Audit log for tenant-level actions"""
    __tablename__ = "tenant_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    
    # Action details
    action = Column(String(100), nullable=False)  # created, updated, suspended, etc
    actor_id = Column(String(255))  # User or system that performed action
    actor_type = Column(String(50))  # user, system, api
    
    # Change details
    changes = Column(JSON, default=dict)  # {"field": {"old": x, "new": y}}
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Additional context
    context = Column(JSON, default=dict)