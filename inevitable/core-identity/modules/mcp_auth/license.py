"""
MCP License Validation and Management System
"""
import json
import logging
import enum
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Enum as SQLEnum, Index
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

from ..core.database import Base, TimestampMixin, TenantMixin
from ..core.security import SecurityUtils

# Optional performance module import
try:
    from ..performance.cache import cached, cache_manager
    HAS_CACHE = True
except ImportError:
    HAS_CACHE = False
    # Dummy decorators if performance module not available
    def cached(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    cache_manager = None

logger = logging.getLogger(__name__)


class LicenseType(str, enum.Enum):
    """License types for MCP features"""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class LicenseStatus(str, enum.Enum):
    """License status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    PENDING = "pending"


class FeatureScope(str, enum.Enum):
    """Feature scopes for licensing"""
    MCP_BASIC = "mcp_basic"
    MCP_ADVANCED = "mcp_advanced"
    ENTERPRISE_SSO = "enterprise_sso"
    WEB3_AUTH = "web3_auth"
    WEB3_BILLING = "web3_billing"
    ANALYTICS_ADVANCED = "analytics_advanced"
    BILLING_ADVANCED = "billing_advanced"
    PERFORMANCE_MONITORING = "performance_monitoring"
    CUSTOM_BRANDING = "custom_branding"
    API_UNLIMITED = "api_unlimited"
    PRIORITY_SUPPORT = "priority_support"


class MCPLicense(Base, TimestampMixin, TenantMixin):
    """MCP License information"""
    __tablename__ = "mcp_licenses"
    
    id = Column(Integer, primary_key=True)
    
    # License identification
    license_key = Column(String(255), unique=True, nullable=False, index=True)
    license_type = Column(SQLEnum(LicenseType), nullable=False)
    status = Column(SQLEnum(LicenseStatus), nullable=False, default=LicenseStatus.PENDING)
    
    # Organization info
    organization_name = Column(String(255), nullable=False)
    contact_email = Column(String(255), nullable=False)
    
    # License validity
    issued_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    activated_at = Column(DateTime(timezone=True), nullable=True)
    
    # Usage limits
    max_users = Column(Integer, nullable=True)  # Null = unlimited
    max_api_calls_per_month = Column(Integer, nullable=True)
    max_storage_gb = Column(Integer, nullable=True)
    
    # Feature permissions
    allowed_features = Column(JSON, nullable=False, default=list)
    feature_limits = Column(JSON, nullable=False, default=dict)
    
    # License verification
    signature = Column(Text, nullable=False)  # Digital signature for verification
    public_key_id = Column(String(100), nullable=False)  # ID of public key used
    
    # Usage tracking
    current_users = Column(Integer, default=0)
    current_api_calls_month = Column(Integer, default=0)
    current_storage_gb = Column(Integer, default=0)
    last_usage_reset = Column(DateTime(timezone=True), default=func.now())
    
    # Metadata
    custom_metadata = Column(JSON, nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_mcp_licenses_tenant_status', 'tenant_id', 'status'),
        Index('idx_mcp_licenses_expires', 'expires_at', 'status'),
    )


class LicenseUsage(Base, TimestampMixin, TenantMixin):
    """License usage tracking"""
    __tablename__ = "license_usage"
    
    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, nullable=False, index=True)
    
    # Usage metrics
    feature_name = Column(String(100), nullable=False)
    usage_count = Column(Integer, default=1)
    usage_data = Column(JSON, nullable=True)
    
    # Context
    user_id = Column(Integer, nullable=True)
    endpoint = Column(String(500), nullable=True)
    request_id = Column(String(255), nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_license_usage_license_feature', 'license_id', 'feature_name'),
        Index('idx_license_usage_created', 'created_at'),
    )


class LicenseViolation(Base, TimestampMixin, TenantMixin):
    """License violation tracking"""
    __tablename__ = "license_violations"
    
    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, nullable=False, index=True)
    
    # Violation details
    violation_type = Column(String(100), nullable=False)  # usage_exceeded, feature_unauthorized, etc.
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    
    # Context
    feature_name = Column(String(100), nullable=True)
    attempted_value = Column(Integer, nullable=True)
    limit_value = Column(Integer, nullable=True)
    user_id = Column(Integer, nullable=True)
    endpoint = Column(String(500), nullable=True)
    
    # Resolution
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Metadata
    custom_metadata = Column(JSON, nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_license_violations_license', 'license_id', 'is_resolved'),
        Index('idx_license_violations_severity', 'severity', 'created_at'),
    )


class LicenseValidator:
    """License validation and verification service"""
    
    def __init__(self):
        # In production, these would be loaded from secure storage
        self.public_keys = {
            "platform-forge-2024": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qiWQZKZ4qiWQZKZ4qiW
QZKZExample...  # This would be a real public key
-----END PUBLIC KEY-----"""
        }
        self.cache_ttl = 300  # 5 minutes
    
    def verify_license_signature(
        self,
        license_data: Dict[str, Any],
        signature: str,
        public_key_id: str
    ) -> bool:
        """Verify license digital signature"""
        try:
            if public_key_id not in self.public_keys:
                logger.error(f"Unknown public key ID: {public_key_id}")
                return False
            
            # Load public key
            public_key_pem = self.public_keys[public_key_id]
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            
            # Create message to verify
            message_data = {
                "license_key": license_data["license_key"],
                "license_type": license_data["license_type"],
                "organization_name": license_data["organization_name"],
                "expires_at": license_data.get("expires_at"),
                "allowed_features": license_data["allowed_features"],
                "max_users": license_data.get("max_users"),
                "max_api_calls_per_month": license_data.get("max_api_calls_per_month")
            }
            
            message = json.dumps(message_data, sort_keys=True).encode()
            signature_bytes = base64.b64decode(signature)
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            logger.error("Invalid license signature")
            return False
        except Exception as e:
            logger.error(f"Error verifying license signature: {e}")
            return False
    
    @cached(ttl=300, tenant_aware=True)
    def get_license_for_tenant(
        self,
        db: Session,
        tenant_id: str
    ) -> Optional[MCPLicense]:
        """Get active license for tenant (cached)"""
        return db.query(MCPLicense).filter(
            MCPLicense.tenant_id == tenant_id,
            MCPLicense.status == LicenseStatus.ACTIVE
        ).first()
    
    def validate_feature_access(
        self,
        db: Session,
        tenant_id: str,
        feature: FeatureScope,
        user_id: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """Validate if tenant has access to a feature"""
        try:
            license = self.get_license_for_tenant(db, tenant_id)
            
            if not license:
                return False, "No active license found"
            
            # Check if license is expired
            if license.expires_at and license.expires_at < datetime.utcnow():
                self._update_license_status(db, license.id, LicenseStatus.EXPIRED)
                return False, "License has expired"
            
            # Check if feature is allowed
            if feature.value not in license.allowed_features:
                self._record_violation(
                    db, license.id, "feature_unauthorized",
                    f"Attempted to access unauthorized feature: {feature.value}",
                    "medium", feature_name=feature.value, user_id=user_id
                )
                return False, f"Feature {feature.value} not included in license"
            
            # Check feature-specific limits
            if not self._check_feature_limits(db, license, feature, user_id):
                return False, f"Feature {feature.value} usage limit exceeded"
            
            # Record usage
            self._record_usage(db, license.id, feature.value, user_id)
            
            return True, None
            
        except Exception as e:
            logger.error(f"Error validating feature access: {e}")
            return False, "License validation error"
    
    def validate_usage_limits(
        self,
        db: Session,
        tenant_id: str,
        check_api_calls: bool = False,
        check_users: bool = False,
        check_storage: bool = False
    ) -> Tuple[bool, List[str]]:
        """Validate usage against license limits"""
        license = self.get_license_for_tenant(db, tenant_id)
        if not license:
            return False, ["No active license found"]
        
        violations = []
        
        # Check user count
        if check_users and license.max_users:
            if license.current_users > license.max_users:
                violations.append(f"User count ({license.current_users}) exceeds limit ({license.max_users})")
                self._record_violation(
                    db, license.id, "user_limit_exceeded",
                    f"Current users: {license.current_users}, Limit: {license.max_users}",
                    "high", attempted_value=license.current_users, limit_value=license.max_users
                )
        
        # Check API calls
        if check_api_calls and license.max_api_calls_per_month:
            if license.current_api_calls_month > license.max_api_calls_per_month:
                violations.append(f"API calls ({license.current_api_calls_month}) exceed monthly limit ({license.max_api_calls_per_month})")
                self._record_violation(
                    db, license.id, "api_limit_exceeded",
                    f"Current API calls: {license.current_api_calls_month}, Limit: {license.max_api_calls_per_month}",
                    "medium", attempted_value=license.current_api_calls_month, limit_value=license.max_api_calls_per_month
                )
        
        # Check storage
        if check_storage and license.max_storage_gb:
            if license.current_storage_gb > license.max_storage_gb:
                violations.append(f"Storage ({license.current_storage_gb}GB) exceeds limit ({license.max_storage_gb}GB)")
                self._record_violation(
                    db, license.id, "storage_limit_exceeded",
                    f"Current storage: {license.current_storage_gb}GB, Limit: {license.max_storage_gb}GB",
                    "high", attempted_value=license.current_storage_gb, limit_value=license.max_storage_gb
                )
        
        return len(violations) == 0, violations
    
    def install_license(
        self,
        db: Session,
        license_key: str,
        tenant_id: str
    ) -> Tuple[bool, str, Optional[MCPLicense]]:
        """Install and activate a license"""
        try:
            # Parse license key (base64 encoded JSON)
            try:
                license_data = json.loads(base64.b64decode(license_key).decode())
            except Exception:
                return False, "Invalid license key format", None
            
            # Verify signature
            if not self.verify_license_signature(
                license_data,
                license_data["signature"],
                license_data["public_key_id"]
            ):
                return False, "Invalid license signature", None
            
            # Check if license already exists
            existing = db.query(MCPLicense).filter(
                MCPLicense.license_key == license_key
            ).first()
            
            if existing:
                if existing.tenant_id == tenant_id:
                    return False, "License already installed for this tenant", existing
                else:
                    return False, "License already in use by another tenant", None
            
            # Create license record
            license = MCPLicense(
                license_key=license_key,
                license_type=LicenseType(license_data["license_type"]),
                status=LicenseStatus.ACTIVE,
                organization_name=license_data["organization_name"],
                contact_email=license_data["contact_email"],
                expires_at=datetime.fromisoformat(license_data["expires_at"]) if license_data.get("expires_at") else None,
                activated_at=datetime.utcnow(),
                max_users=license_data.get("max_users"),
                max_api_calls_per_month=license_data.get("max_api_calls_per_month"),
                max_storage_gb=license_data.get("max_storage_gb"),
                allowed_features=license_data["allowed_features"],
                feature_limits=license_data.get("feature_limits", {}),
                signature=license_data["signature"],
                public_key_id=license_data["public_key_id"],
                metadata=license_data.get("metadata", {}),
                tenant_id=tenant_id
            )
            
            db.add(license)
            db.commit()
            
            # Clear cache
            cache_manager.delete_pattern(f"*license*{tenant_id}*")
            
            return True, "License installed successfully", license
            
        except Exception as e:
            logger.error(f"Error installing license: {e}")
            db.rollback()
            return False, f"License installation failed: {str(e)}", None
    
    def _check_feature_limits(
        self,
        db: Session,
        license: MCPLicense,
        feature: FeatureScope,
        user_id: Optional[int]
    ) -> bool:
        """Check feature-specific limits"""
        feature_limits = license.feature_limits.get(feature.value, {})
        
        # Check daily limits
        if "daily_limit" in feature_limits:
            today = datetime.utcnow().date()
            daily_usage = db.query(func.sum(LicenseUsage.usage_count)).filter(
                LicenseUsage.license_id == license.id,
                LicenseUsage.feature_name == feature.value,
                func.date(LicenseUsage.created_at) == today
            ).scalar() or 0
            
            if daily_usage >= feature_limits["daily_limit"]:
                self._record_violation(
                    db, license.id, "daily_limit_exceeded",
                    f"Daily limit exceeded for {feature.value}: {daily_usage}/{feature_limits['daily_limit']}",
                    "medium", feature_name=feature.value, user_id=user_id,
                    attempted_value=daily_usage, limit_value=feature_limits["daily_limit"]
                )
                return False
        
        return True
    
    def _record_usage(
        self,
        db: Session,
        license_id: int,
        feature_name: str,
        user_id: Optional[int],
        usage_count: int = 1
    ):
        """Record feature usage"""
        try:
            usage = LicenseUsage(
                license_id=license_id,
                feature_name=feature_name,
                usage_count=usage_count,
                user_id=user_id,
                tenant_id=None  # Will be set by middleware
            )
            db.add(usage)
            db.commit()
        except Exception as e:
            logger.error(f"Error recording usage: {e}")
    
    def _record_violation(
        self,
        db: Session,
        license_id: int,
        violation_type: str,
        description: str,
        severity: str,
        **kwargs
    ):
        """Record license violation"""
        try:
            violation = LicenseViolation(
                license_id=license_id,
                violation_type=violation_type,
                description=description,
                severity=severity,
                feature_name=kwargs.get("feature_name"),
                attempted_value=kwargs.get("attempted_value"),
                limit_value=kwargs.get("limit_value"),
                user_id=kwargs.get("user_id"),
                endpoint=kwargs.get("endpoint"),
                metadata=kwargs.get("metadata", {}),
                tenant_id=None  # Will be set by middleware
            )
            db.add(violation)
            db.commit()
        except Exception as e:
            logger.error(f"Error recording violation: {e}")
    
    def _update_license_status(
        self,
        db: Session,
        license_id: int,
        status: LicenseStatus
    ):
        """Update license status"""
        try:
            license = db.query(MCPLicense).filter(MCPLicense.id == license_id).first()
            if license:
                license.status = status
                db.commit()
                
                # Clear cache
                cache_manager.delete_pattern(f"*license*{license.tenant_id}*")
        except Exception as e:
            logger.error(f"Error updating license status: {e}")


# Global license validator instance
license_validator = LicenseValidator()


# Feature access decorators
def require_license_feature(feature: FeatureScope):
    """Decorator to require license feature access"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract tenant_id from kwargs or function context
            tenant_id = kwargs.get("tenant_id")
            if not tenant_id:
                raise ValueError("Tenant ID required for license validation")
            
            # Get database session
            db = kwargs.get("db")
            if not db:
                from ..core.database import get_db
                db = next(get_db())
            
            # Validate feature access
            has_access, error_msg = license_validator.validate_feature_access(
                db, tenant_id, feature, kwargs.get("user_id")
            )
            
            if not has_access:
                from fastapi import HTTPException
                raise HTTPException(403, f"License required: {error_msg}")
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def check_usage_limits(**limits):
    """Decorator to check usage limits"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            tenant_id = kwargs.get("tenant_id")
            if not tenant_id:
                raise ValueError("Tenant ID required for license validation")
            
            db = kwargs.get("db")
            if not db:
                from ..core.database import get_db
                db = next(get_db())
            
            # Validate usage limits
            valid, violations = license_validator.validate_usage_limits(
                db, tenant_id, **limits
            )
            
            if not valid:
                from fastapi import HTTPException
                raise HTTPException(429, f"Usage limit exceeded: {'; '.join(violations)}")
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator