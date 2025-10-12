"""
License management API routes
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_, func, desc
from pydantic import BaseModel, Field, validator

from ..core.database import get_db
from ..core.enhanced_validators import SecureBaseModel, APIParameterValidator
from ..auth.dependencies import get_current_user, require_tenant
from ..auth.models import User
from ..auth.permissions import require_permission, Resource, Action

# Optional analytics module import
try:
    from ..analytics.tracker import track_feature_use
except ImportError:
    # Dummy decorator if analytics module not available
    def track_feature_use(feature_name):
        def decorator(func):
            return func
        return decorator
from .license import (
    MCPLicense, LicenseUsage, LicenseViolation,
    LicenseType, LicenseStatus, FeatureScope,
    license_validator
)

router = APIRouter(prefix="/license", tags=["license"])


class LicenseInstallRequest(SecureBaseModel):
    license_key: str = Field(..., min_length=100, description="Base64 encoded license key")


class LicenseInfo(SecureBaseModel):
    id: int
    license_type: LicenseType
    status: LicenseStatus
    organization_name: str
    contact_email: str
    issued_at: datetime
    expires_at: Optional[datetime]
    activated_at: Optional[datetime]
    max_users: Optional[int]
    max_api_calls_per_month: Optional[int]
    max_storage_gb: Optional[int]
    allowed_features: List[str]
    current_users: int
    current_api_calls_month: int
    current_storage_gb: int


class UsageSummary(SecureBaseModel):
    feature_name: str
    total_usage: int
    daily_usage: int
    monthly_usage: int
    last_used: Optional[datetime]


class ViolationInfo(SecureBaseModel):
    id: int
    violation_type: str
    description: str
    severity: str
    feature_name: Optional[str]
    attempted_value: Optional[int]
    limit_value: Optional[int]
    created_at: datetime
    is_resolved: bool
    resolved_at: Optional[datetime]


# License management endpoints
    @validator('description')
    def validate_description(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'description')
                        return v

@router.get("/info", response_model=LicenseInfo)
@track_feature_use("license_info_view")
async def get_license_info(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Get current license information"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    if not license:
        raise HTTPException(404, "No active license found")
    
    return LicenseInfo(
        id=license.id,
        license_type=license.license_type,
        status=license.status,
        organization_name=license.organization_name,
        contact_email=license.contact_email,
        issued_at=license.issued_at,
        expires_at=license.expires_at,
        activated_at=license.activated_at,
        max_users=license.max_users,
        max_api_calls_per_month=license.max_api_calls_per_month,
        max_storage_gb=license.max_storage_gb,
        allowed_features=license.allowed_features,
        current_users=license.current_users,
        current_api_calls_month=license.current_api_calls_month,
        current_storage_gb=license.current_storage_gb
    )


@router.post("/install")
@require_permission(Resource.ADMIN, Action.CREATE)
@track_feature_use("license_install")
async def install_license(
    license_request: LicenseInstallRequest,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Install a new license (admin only)"""
    success, message, license = license_validator.install_license(
        db, license_request.license_key, tenant_id
    )
    
    if not success:
        raise HTTPException(400, message)
    
    return {
        "message": message,
        "license_id": license.id,
        "license_type": license.license_type,
        "expires_at": license.expires_at,
        "allowed_features": license.allowed_features
    }


@router.get("/validate/{feature}")
async def validate_feature_access(
    feature: FeatureScope,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Validate access to a specific feature"""
    has_access, error_msg = license_validator.validate_feature_access(
        db, tenant_id, feature, current_user.id
    )
    
    return {
        "feature": feature.value,
        "has_access": has_access,
        "error_message": error_msg,
        "tenant_id": tenant_id
    }


@router.get("/usage/summary")
@track_feature_use("license_usage_summary")
async def get_usage_summary(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Get license usage summary"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    if not license:
        raise HTTPException(404, "No active license found")
    
    # Get usage data
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Feature usage summary
    usage_query = db.query(
        LicenseUsage.feature_name,
        func.sum(LicenseUsage.usage_count).label('total_usage'),
        func.max(LicenseUsage.created_at).label('last_used')
    ).filter(
        and_(
            LicenseUsage.license_id == license.id,
            LicenseUsage.created_at >= start_date
        )
    ).group_by(LicenseUsage.feature_name).all()
    
    # Daily usage for today
    today = datetime.utcnow().date()
    daily_usage = {}
    daily_query = db.query(
        LicenseUsage.feature_name,
        func.sum(LicenseUsage.usage_count).label('daily_usage')
    ).filter(
        and_(
            LicenseUsage.license_id == license.id,
            func.date(LicenseUsage.created_at) == today
        )
    ).group_by(LicenseUsage.feature_name).all()
    
    for row in daily_query:
        daily_usage[row.feature_name] = row.daily_usage
    
    # Monthly usage
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_usage = {}
    monthly_query = db.query(
        LicenseUsage.feature_name,
        func.sum(LicenseUsage.usage_count).label('monthly_usage')
    ).filter(
        and_(
            LicenseUsage.license_id == license.id,
            LicenseUsage.created_at >= month_start
        )
    ).group_by(LicenseUsage.feature_name).all()
    
    for row in monthly_query:
        monthly_usage[row.feature_name] = row.monthly_usage
    
    # Build response
    usage_summary = []
    for row in usage_query:
        usage_summary.append(UsageSummary(
            feature_name=row.feature_name,
            total_usage=row.total_usage,
            daily_usage=daily_usage.get(row.feature_name, 0),
            monthly_usage=monthly_usage.get(row.feature_name, 0),
            last_used=row.last_used
        ))
    
    # Check current limits
    valid, violations = license_validator.validate_usage_limits(
        db, tenant_id, check_api_calls=True, check_users=True, check_storage=True
    )
    
    return {
        "license_type": license.license_type,
        "period_days": days,
        "usage_summary": usage_summary,
        "current_limits": {
            "users": {
                "current": license.current_users,
                "limit": license.max_users,
                "percentage": (license.current_users / license.max_users * 100) if license.max_users else 0
            },
            "api_calls": {
                "current": license.current_api_calls_month,
                "limit": license.max_api_calls_per_month,
                "percentage": (license.current_api_calls_month / license.max_api_calls_per_month * 100) if license.max_api_calls_per_month else 0
            },
            "storage": {
                "current": license.current_storage_gb,
                "limit": license.max_storage_gb,
                "percentage": (license.current_storage_gb / license.max_storage_gb * 100) if license.max_storage_gb else 0
            }
        },
        "limits_valid": valid,
        "violations": violations
    }


@router.get("/violations")
@require_permission(Resource.ADMIN, Action.READ)
async def list_license_violations(
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    is_resolved: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """List license violations (admin only)"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    if not license:
        raise HTTPException(404, "No active license found")
    
    query = db.query(LicenseViolation).filter(
        LicenseViolation.license_id == license.id
    )
    
    if severity:
        query = query.filter(LicenseViolation.severity == severity)
    
    if is_resolved is not None:
        query = query.filter(LicenseViolation.is_resolved == is_resolved)
    
    violations = query.order_by(
        desc(LicenseViolation.created_at)
    ).limit(limit).all()
    
    return {
        "violations": [
            ViolationInfo(
                id=v.id,
                violation_type=v.violation_type,
                description=v.description,
                severity=v.severity,
                feature_name=v.feature_name,
                attempted_value=v.attempted_value,
                limit_value=v.limit_value,
                created_at=v.created_at,
                is_resolved=v.is_resolved,
                resolved_at=v.resolved_at
            )
            for v in violations
        ],
        "total_count": len(violations)
    }


@router.put("/violations/{violation_id}/resolve")
@require_permission(Resource.ADMIN, Action.UPDATE)
async def resolve_violation(
    violation_id: int,
    resolution_notes: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Resolve a license violation (admin only)"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    if not license:
        raise HTTPException(404, "No active license found")
    
    violation = db.query(LicenseViolation).filter(
        and_(
            LicenseViolation.id == violation_id,
            LicenseViolation.license_id == license.id
        )
    ).first()
    
    if not violation:
        raise HTTPException(404, "Violation not found")
    
    if violation.is_resolved:
        raise HTTPException(400, "Violation already resolved")
    
    violation.is_resolved = True
    violation.resolved_at = datetime.utcnow()
    violation.resolution_notes = resolution_notes
    
    db.commit()
    
    return {
        "violation_id": violation.id,
        "message": "Violation resolved successfully"
    }


@router.get("/features/available")
async def list_available_features(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """List all available features and their license requirements"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    # Feature definitions with requirements
    feature_info = {
        FeatureScope.MCP_BASIC: {
            "name": "MCP Basic",
            "description": "Basic Model Context Protocol features",
            "required_license": ["starter", "professional", "enterprise"]
        },
        FeatureScope.MCP_ADVANCED: {
            "name": "MCP Advanced",
            "description": "Advanced MCP features with policy engine",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.ENTERPRISE_SSO: {
            "name": "Enterprise SSO",
            "description": "SAML, OAuth, and LDAP authentication",
            "required_license": ["enterprise"]
        },
        FeatureScope.WEB3_AUTH: {
            "name": "Web3 Authentication",
            "description": "Blockchain wallet authentication",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.WEB3_BILLING: {
            "name": "Web3 Billing",
            "description": "Cryptocurrency subscription payments",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.ANALYTICS_ADVANCED: {
            "name": "Advanced Analytics",
            "description": "User behavior tracking and insights",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.BILLING_ADVANCED: {
            "name": "Advanced Billing",
            "description": "Usage-based billing and metering",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.PERFORMANCE_MONITORING: {
            "name": "Performance Monitoring",
            "description": "Redis caching and optimization",
            "required_license": ["professional", "enterprise"]
        },
        FeatureScope.CUSTOM_BRANDING: {
            "name": "Custom Branding",
            "description": "White-label customization",
            "required_license": ["enterprise"]
        },
        FeatureScope.API_UNLIMITED: {
            "name": "Unlimited API",
            "description": "No API rate limiting",
            "required_license": ["enterprise"]
        },
        FeatureScope.PRIORITY_SUPPORT: {
            "name": "Priority Support",
            "description": "24/7 priority customer support",
            "required_license": ["enterprise"]
        }
    }
    
    # Check access for each feature
    features = []
    for feature_scope, info in feature_info.items():
        has_access = False
        if license:
            has_access, _ = license_validator.validate_feature_access(
                db, tenant_id, feature_scope, current_user.id
            )
        
        features.append({
            "feature": feature_scope.value,
            "name": info["name"],
            "description": info["description"],
            "required_license": info["required_license"],
            "has_access": has_access,
            "current_license": license.license_type.value if license else None
        })
    
    return {
        "features": features,
        "current_license": license.license_type.value if license else None,
        "license_status": license.status.value if license else "none"
    }


@router.get("/health")
async def license_health_check(
    current_user: User = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: Session = Depends(get_db)
):
    """Check license health and status"""
    license = license_validator.get_license_for_tenant(db, tenant_id)
    
    if not license:
        return {
            "status": "no_license",
            "message": "No license installed",
            "health": "critical"
        }
    
    health_issues = []
    health_status = "healthy"
    
    # Check expiration
    if license.expires_at:
        days_until_expiry = (license.expires_at - datetime.utcnow()).days
        if days_until_expiry <= 0:
            health_issues.append("License has expired")
            health_status = "critical"
        elif days_until_expiry <= 7:
            health_issues.append(f"License expires in {days_until_expiry} days")
            health_status = "warning"
        elif days_until_expiry <= 30:
            health_issues.append(f"License expires in {days_until_expiry} days")
            if health_status == "healthy":
                health_status = "notice"
    
    # Check usage limits
    valid, violations = license_validator.validate_usage_limits(
        db, tenant_id, check_api_calls=True, check_users=True, check_storage=True
    )
    
    if not valid:
        health_issues.extend(violations)
        if health_status in ["healthy", "notice"]:
            health_status = "warning"
    
    # Check for recent violations
    recent_violations = db.query(LicenseViolation).filter(
        and_(
            LicenseViolation.license_id == license.id,
            LicenseViolation.created_at >= datetime.utcnow() - timedelta(days=1),
            LicenseViolation.is_resolved == False
        )
    ).count()
    
    if recent_violations > 0:
        health_issues.append(f"{recent_violations} unresolved violations in the last 24 hours")
        if health_status == "healthy":
            health_status = "notice"
    
    return {
        "status": license.status.value,
        "license_type": license.license_type.value,
        "health": health_status,
        "issues": health_issues,
        "expires_at": license.expires_at,
        "days_until_expiry": (license.expires_at - datetime.utcnow()).days if license.expires_at else None,
        "usage_valid": valid
    }