"""
Enterprise MCP Authentication Module for Platform Forge
Provides enterprise-grade authentication and authorization for Model Context Protocol
"""

from .models import MCPPolicy, MCPSession, MCPAuditLog
from .auth import MCPAuthProvider
from .policy_engine import PolicyEngine
from .routes import router
from .license import (
    MCPLicense, LicenseUsage, LicenseViolation,
    LicenseType, LicenseStatus, FeatureScope,
    license_validator, require_license_feature, check_usage_limits
)
from .license_routes import router as license_router
from .license_middleware import LicenseEnforcementMiddleware, UsageLimitMiddleware

__all__ = [
    "MCPPolicy",
    "MCPSession", 
    "MCPAuditLog",
    "MCPAuthProvider",
    "PolicyEngine",
    "router",
    "MCPLicense",
    "LicenseUsage",
    "LicenseViolation",
    "LicenseType",
    "LicenseStatus",
    "FeatureScope",
    "license_validator",
    "require_license_feature",
    "check_usage_limits",
    "license_router",
    "LicenseEnforcementMiddleware",
    "UsageLimitMiddleware"
]