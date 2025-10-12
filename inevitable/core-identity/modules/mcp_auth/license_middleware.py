"""
License enforcement middleware
"""
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlalchemy.orm import Session

from ..core.database import get_db_session_factory
from .license import license_validator, FeatureScope

logger = logging.getLogger(__name__)


class LicenseEnforcementMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce license requirements for protected endpoints"""
    
    def __init__(self, app, protected_routes: Optional[Dict[str, FeatureScope]] = None):
        super().__init__(app)
        
        # Default protected routes mapping
        self.protected_routes = protected_routes or {
            # MCP routes
            "/api/mcp": FeatureScope.MCP_BASIC,
            "/api/mcp/advanced": FeatureScope.MCP_ADVANCED,
            
            # Enterprise SSO
            "/api/enterprise-sso": FeatureScope.ENTERPRISE_SSO,
            "/api/auth/saml": FeatureScope.ENTERPRISE_SSO,
            "/api/auth/ldap": FeatureScope.ENTERPRISE_SSO,
            
            # Web3 features
            "/api/web3": FeatureScope.WEB3_AUTH,
            "/api/web3-billing": FeatureScope.WEB3_BILLING,
            
            # Advanced features
            "/api/analytics": FeatureScope.ANALYTICS_ADVANCED,
            "/api/billing-advanced": FeatureScope.BILLING_ADVANCED,
            "/api/performance": FeatureScope.PERFORMANCE_MONITORING,
            
            # Enterprise only
            "/api/admin/branding": FeatureScope.CUSTOM_BRANDING,
        }
        
        # Routes that are always exempt from license checks
        self.exempt_routes = {
            "/api/auth/login",
            "/api/auth/register", 
            "/api/auth/logout",
            "/api/license/info",
            "/api/license/install",
            "/api/license/health",
            "/docs",
            "/openapi.json",
            "/metrics",
            "/health"
        }
        
        self.db_factory = get_db_session_factory()
    
    async def dispatch(self, request: Request, call_next):
        """Process request and enforce license requirements"""
        try:
            # Skip license checks for exempt routes
            if self._is_exempt_route(request.url.path):
                return await call_next(request)
            
            # Skip for OPTIONS requests
            if request.method == "OPTIONS":
                return await call_next(request)
            
            # Get tenant ID from request
            tenant_id = self._extract_tenant_id(request)
            if not tenant_id:
                # Allow requests without tenant ID to proceed (they may be handled by other middleware)
                return await call_next(request)
            
            # Check if route requires license
            required_feature = self._get_required_feature(request.url.path)
            if not required_feature:
                # Route doesn't require specific license
                return await call_next(request)
            
            # Validate license
            with self.db_factory() as db:
                has_access, error_msg = license_validator.validate_feature_access(
                    db, tenant_id, required_feature, self._extract_user_id(request)
                )
                
                if not has_access:
                    return self._create_license_error_response(required_feature, error_msg)
                
                # Update API call count for usage tracking
                await self._track_api_usage(db, tenant_id)
            
            # Proceed with request
            response = await call_next(request)
            
            # Add license info to response headers (optional)
            if hasattr(request.state, "license_info"):
                response.headers["X-License-Type"] = request.state.license_info.get("type", "unknown")
                response.headers["X-License-Status"] = request.state.license_info.get("status", "unknown")
            
            return response
            
        except Exception as e:
            logger.error(f"License middleware error: {e}")
            # Don't block requests due to license middleware errors
            return await call_next(request)
    
    def _is_exempt_route(self, path: str) -> bool:
        """Check if route is exempt from license checks"""
        # Exact matches
        if path in self.exempt_routes:
            return True
        
        # Prefix matches for exempt routes
        exempt_prefixes = ["/docs", "/static", "/favicon"]
        for prefix in exempt_prefixes:
            if path.startswith(prefix):
                return True
        
        return False
    
    def _get_required_feature(self, path: str) -> Optional[FeatureScope]:
        """Get required feature scope for a path"""
        # Check exact matches first
        if path in self.protected_routes:
            return self.protected_routes[path]
        
        # Check prefix matches (longest match wins)
        matches = []
        for route_pattern, feature in self.protected_routes.items():
            if path.startswith(route_pattern):
                matches.append((len(route_pattern), feature))
        
        if matches:
            # Return feature for longest matching prefix
            matches.sort(reverse=True)
            return matches[0][1]
        
        return None
    
    def _extract_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant ID from request - JWT ONLY for security"""
        # CRITICAL SECURITY FIX: Only use JWT for tenant ID, never headers
        # Check if tenant_id already set by tenant isolation middleware
        if hasattr(request.state, 'tenant_id'):
            return request.state.tenant_id
        
        # Extract from JWT token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                import jwt
                from modules.core.config import settings
                token = auth_header.split(" ")[1]
                # CRITICAL FIX: Properly verify JWT signature to prevent token forgery
                payload = jwt.decode(
                    token, 
                    settings.SECRET_KEY, 
                    algorithms=[settings.ALGORITHM]
                )
                return payload.get("tenant_id")
            except Exception:
                pass
        
        # Try query parameter
        return request.query_params.get("tenant_id")
    
    def _extract_user_id(self, request: Request) -> Optional[int]:
        """Extract user ID from request"""
        # Try from JWT token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                import jwt
                from modules.core.config import settings
                token = auth_header.split(" ")[1]
                # CRITICAL FIX: Properly verify JWT signature to prevent token forgery
                payload = jwt.decode(
                    token, 
                    settings.SECRET_KEY, 
                    algorithms=[settings.ALGORITHM]
                )
                return payload.get("user_id")
            except Exception:
                pass
        
        return None
    
    def _create_license_error_response(
        self,
        required_feature: FeatureScope,
        error_msg: str
    ) -> Response:
        """Create license error response"""
        error_response = {
            "error": "License Required",
            "message": error_msg,
            "required_feature": required_feature.value,
            "upgrade_info": {
                "current_plan": "Check /api/license/info for current plan",
                "required_plans": self._get_plans_for_feature(required_feature),
                "contact": "Contact sales for license upgrade"
            }
        }
        
        import json
        return Response(
            content=json.dumps(error_response),
            status_code=403,
            headers={"Content-Type": "application/json"}
        )
    
    def _get_plans_for_feature(self, feature: FeatureScope) -> list:
        """Get license plans that include a feature"""
        feature_plans = {
            FeatureScope.MCP_BASIC: ["starter", "professional", "enterprise"],
            FeatureScope.MCP_ADVANCED: ["professional", "enterprise"],
            FeatureScope.ENTERPRISE_SSO: ["enterprise"],
            FeatureScope.WEB3_AUTH: ["professional", "enterprise"],
            FeatureScope.WEB3_BILLING: ["professional", "enterprise"],
            FeatureScope.ANALYTICS_ADVANCED: ["professional", "enterprise"],
            FeatureScope.BILLING_ADVANCED: ["professional", "enterprise"],
            FeatureScope.PERFORMANCE_MONITORING: ["professional", "enterprise"],
            FeatureScope.CUSTOM_BRANDING: ["enterprise"],
            FeatureScope.API_UNLIMITED: ["enterprise"],
            FeatureScope.PRIORITY_SUPPORT: ["enterprise"]
        }
        
        return feature_plans.get(feature, ["enterprise"])
    
    async def _track_api_usage(self, db: Session, tenant_id: str):
        """Track API usage for license limits"""
        try:
            license = license_validator.get_license_for_tenant(db, tenant_id)
            if license and license.max_api_calls_per_month:
                # Increment API call count
                license.current_api_calls_month += 1
                
                # Reset monthly counter if needed
                now = datetime.utcnow()
                if license.last_usage_reset:
                    # Check if we've crossed into a new month
                    if (now.year, now.month) != (license.last_usage_reset.year, license.last_usage_reset.month):
                        license.current_api_calls_month = 1
                        license.last_usage_reset = now
                else:
                    license.last_usage_reset = now
                
                db.commit()
                
                # Check if approaching limits
                if license.current_api_calls_month > license.max_api_calls_per_month * 0.9:
                    logger.warning(
                        f"Tenant {tenant_id} approaching API limit: "
                        f"{license.current_api_calls_month}/{license.max_api_calls_per_month}"
                    )
        
        except Exception as e:
            logger.error(f"Error tracking API usage: {e}")


class UsageLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce usage limits"""
    
    def __init__(self, app):
        super().__init__(app)
        self.db_factory = get_db_session_factory()
    
    async def dispatch(self, request: Request, call_next):
        """Check usage limits before processing request"""
        try:
            # Extract tenant ID
            tenant_id = self._extract_tenant_id(request)
            if not tenant_id:
                return await call_next(request)
            
            # Skip for certain endpoints
            if self._is_exempt_route(request.url.path):
                return await call_next(request)
            
            # Check usage limits
            with self.db_factory() as db:
                valid, violations = license_validator.validate_usage_limits(
                    db, tenant_id, 
                    check_api_calls=True,
                    check_users=False,  # Don't check users for every request
                    check_storage=False
                )
                
                if not valid:
                    error_response = {
                        "error": "Usage Limit Exceeded",
                        "violations": violations,
                        "message": "Your current usage exceeds license limits"
                    }
                    
                    import json
                    return Response(
                        content=json.dumps(error_response),
                        status_code=429,
                        headers={"Content-Type": "application/json"}
                    )
            
            return await call_next(request)
            
        except Exception as e:
            logger.error(f"Usage limit middleware error: {e}")
            return await call_next(request)
    
    def _extract_tenant_id(self, request: Request) -> Optional[str]:
        """Extract tenant ID from request - JWT ONLY for security"""
        # CRITICAL SECURITY FIX: Only use JWT for tenant ID, never headers
        # Check if tenant_id already set by tenant isolation middleware
        if hasattr(request.state, 'tenant_id'):
            return request.state.tenant_id
        
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                import jwt
                from modules.core.config import settings
                token = auth_header.split(" ")[1]
                # CRITICAL FIX: Properly verify JWT signature to prevent token forgery
                payload = jwt.decode(
                    token, 
                    settings.SECRET_KEY, 
                    algorithms=[settings.ALGORITHM]
                )
                return payload.get("tenant_id")
            except Exception:
                pass
        
        return request.query_params.get("tenant_id")
    
    def _is_exempt_route(self, path: str) -> bool:
        """Check if route is exempt from usage limits"""
        exempt_routes = {
            "/api/license",
            "/api/auth",
            "/docs",
            "/openapi.json",
            "/metrics",
            "/health"
        }
        
        for exempt in exempt_routes:
            if path.startswith(exempt):
                return True
        
        return False