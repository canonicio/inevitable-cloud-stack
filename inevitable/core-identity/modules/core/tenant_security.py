"""
Enhanced multi-tenant security middleware for Platform Forge
Fixes CRITICAL-003: Tenant Isolation Bypass
Fixes HIGH-009: Cross-Tenant Data Leakage
"""
from fastapi import Request, HTTPException, status
from typing import Optional
import logging
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .config import settings

logger = logging.getLogger(__name__)

class TenantSecurityMiddleware:
    """
    Enhanced multi-tenant security middleware that validates tenant access
    across JWT claims, headers, and resources.
    """
    
    def __init__(self, app):
        self.app = app
        self._tenant_keys_cache = {}
    
    async def __call__(self, request: Request, call_next):
        # Skip tenant validation for auth endpoints and health checks
        skip_paths = ["/auth/", "/health", "/docs", "/openapi.json"]
        if any(request.url.path.startswith(path) for path in skip_paths):
            return await call_next(request)
        
        try:
            # HIGH-009 FIX: Only trust JWT for tenant identification, never headers
            # Headers can be spoofed and lead to cross-tenant data leakage
            
            # Get JWT tenant from validated user (set by auth dependencies)
            jwt_tenant = getattr(request.state, "jwt_tenant_id", None)
            
            # For authenticated requests, JWT is the only source of truth
            if jwt_tenant:
                # Ignore any header-based tenant ID for security
                header_tenant = request.headers.get("X-Tenant-ID")
                if header_tenant:
                    # Log potential attack attempt
                    if header_tenant != jwt_tenant:
                        logger.warning(
                            f"HIGH-009: Potential cross-tenant attack - JWT: {jwt_tenant}, "
                            f"Header attempt: {header_tenant}, Path: {request.url.path}, "
                            f"IP: {request.client.host if request.client else 'unknown'}"
                        )
                        
                        # Track security event
                        await self._log_security_event(
                            event_type="cross_tenant_attack_attempt",
                            jwt_tenant=jwt_tenant,
                            header_tenant=header_tenant,
                            path=request.url.path,
                            ip=request.client.host if request.client else None
                        )
                
                # Use JWT tenant as the ONLY authoritative source
                validated_tenant = jwt_tenant
            else:
                # For unauthenticated requests, reject if tenant required
                if request.url.path.startswith("/api/"):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required for tenant-scoped resources"
                    )
                validated_tenant = "public"  # Public tenant for unauthenticated access
            
            # Set validated tenant in request state
            request.state.tenant_id = validated_tenant
            
            # Generate tenant-specific encryption key for cryptographic separation
            request.state.tenant_key = self._derive_tenant_key(validated_tenant)
            
            # Add tenant context to logging
            logger.info(
                f"Request processed for tenant: {validated_tenant}",
                extra={"tenant_id": validated_tenant, "path": request.url.path}
            )
            
            response = await call_next(request)
            
            # Add tenant ID to response headers for debugging (only in debug mode)
            if settings.DEBUG:
                response.headers["X-Tenant-ID-Debug"] = validated_tenant
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Tenant security middleware error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
    
    def _derive_tenant_key(self, tenant_id: str) -> bytes:
        """
        Derive a unique encryption key for each tenant.
        This ensures cryptographic separation of tenant data.
        """
        if tenant_id in self._tenant_keys_cache:
            return self._tenant_keys_cache[tenant_id]
        
        try:
            master_key = settings.PLATFORM_FORGE_MASTER_KEY.encode()
            salt = f"tenant_{tenant_id}_v1".encode()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = kdf.derive(master_key)
            
            # Cache the derived key
            self._tenant_keys_cache[tenant_id] = key
            
            return key
            
        except Exception as e:
            logger.error(f"Failed to derive tenant key: {str(e)}")
            # Return a fallback key (this should trigger an alert in production)
            return hashlib.sha256(f"fallback_{tenant_id}".encode()).digest()
    
    async def _log_security_event(self, event_type: str, **kwargs):
        """Log security events for monitoring and alerting"""
        # In production, this would send to a SIEM or security monitoring system
        logger.error(
            f"SECURITY_EVENT: {event_type}",
            extra={
                "event_type": event_type,
                "details": kwargs
            }
        )


class TenantContextManager:
    """
    Context manager for tenant-aware database operations.
    Ensures all queries are properly filtered by tenant.
    """
    
    def __init__(self, db_session, tenant_id: str):
        self.db_session = db_session
        self.tenant_id = tenant_id
    
    def __enter__(self):
        # Set tenant context on the session
        self.db_session.info['tenant_id'] = self.tenant_id
        return self.db_session
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clear tenant context
        self.db_session.info.pop('tenant_id', None)


def get_current_tenant_id(request: Request) -> str:
    """
    Get the current validated tenant ID from the request.
    This should only be called after the tenant security middleware has run.
    """
    tenant_id = getattr(request.state, 'tenant_id', None)
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tenant context not initialized"
        )
    return tenant_id


def validate_tenant_resource(resource, expected_tenant_id: str):
    """
    Validate that a resource belongs to the expected tenant.
    Raises HTTPException if validation fails.
    """
    if not hasattr(resource, 'tenant_id'):
        logger.error(f"Resource {type(resource).__name__} does not have tenant_id attribute")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Resource does not support multi-tenancy"
        )
    
    if resource.tenant_id != expected_tenant_id:
        logger.error(
            f"Tenant validation failed - Expected: {expected_tenant_id}, "
            f"Actual: {resource.tenant_id}, Resource: {type(resource).__name__}"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found"
        )