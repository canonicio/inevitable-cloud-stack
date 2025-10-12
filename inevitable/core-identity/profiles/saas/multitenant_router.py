
"""
Secure Multitenant Router
Resolves tenant identity from JWT only - no header manipulation allowed
"""
from fastapi import Request, Depends
from typing import Optional
from modules.core.tenant_isolation import get_current_tenant

def get_tenant_from_request(request: Request) -> Optional[str]:
    """
    Get tenant ID from request state (set by TenantIsolationMiddleware)
    SECURITY: Never trust X-Tenant-ID header - use JWT claims only
    """
    return getattr(request.state, "tenant_id", None)

def with_tenant_context(handler):
    """
    Decorator to inject tenant context into route handlers
    """
    async def wrapper(request: Request, *args, **kwargs):
        # Tenant ID is already set by middleware from JWT
        tenant_id = get_tenant_from_request(request)
        
        # For backward compatibility, also set request.state.tenant
        if tenant_id:
            request.state.tenant = tenant_id
        
        return await handler(request, *args, **kwargs)
    return wrapper

# FastAPI dependency for getting current tenant
CurrentTenant = Depends(get_current_tenant)
