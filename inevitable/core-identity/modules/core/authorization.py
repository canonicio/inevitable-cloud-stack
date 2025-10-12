"""
CRITICAL-009 FIX: Comprehensive authorization system to prevent IDOR
Implements object-level authorization checks for all resources
"""
from typing import Any, Optional, Type
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import inspect

from .database import Base, TenantMixin
from ..auth.models import User


class AuthorizationService:
    """Service for comprehensive authorization checks"""
    
    @staticmethod
    def check_resource_access(
        db: Session,
        model: Type[Base],
        resource_id: Any,
        user: User,
        operation: str = "read",
        tenant_id: Optional[str] = None
    ) -> Any:
        """
        CRITICAL FIX: Validate user has access to specific resource
        Prevents Insecure Direct Object Reference vulnerabilities
        """
        # Get the resource
        resource = db.query(model).filter(model.id == resource_id).first()
        
        if not resource:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resource not found"
            )
        
        # Check if model has tenant isolation
        if hasattr(resource, 'tenant_id'):
            # Verify tenant access
            resource_tenant = getattr(resource, 'tenant_id')
            
            # Admin users can access their tenant's resources
            if hasattr(user, 'tenant_id'):
                user_tenant = getattr(user, 'tenant_id')
                if resource_tenant != user_tenant:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: Resource belongs to different tenant"
                    )
            
            # Additional tenant check if provided
            if tenant_id and resource_tenant != tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Invalid tenant"
                )
        
        # Check if resource has owner
        if hasattr(resource, 'user_id'):
            resource_owner = getattr(resource, 'user_id')
            
            # Check if user is owner or has admin role
            if resource_owner != user.id:
                # Check for admin privileges
                user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') else []
                if 'admin' not in user_roles and 'super_admin' not in user_roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: You don't own this resource"
                    )
        
        # Check if resource has organization
        if hasattr(resource, 'organization_id') and hasattr(user, 'organization_id'):
            if getattr(resource, 'organization_id') != getattr(user, 'organization_id'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Resource belongs to different organization"
                )
        
        # Operation-specific checks
        if operation in ['update', 'delete']:
            # Additional checks for write operations
            if hasattr(resource, 'is_locked') and getattr(resource, 'is_locked'):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: Resource is locked"
                )
            
            if hasattr(resource, 'is_system') and getattr(resource, 'is_system'):
                user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') else []
                if 'super_admin' not in user_roles:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: System resources require super admin privileges"
                    )
        
        return resource
    
    @staticmethod
    def check_bulk_access(
        db: Session,
        model: Type[Base],
        resource_ids: list,
        user: User,
        operation: str = "read"
    ) -> list:
        """Check access to multiple resources at once"""
        authorized_resources = []
        
        for resource_id in resource_ids:
            try:
                resource = AuthorizationService.check_resource_access(
                    db, model, resource_id, user, operation
                )
                authorized_resources.append(resource)
            except HTTPException:
                # Skip resources user doesn't have access to
                continue
        
        if not authorized_resources:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to all requested resources"
            )
        
        return authorized_resources
    
    @staticmethod
    def filter_query_by_access(
        query,
        user: User,
        model: Type[Base]
    ):
        """Filter query to only return resources user has access to"""
        # Filter by tenant if applicable
        if hasattr(model, 'tenant_id') and hasattr(user, 'tenant_id'):
            query = query.filter(model.tenant_id == user.tenant_id)
        
        # Filter by user if applicable (non-admin users)
        if hasattr(model, 'user_id'):
            user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') else []
            if 'admin' not in user_roles and 'super_admin' not in user_roles:
                query = query.filter(model.user_id == user.id)
        
        # Filter by organization if applicable
        if hasattr(model, 'organization_id') and hasattr(user, 'organization_id'):
            query = query.filter(model.organization_id == user.organization_id)
        
        # Exclude system resources for non-super-admins
        if hasattr(model, 'is_system'):
            user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') else []
            if 'super_admin' not in user_roles:
                query = query.filter(model.is_system == False)
        
        return query


# Dependency for FastAPI routes
def authorize_resource(
    model: Type[Base],
    operation: str = "read"
):
    """
    FastAPI dependency for resource authorization
    Usage: resource = Depends(authorize_resource(MyModel, "update"))
    """
    async def _authorize(
        resource_id: int,
        db: Session,
        current_user: User
    ):
        return AuthorizationService.check_resource_access(
            db, model, resource_id, current_user, operation
        )
    
    return _authorize