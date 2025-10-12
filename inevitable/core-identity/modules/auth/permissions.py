"""
Permission system for RBAC
"""
from typing import List, Dict, Optional, Set
from enum import Enum
from functools import wraps
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import and_

from .models import User, Role, Permission
from .dependencies import get_current_user, require_tenant
from ..core.database import get_db


class Resource(str, Enum):
    """Available resources in the system"""
    USERS = "users"
    BILLING = "billing"
    ADMIN = "admin"
    ANALYTICS = "analytics"
    SETTINGS = "settings"
    REPORTS = "reports"
    API_KEYS = "api_keys"
    WEBHOOKS = "webhooks"
    TENANTS = "tenants"
    ROLES = "roles"
    AUDIT_LOGS = "audit_logs"


class Action(str, Enum):
    """Available actions on resources"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    EXECUTE = "execute"
    EXPORT = "export"
    IMPORT = "import"


class PermissionService:
    """Service for managing permissions"""
    
    def __init__(self):
        self._permission_cache = {}
    
    def format_permission(self, resource: str, action: str) -> str:
        """Format permission string"""
        return f"{resource}:{action}"
    
    def parse_permission(self, permission: str) -> tuple:
        """Parse permission string into resource and action"""
        parts = permission.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid permission format: {permission}")
        return parts[0], parts[1]
    
    def user_has_permission(
        self,
        db: Session,
        user: User,
        resource: str,
        action: str,
        tenant_id: str
    ) -> bool:
        """Check if user has specific permission"""
        # Superusers have all permissions
        if user.is_superuser:
            return True
        
        # Check cache first
        cache_key = f"{user.id}:{tenant_id}:{resource}:{action}"
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]
        
        # Get user's roles
        user_roles = db.query(Role).join(
            User.roles
        ).filter(
            and_(
                User.id == user.id,
                Role.tenant_id == tenant_id
            )
        ).all()
        
        # Check permissions for each role
        permission_name = self.format_permission(resource, action)
        
        for role in user_roles:
            permission = db.query(Permission).filter(
                and_(
                    Permission.role_id == role.id,
                    Permission.name == permission_name
                )
            ).first()
            
            if permission:
                self._permission_cache[cache_key] = True
                return True
        
        # Check wildcard permissions
        for role in user_roles:
            # Check resource wildcard (e.g., "users:*")
            wildcard_permission = db.query(Permission).filter(
                and_(
                    Permission.role_id == role.id,
                    Permission.name == f"{resource}:*"
                )
            ).first()
            
            if wildcard_permission:
                self._permission_cache[cache_key] = True
                return True
            
            # Check global wildcard (e.g., "*:*")
            global_permission = db.query(Permission).filter(
                and_(
                    Permission.role_id == role.id,
                    Permission.name == "*:*"
                )
            ).first()
            
            if global_permission:
                self._permission_cache[cache_key] = True
                return True
        
        self._permission_cache[cache_key] = False
        return False
    
    def get_user_permissions(
        self,
        db: Session,
        user: User,
        tenant_id: str
    ) -> Set[str]:
        """Get all permissions for a user"""
        if user.is_superuser:
            # Return all possible permissions
            all_permissions = set()
            for resource in Resource:
                for action in Action:
                    all_permissions.add(self.format_permission(resource.value, action.value))
            return all_permissions
        
        # Get user's roles
        user_roles = db.query(Role).join(
            User.roles
        ).filter(
            and_(
                User.id == user.id,
                Role.tenant_id == tenant_id
            )
        ).all()
        
        # Collect all permissions
        permissions = set()
        for role in user_roles:
            role_permissions = db.query(Permission).filter(
                Permission.role_id == role.id
            ).all()
            
            for perm in role_permissions:
                if perm.name == "*:*":
                    # Global wildcard - add all permissions
                    for resource in Resource:
                        for action in Action:
                            permissions.add(self.format_permission(resource.value, action.value))
                elif perm.name.endswith(":*"):
                    # Resource wildcard - add all actions for resource
                    resource = perm.name.split(":")[0]
                    for action in Action:
                        permissions.add(self.format_permission(resource, action.value))
                else:
                    permissions.add(perm.name)
        
        return permissions
    
    def clear_cache(self, user_id: Optional[int] = None):
        """Clear permission cache"""
        if user_id:
            # Clear cache for specific user
            keys_to_remove = [k for k in self._permission_cache.keys() if k.startswith(f"{user_id}:")]
            for key in keys_to_remove:
                del self._permission_cache[key]
        else:
            # Clear entire cache
            self._permission_cache.clear()


# Singleton instance
permission_service = PermissionService()


def require_permission(resource: str, action: str):
    """Decorator to require specific permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get dependencies from kwargs
            db = kwargs.get('db')
            current_user = kwargs.get('current_user')
            tenant_id = kwargs.get('tenant_id')
            
            if not all([db, current_user, tenant_id]):
                raise HTTPException(500, "Missing required dependencies")
            
            if not permission_service.user_has_permission(
                db, current_user, resource, action, tenant_id
            ):
                raise HTTPException(
                    403,
                    f"Permission denied: {resource}:{action}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(permissions: List[tuple]):
    """Decorator to require any of the specified permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get dependencies from kwargs
            db = kwargs.get('db')
            current_user = kwargs.get('current_user')
            tenant_id = kwargs.get('tenant_id')
            
            if not all([db, current_user, tenant_id]):
                raise HTTPException(500, "Missing required dependencies")
            
            for resource, action in permissions:
                if permission_service.user_has_permission(
                    db, current_user, resource, action, tenant_id
                ):
                    return await func(*args, **kwargs)
            
            permission_strings = [f"{r}:{a}" for r, a in permissions]
            raise HTTPException(
                403,
                f"Permission denied: requires any of {permission_strings}"
            )
        return wrapper
    return decorator


def require_all_permissions(permissions: List[tuple]):
    """Decorator to require all of the specified permissions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get dependencies from kwargs
            db = kwargs.get('db')
            current_user = kwargs.get('current_user')
            tenant_id = kwargs.get('tenant_id')
            
            if not all([db, current_user, tenant_id]):
                raise HTTPException(500, "Missing required dependencies")
            
            for resource, action in permissions:
                if not permission_service.user_has_permission(
                    db, current_user, resource, action, tenant_id
                ):
                    raise HTTPException(
                        403,
                        f"Permission denied: {resource}:{action}"
                    )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Predefined role templates
ROLE_TEMPLATES = {
    "super_admin": {
        "name": "Super Admin",
        "description": "Full system access",
        "permissions": ["*:*"]
    },
    "admin": {
        "name": "Admin",
        "description": "Administrative access",
        "permissions": [
            "users:*",
            "roles:*",
            "settings:*",
            "audit_logs:read",
            "analytics:*",
            "reports:*"
        ]
    },
    "manager": {
        "name": "Manager",
        "description": "Management access",
        "permissions": [
            "users:read",
            "users:list",
            "users:update",
            "analytics:read",
            "reports:read",
            "reports:export",
            "billing:read"
        ]
    },
    "user": {
        "name": "User",
        "description": "Standard user access",
        "permissions": [
            "users:read",  # Own profile
            "users:update",  # Own profile
            "settings:read",
            "settings:update"
        ]
    },
    "viewer": {
        "name": "Viewer",
        "description": "Read-only access",
        "permissions": [
            "users:read",
            "analytics:read",
            "reports:read"
        ]
    },
    "billing_admin": {
        "name": "Billing Admin",
        "description": "Billing management access",
        "permissions": [
            "billing:*",
            "users:read",
            "users:list",
            "reports:read",
            "reports:export"
        ]
    },
    "api_developer": {
        "name": "API Developer",
        "description": "API development access",
        "permissions": [
            "api_keys:*",
            "webhooks:*",
            "users:read",
            "analytics:read"
        ]
    }
}


async def create_default_roles(db: Session, tenant_id: str):
    """Create default roles for a tenant"""
    for role_key, role_data in ROLE_TEMPLATES.items():
        # Check if role exists
        existing_role = db.query(Role).filter(
            and_(
                Role.name == role_data["name"],
                Role.tenant_id == tenant_id
            )
        ).first()
        
        if not existing_role:
            # Create role
            role = Role(
                name=role_data["name"],
                description=role_data["description"],
                tenant_id=tenant_id,
                is_system_role=True
            )
            db.add(role)
            db.flush()
            
            # Create permissions
            for perm_string in role_data["permissions"]:
                if ":" in perm_string:
                    resource, action = perm_string.split(":")
                    permission = Permission(
                        name=perm_string,
                        resource=resource,
                        action=action,
                        role_id=role.id,
                        tenant_id=tenant_id
                    )
                    db.add(permission)
    
    db.commit()