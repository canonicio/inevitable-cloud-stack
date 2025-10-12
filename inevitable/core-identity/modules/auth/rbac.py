"""
Role-Based Access Control (RBAC) system for Platform Forge
Fixes HIGH-001: Missing Admin Role Checks
"""
from enum import Enum
from typing import List, Optional, Set
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy import Column, Integer, String, ForeignKey, Table, Boolean, DateTime, Index
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func
import logging

from ..core.database import Base, get_db, TimestampMixin, TenantMixin
from .dependencies import get_current_user
from .models import User, user_roles, Role, Permission as PermissionModel

logger = logging.getLogger(__name__)

# Role definitions
class SystemRole(str, Enum):
    """System-wide role definitions"""
    SUPER_ADMIN = "super_admin"      # Full system access
    TENANT_ADMIN = "tenant_admin"    # Full tenant access
    USER = "user"                    # Standard user access
    READONLY = "readonly"            # Read-only access
    SERVICE_ACCOUNT = "service"      # API/Service access

# Permission definitions
class Permission(str, Enum):
    """Granular permission definitions"""
    # User management
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    USERS_DELETE = "users:delete"
    USERS_STATUS = "users:status"
    
    # Audit logs
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    
    # Billing
    BILLING_READ = "billing:read"
    BILLING_WRITE = "billing:write"
    BILLING_CANCEL = "billing:cancel"
    
    # Admin functions
    ADMIN_PANEL = "admin:panel"
    ADMIN_SETTINGS = "admin:settings"
    ADMIN_TENANT = "admin:tenant"
    
    # MFA management
    MFA_MANAGE = "mfa:manage"
    MFA_RESET = "mfa:reset"

# Import association table from models to avoid duplication

# Models are imported from .models to avoid duplication

class RoleChecker:
    """
    Dependency for checking user roles.
    Usage: current_user = Depends(require_role([SystemRole.ADMIN]))
    """
    
    def __init__(self, allowed_roles: List[SystemRole], allow_superuser: bool = True):
        self.allowed_roles = allowed_roles
        self.allow_superuser = allow_superuser
    
    async def __call__(
        self,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        # Get user's roles
        user_role_names = [role.name for role in current_user.roles]
        
        # Log access attempt
        logger.info(
            f"Role check - User: {current_user.id}, Roles: {user_role_names}, "
            f"Required: {self.allowed_roles}, Path: {request.url.path}"
        )
        
        # Super admin bypasses all checks if allowed
        if self.allow_superuser and SystemRole.SUPER_ADMIN in user_role_names:
            return current_user
        
        # Check if user has any of the allowed roles
        if not any(role.value in user_role_names for role in self.allowed_roles):
            logger.warning(
                f"Access denied - User: {current_user.id}, Roles: {user_role_names}, "
                f"Required: {self.allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges"
            )
        
        # For tenant admins, ensure they're accessing their own tenant
        if SystemRole.TENANT_ADMIN in user_role_names and SystemRole.SUPER_ADMIN not in user_role_names:
            request_tenant = getattr(request.state, 'tenant_id', None)
            if request_tenant and request_tenant != current_user.tenant_id:
                logger.error(
                    f"Tenant admin cross-tenant access attempt - "
                    f"User tenant: {current_user.tenant_id}, Request tenant: {request_tenant}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot access other tenant's resources"
                )
        
        return current_user

class PermissionChecker:
    """
    Dependency for checking granular permissions.
    Usage: current_user = Depends(require_permissions(["users:read", "users:write"]))
    """
    
    def __init__(self, required_permissions: List[str], require_all: bool = True):
        self.required_permissions = required_permissions
        self.require_all = require_all
    
    async def __call__(
        self,
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        # Collect all user permissions
        user_permissions = set()
        
        for role in current_user.roles:
            for permission in role.permissions:
                user_permissions.add(permission.name)
        
        # Log permission check
        logger.info(
            f"Permission check - User: {current_user.id}, "
            f"Has: {user_permissions}, Required: {self.required_permissions}"
        )
        
        # Check permissions
        if self.require_all:
            # All permissions required
            missing = set(self.required_permissions) - user_permissions
            if missing:
                logger.warning(
                    f"Missing permissions - User: {current_user.id}, Missing: {missing}"
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permissions: {', '.join(missing)}"
                )
        else:
            # Any permission sufficient
            if not any(perm in user_permissions for perm in self.required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
        
        return current_user

# Convenience functions
def require_role(roles: List[SystemRole], allow_superuser: bool = True):
    """Convenience function for role checking"""
    return RoleChecker(roles, allow_superuser)

def require_permissions(permissions: List[str], require_all: bool = True):
    """Convenience function for permission checking"""
    return PermissionChecker(permissions, require_all)

def require_admin():
    """Convenience function for admin access"""
    return require_role([SystemRole.SUPER_ADMIN, SystemRole.TENANT_ADMIN])

def require_super_admin():
    """Convenience function for super admin access"""
    return require_role([SystemRole.SUPER_ADMIN], allow_superuser=False)

# RBAC service functions
class RBACService:
    """Service for managing roles and permissions"""
    
    @staticmethod
    async def assign_role(
        db: Session,
        user_id: int,
        role_name: str,
        assigned_by_id: int,
        tenant_id: Optional[str] = None
    ):
        """Assign a role to a user"""
        # Get user and role
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        # For tenant-specific roles, ensure same tenant
        role_query = db.query(Role).filter(Role.name == role_name)
        if tenant_id:
            role_query = role_query.filter(Role.tenant_id == tenant_id)
        else:
            role_query = role_query.filter(Role.is_system == True)
        
        role = role_query.first()
        if not role:
            raise ValueError(f"Role {role_name} not found")
        
        # Check if already assigned
        if role in user.roles:
            return
        
        # Assign role
        user.roles.append(role)
        db.commit()
        
        logger.info(
            f"Role assigned - User: {user_id}, Role: {role_name}, "
            f"AssignedBy: {assigned_by_id}"
        )
    
    @staticmethod
    async def revoke_role(
        db: Session,
        user_id: int,
        role_name: str,
        revoked_by_id: int
    ):
        """Revoke a role from a user"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        # Find and remove role
        for role in user.roles:
            if role.name == role_name:
                user.roles.remove(role)
                db.commit()
                
                logger.info(
                    f"Role revoked - User: {user_id}, Role: {role_name}, "
                    f"RevokedBy: {revoked_by_id}"
                )
                return
        
        raise ValueError(f"User does not have role {role_name}")
    
    @staticmethod
    async def get_user_permissions(db: Session, user_id: int) -> Set[str]:
        """Get all permissions for a user"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return set()
        
        permissions = set()
        for role in user.roles:
            for permission in role.permissions:
                permissions.add(permission.name)
        
        return permissions
    
    @staticmethod
    async def check_permission(
        db: Session,
        user_id: int,
        permission: str
    ) -> bool:
        """Check if user has a specific permission"""
        user_permissions = await RBACService.get_user_permissions(db, user_id)
        return permission in user_permissions

# Initialize default roles and permissions
async def init_rbac(db: Session):
    """Initialize default roles and permissions"""
    # Create permissions
    for perm in Permission:
        if not db.query(PermissionModel).filter(PermissionModel.name == perm.value).first():
            parts = perm.value.split(':')
            permission = PermissionModel(
                name=perm.value,
                resource=parts[0],
                action=parts[1],
                description=f"{parts[1].title()} access to {parts[0]}"
            )
            db.add(permission)
    
    db.commit()
    
    # Create system roles
    system_roles = {
        SystemRole.SUPER_ADMIN: ["*:*"],  # All permissions
        SystemRole.TENANT_ADMIN: [
            Permission.USERS_READ, Permission.USERS_WRITE, Permission.USERS_STATUS,
            Permission.AUDIT_READ, Permission.BILLING_READ, Permission.ADMIN_PANEL,
            Permission.MFA_MANAGE
        ],
        SystemRole.USER: [Permission.USERS_READ],
        SystemRole.READONLY: [Permission.USERS_READ, Permission.AUDIT_READ],
    }
    
    for role_name, perms in system_roles.items():
        if not db.query(Role).filter(Role.name == role_name.value, Role.is_system == True).first():
            role = Role(
                name=role_name.value,
                description=f"System role: {role_name.value}",
                is_system=True,
                tenant_id=None  # System roles are not tenant-specific
            )
            db.add(role)
            db.commit()
            
            # Assign permissions
            if perms[0] == "*:*":
                # Super admin gets all permissions
                all_perms = db.query(PermissionModel).all()
                role.permissions.extend(all_perms)
            else:
                # Assign specific permissions
                for perm in perms:
                    permission = db.query(PermissionModel).filter(
                        PermissionModel.name == perm.value
                    ).first()
                    if permission:
                        role.permissions.append(permission)
            
            db.commit()
    
    logger.info("RBAC system initialized")