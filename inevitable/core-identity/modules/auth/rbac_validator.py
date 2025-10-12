"""
RBAC Validator Module
Addresses RISK-H001: RBAC Privilege Escalation
"""
from typing import Set, List, Dict, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException
import networkx as nx
import logging

from .models import User, Role, Permission
from ..core.audit_logger import create_audit_log

logger = logging.getLogger(__name__)


class RBACValidator:
    """Comprehensive RBAC validation with circular dependency detection"""
    
    def __init__(self, db: Session):
        self.db = db
        self._role_cache = {}
        self._permission_cache = {}
    
    def validate_role_creation(
        self, 
        role_data: Dict, 
        requesting_user: User
    ) -> None:
        """Validate role creation with full permission checks"""
        # Build permission graph
        all_permissions = self._collect_all_permissions(role_data)
        
        # Validate requesting user can grant all permissions
        for permission in all_permissions:
            if not self._user_can_grant(requesting_user, permission):
                logger.warning(
                    f"User {requesting_user.id} attempted to grant unauthorized permission: {permission}",
                    extra={
                        "user_id": requesting_user.id,
                        "permission": permission,
                        "action": "rbac_escalation_blocked"
                    }
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Cannot grant permission: {permission}"
                )
        
        # Check for circular dependencies
        if self._creates_circular_dependency(role_data):
            logger.warning(
                f"User {requesting_user.id} attempted to create circular role dependency",
                extra={
                    "user_id": requesting_user.id,
                    "role_data": role_data,
                    "action": "circular_dependency_blocked"
                }
            )
            raise HTTPException(
                status_code=400,
                detail="Role hierarchy would create circular dependency"
            )
    
    def validate_role_update(
        self,
        role_id: str,
        update_data: Dict,
        requesting_user: User
    ) -> None:
        """Validate role updates with permission checks"""
        existing_role = self.db.query(Role).filter(Role.id == role_id).first()
        if not existing_role:
            raise HTTPException(status_code=404, detail="Role not found")
        
        # Merge existing data with updates
        merged_data = {
            "id": role_id,
            "permissions": update_data.get("permissions", existing_role.permissions),
            "inherits_from": update_data.get("inherits_from", existing_role.inherits_from or [])
        }
        
        # Validate using standard creation logic
        self.validate_role_creation(merged_data, requesting_user)
    
    def validate_role_assignment(
        self,
        user_id: str,
        role_ids: List[str],
        requesting_user: User
    ) -> None:
        """Validate role assignment to user"""
        # Get all permissions from assigned roles
        all_permissions = set()
        
        for role_id in role_ids:
            role = self.db.query(Role).filter(Role.id == role_id).first()
            if not role:
                raise HTTPException(status_code=404, detail=f"Role {role_id} not found")
            
            role_permissions = self._collect_all_permissions({
                "id": role_id,
                "permissions": role.permissions,
                "inherits_from": role.inherits_from or []
            })
            all_permissions.update(role_permissions)
        
        # Validate requesting user can assign all permissions
        for permission in all_permissions:
            if not self._user_can_grant(requesting_user, permission):
                raise HTTPException(
                    status_code=403,
                    detail=f"Cannot assign role with permission: {permission}"
                )
    
    def _collect_all_permissions(self, role_data: Dict) -> Set[str]:
        """Recursively collect all permissions including inherited"""
        permissions = set(role_data.get('permissions', []))
        visited = set()
        
        def traverse_parents(role_id: str):
            if role_id in visited:
                return
            visited.add(role_id)
            
            parent_role = self.db.query(Role).filter(
                Role.id == role_id
            ).first()
            
            if parent_role:
                permissions.update(parent_role.permissions or [])
                for parent_id in (parent_role.inherits_from or []):
                    traverse_parents(parent_id)
        
        for parent_id in role_data.get('inherits_from', []):
            traverse_parents(parent_id)
        
        return permissions
    
    def _user_can_grant(self, user: User, permission: str) -> bool:
        """Check if user has permission to grant specific permission"""
        # System admins can grant any permission
        if self._is_system_admin(user):
            return True
        
        # User must have the permission to grant it
        user_permissions = self._get_user_permissions(user)
        
        # Direct permission match
        if permission in user_permissions:
            return True
        
        # Wildcard permission handling
        if self._has_wildcard_permission(user_permissions, permission):
            return True
        
        return False
    
    def _is_system_admin(self, user: User) -> bool:
        """Check if user is a system administrator"""
        user_permissions = self._get_user_permissions(user)
        return "system:admin" in user_permissions or "*:*" in user_permissions
    
    def _get_user_permissions(self, user: User) -> Set[str]:
        """Get all permissions for a user (including role inheritance)"""
        if user.id in self._permission_cache:
            return self._permission_cache[user.id]
        
        permissions = set()
        
        # Get permissions from all user roles
        for role in user.roles:
            role_permissions = self._collect_all_permissions({
                "id": role.id,
                "permissions": role.permissions or [],
                "inherits_from": role.inherits_from or []
            })
            permissions.update(role_permissions)
        
        self._permission_cache[user.id] = permissions
        return permissions
    
    def _has_wildcard_permission(self, user_permissions: Set[str], required_permission: str) -> bool:
        """Check if user has wildcard permissions that cover the required permission"""
        # Parse required permission (e.g., "users:create")
        if ":" not in required_permission:
            return False
        
        resource, action = required_permission.split(":", 1)
        
        # Check for specific wildcards
        wildcard_patterns = [
            "*:*",  # Full admin
            f"{resource}:*",  # Resource admin
        ]
        
        for pattern in wildcard_patterns:
            if pattern in user_permissions:
                return True
        
        return False
    
    def _creates_circular_dependency(self, role_data: Dict) -> bool:
        """Detect circular dependencies using graph theory"""
        # Build role hierarchy graph
        graph = nx.DiGraph()
        
        # Add existing roles
        roles = self.db.query(Role).all()
        for role in roles:
            for parent_id in (role.inherits_from or []):
                graph.add_edge(role.id, parent_id)
        
        # Add new role edges
        new_role_id = role_data.get('id', 'new_role')
        for parent_id in role_data.get('inherits_from', []):
            graph.add_edge(new_role_id, parent_id)
        
        # Check for cycles
        try:
            cycles = list(nx.simple_cycles(graph))
            if cycles:
                logger.warning(
                    f"Circular dependency detected: {cycles}",
                    extra={"cycles": cycles}
                )
                return True
            return False
        except nx.NetworkXError:
            # If there's an error in cycle detection, be safe and reject
            logger.error("Error in circular dependency detection")
            return True
    
    def get_effective_permissions(self, user: User) -> Dict[str, List[str]]:
        """Get effective permissions for user with source tracking"""
        permissions_by_source = {}
        
        for role in user.roles:
            role_permissions = self._collect_all_permissions({
                "id": role.id,
                "permissions": role.permissions or [],
                "inherits_from": role.inherits_from or []
            })
            
            permissions_by_source[role.name] = list(role_permissions)
        
        return permissions_by_source
    
    def audit_permission_change(
        self,
        user: User,
        action: str,
        target_resource: str,
        details: Dict
    ) -> None:
        """Create audit log for permission changes"""
        create_audit_log(
            self.db,
            user_id=user.id,
            action=f"rbac.{action}",
            resource=target_resource,
            details={
                **details,
                "validator_used": "RBACValidator",
                "security_level": "high"
            }
        )


def validate_permission_format(permission: str) -> bool:
    """Validate permission string format"""
    if not permission or not isinstance(permission, str):
        return False
    
    # Allow wildcards
    if permission in ["*:*"]:
        return True
    
    # Standard format: resource:action
    if ":" not in permission:
        return False
    
    resource, action = permission.split(":", 1)
    
    # Basic validation
    if not resource or not action:
        return False
    
    # Resource wildcard
    if resource == "*" and action == "*":
        return True
    
    if resource == "*":
        return False  # Resource wildcard requires action wildcard
    
    return True


def expand_wildcard_permissions(permissions: List[str]) -> Set[str]:
    """Expand wildcard permissions to concrete permissions"""
    expanded = set()
    
    # Define all possible permissions (this would come from a central registry)
    ALL_PERMISSIONS = [
        "users:create", "users:read", "users:update", "users:delete",
        "roles:create", "roles:read", "roles:update", "roles:delete",
        "billing:create", "billing:read", "billing:update", "billing:delete",
        "admin:read", "admin:write", "admin:delete",
        "system:admin", "system:config"
    ]
    
    for permission in permissions:
        if permission == "*:*":
            expanded.update(ALL_PERMISSIONS)
        elif permission.endswith(":*"):
            resource = permission.split(":")[0]
            expanded.update([
                p for p in ALL_PERMISSIONS 
                if p.startswith(f"{resource}:")
            ])
        else:
            expanded.add(permission)
    
    return expanded