"""
Security utilities for CRUD operations
Implements field-level security and access controls
"""
from typing import Dict, List, Set, Any, Optional, Type
from sqlalchemy import inspect
from sqlalchemy.orm import Session
from modules.core.database import Base
from modules.auth.models import User
from modules.admin.audit_logs import SecureAuditService
import logging

logger = logging.getLogger(__name__)


class FieldSecurity:
    """Define field-level security policies for CRUD operations"""
    
    # Fields that should never be set via API
    PROTECTED_FIELDS = {
        'id', 'created_at', 'updated_at', 'created_by',
        'is_superuser', 'is_system_role', 'is_verified',
        'failed_login_attempts', 'locked_until', 'password_changed_at',
        'password_hash', 'totp_secret', 'mfa_secret'
    }
    
    # Fields that can only be set on creation
    CREATE_ONLY_FIELDS = {
        'tenant_id', 'username'
    }
    
    # Fields that require admin permissions
    ADMIN_ONLY_FIELDS = {
        'is_active', 'is_encrypted', 'modified_by', 'permissions',
        'role_id', 'granted_by', 'enabled_by'
    }
    
    # Fields that are system-controlled
    SYSTEM_FIELDS = {
        'created_at', 'updated_at', 'created_by', 'modified_by',
        'tenant_id', 'last_used', 'processed_at'
    }

    @classmethod
    def get_model_protected_fields(cls, model: Type[Base]) -> Set[str]:
        """Get protected fields specific to a model"""
        protected = cls.PROTECTED_FIELDS.copy()
        
        # Add model-specific protected fields
        model_name = model.__name__.lower()
        
        if model_name == 'user':
            protected.update({
                'email_verified_at', 'phone_verified_at', 'last_login_at',
                'password_reset_token', 'email_verification_token'
            })
        elif model_name == 'apikey':
            protected.update({
                'key_hash', 'prefix'
            })
        elif model_name == 'systemsetting':
            protected.update({
                'value'  # If encrypted, should only be set through special methods
            })
        
        return protected

    @classmethod
    def filter_fields(cls, data: dict, operation: str, user: User, model: Type[Base]) -> dict:
        """Filter fields based on security policy"""
        filtered = {}
        protected_fields = cls.get_model_protected_fields(model)
        
        # Check if user has admin permissions
        has_admin_perms = cls._has_admin_permissions(user)
        
        for field, value in data.items():
            # Skip protected fields
            if field in protected_fields:
                logger.warning(f"Attempted to set protected field '{field}' by user {user.id}")
                continue
                
            # Check create-only fields
            if operation == 'update' and field in cls.CREATE_ONLY_FIELDS:
                logger.warning(f"Attempted to update create-only field '{field}' by user {user.id}")
                continue
                
            # Check admin fields
            if field in cls.ADMIN_ONLY_FIELDS and not has_admin_perms:
                logger.warning(f"Attempted to set admin-only field '{field}' by non-admin user {user.id}")
                continue
                
            # Skip system fields (should be set by system only)
            if field in cls.SYSTEM_FIELDS:
                continue
                
            filtered[field] = value
            
        return filtered

    @classmethod
    def _has_admin_permissions(cls, user: User) -> bool:
        """Check if user has admin permissions"""
        # Simple check - in production this would be more sophisticated
        return getattr(user, 'is_superuser', False) or getattr(user, 'is_admin', False)

    @classmethod
    async def log_security_violation(cls, violation_type: str, user_id: int, 
                                   details: dict, db: Session):
        """Log security violations for monitoring"""
        await SecureAuditService.log_action(
            action=f"security_violation_{violation_type}",
            user_id=user_id,
            resource_type="crud_security",
            details=details,
            request=None,  # Will be set by caller if available
            db=db
        )


class TenantSecurity:
    """Tenant isolation security for CRUD operations"""

    @staticmethod
    def apply_tenant_filter(query, model: Type[Base], tenant_id: str):
        """Apply tenant filtering to queries"""
        if hasattr(model, 'tenant_id') and tenant_id:
            return query.filter(model.tenant_id == tenant_id)
        return query

    @staticmethod
    def validate_tenant_access(item: Base, expected_tenant_id: str) -> bool:
        """Validate that an item belongs to the expected tenant"""
        if hasattr(item, 'tenant_id'):
            item_tenant = getattr(item, 'tenant_id')
            if item_tenant != expected_tenant_id:
                logger.error(f"Tenant violation: Expected {expected_tenant_id}, got {item_tenant}")
                return False
        return True

    @staticmethod
    def get_tenant_from_user(user: User) -> str:
        """Extract tenant ID from user (from JWT claims)"""
        return getattr(user, 'tenant_id', None)

    @staticmethod
    async def log_tenant_violation(user_id: int, user_tenant: str, 
                                 resource_tenant: str, operation: str, 
                                 db: Session):
        """Log tenant isolation violations"""
        await SecureAuditService.log_action(
            action="tenant_isolation_violation",
            user_id=user_id,
            resource_type="tenant_security",
            details={
                "user_tenant": user_tenant,
                "resource_tenant": resource_tenant,
                "operation": operation,
                "severity": "CRITICAL"
            },
            request=None,
            db=db
        )


class CRUDSecurityMonitor:
    """Monitor for suspicious CRUD activity"""
    
    @staticmethod
    async def detect_mass_assignment_attempt(
        model_name: str,
        provided_fields: set,
        filtered_fields: set,
        user_id: int,
        db: Session
    ):
        """Detect attempts to set protected fields"""
        blocked_fields = provided_fields - filtered_fields
        
        if blocked_fields:
            await FieldSecurity.log_security_violation(
                violation_type="mass_assignment_attempt",
                user_id=user_id,
                details={
                    "model": model_name,
                    "attempted_fields": list(blocked_fields),
                    "severity": "HIGH"
                },
                db=db
            )
            
            logger.warning(
                f"Mass assignment attempt on {model_name} by user {user_id}: "
                f"blocked fields {list(blocked_fields)}"
            )

    @staticmethod
    async def detect_tenant_violation(
        user_tenant: str,
        resource_tenant: str,
        operation: str,
        user_id: int,
        db: Session
    ):
        """Detect cross-tenant access attempts"""
        if user_tenant != resource_tenant:
            await TenantSecurity.log_tenant_violation(
                user_id=user_id,
                user_tenant=user_tenant,
                resource_tenant=resource_tenant,
                operation=operation,
                db=db
            )
            
            logger.critical(
                f"TENANT VIOLATION: User {user_id} (tenant {user_tenant}) "
                f"attempted {operation} on resource from tenant {resource_tenant}"
            )
            
            return True
        return False


class SecureCRUDHelper:
    """Helper class for secure CRUD operations"""

    @staticmethod
    def prepare_create_data(data: dict, user: User, model: Type[Base]) -> dict:
        """Prepare data for creation with security filtering"""
        # Filter fields
        filtered_data = FieldSecurity.filter_fields(data, 'create', user, model)
        
        # Add system-controlled fields
        if hasattr(model, 'tenant_id'):
            filtered_data['tenant_id'] = TenantSecurity.get_tenant_from_user(user)
        
        if hasattr(model, 'created_by'):
            filtered_data['created_by'] = user.id
            
        return filtered_data

    @staticmethod
    def prepare_update_data(data: dict, user: User, model: Type[Base]) -> dict:
        """Prepare data for update with security filtering"""
        # Filter fields
        filtered_data = FieldSecurity.filter_fields(data, 'update', user, model)
        
        # Add system-controlled fields
        if hasattr(model, 'modified_by'):
            filtered_data['modified_by'] = user.id
            
        return filtered_data

    @staticmethod
    def secure_query(query, model: Type[Base], user: User):
        """Apply security filters to a query"""
        tenant_id = TenantSecurity.get_tenant_from_user(user)
        return TenantSecurity.apply_tenant_filter(query, model, tenant_id)

    @staticmethod
    async def validate_access(item: Base, user: User, operation: str, db: Session) -> bool:
        """Validate that user can access this item"""
        user_tenant = TenantSecurity.get_tenant_from_user(user)
        
        if not TenantSecurity.validate_tenant_access(item, user_tenant):
            await CRUDSecurityMonitor.detect_tenant_violation(
                user_tenant=user_tenant,
                resource_tenant=getattr(item, 'tenant_id', 'unknown'),
                operation=operation,
                user_id=user.id,
                db=db
            )
            return False
            
        return True