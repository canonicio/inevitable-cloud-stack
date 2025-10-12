"""
Secure audit logs module
Addresses CRITICAL-002: SQL Injection in Admin Audit Logs
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_, text
from modules.core.database import get_db
from modules.core.security import TenantSecurity, SecurityError
from modules.core.middleware import SQLInjectionPrevention
from modules.auth.models import User
from modules.core.audit_logger import AuditLog
import json
import logging

logger = logging.getLogger(__name__)

class SecureAuditService:
    """Secure service for handling audit logging with SQL injection prevention"""
    
    # Allowed columns for ordering (whitelist)
    ALLOWED_ORDER_COLUMNS = [
        'id', 'created_at', 'updated_at', 'action', 'resource_type', 'user_id'
    ]
    
    # Allowed filter fields (whitelist)
    ALLOWED_FILTER_FIELDS = [
        'action', 'resource_type', 'user_id', 'tenant_id'
    ]
    
    @staticmethod
    async def log_action(
        action: str,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None,
        db: Session = None
    ) -> AuditLog:
        """
        Securely log an audit action with input validation
        
        Args:
            action: Action performed (validated)
            user_id: User performing action
            resource_type: Type of resource affected
            resource_id: ID of resource affected
            details: Additional details (sanitized)
            request: HTTP request object
            db: Database session
            
        Returns:
            Created audit log entry
            
        Raises:
            SecurityError: If inputs are invalid
        """
        if db is None:
            raise ValueError("Database session is required")
        
        try:
            # Validate and sanitize inputs
            action = SecureAuditService._validate_action(action)
            resource_type = SecureAuditService._validate_resource_type(resource_type)
            resource_id = SecureAuditService._validate_resource_id(resource_id)
            
            # Extract safe request information
            ip_address = None
            user_agent = None
            tenant_id = None
            
            if request:
                ip_address = SecureAuditService._extract_safe_ip(request)
                user_agent = SecureAuditService._extract_safe_user_agent(request)
                tenant_id = SecureAuditService._extract_safe_tenant_id(request)
            
            # Sanitize details
            details_json = SecureAuditService._sanitize_details(details)
            
            # Create audit log entry using parameterized query
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details_json,
                tenant_id=tenant_id
            )
            
            db.add(audit_log)
            db.commit()
            db.refresh(audit_log)
            
            logger.info(f"Audit log created: {action} by user {user_id}")
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            if isinstance(e, SecurityError):
                raise
            raise SecurityError(f"Audit logging failed: {e}")
    
    @staticmethod
    def _validate_action(action: str) -> str:
        """Validate and sanitize action string"""
        if not action or not isinstance(action, str):
            raise SecurityError("Action must be a non-empty string")
        
        # Limit length
        if len(action) > 255:
            raise SecurityError("Action string too long")
        
        # Remove potentially dangerous characters
        sanitized = ''.join(c for c in action if c.isalnum() or c in '_-.')
        
        if not sanitized:
            raise SecurityError("Action contains only invalid characters")
        
        return sanitized[:255]  # Ensure length limit
    
    @staticmethod
    def _validate_resource_type(resource_type: Optional[str]) -> Optional[str]:
        """Validate and sanitize resource type"""
        if resource_type is None:
            return None
        
        if not isinstance(resource_type, str):
            raise SecurityError("Resource type must be a string")
        
        if len(resource_type) > 100:
            raise SecurityError("Resource type too long")
        
        # Allow only alphanumeric and underscores
        sanitized = ''.join(c for c in resource_type if c.isalnum() or c == '_')
        
        return sanitized[:100] if sanitized else None
    
    @staticmethod
    def _validate_resource_id(resource_id: Optional[str]) -> Optional[str]:
        """Validate and sanitize resource ID"""
        if resource_id is None:
            return None
        
        if not isinstance(resource_id, str):
            resource_id = str(resource_id)
        
        if len(resource_id) > 255:
            raise SecurityError("Resource ID too long")
        
        # Allow alphanumeric, hyphens, and underscores
        sanitized = ''.join(c for c in resource_id if c.isalnum() or c in '-_')
        
        return sanitized[:255] if sanitized else None
    
    @staticmethod
    def _extract_safe_ip(request: Request) -> Optional[str]:
        """Safely extract IP address from request"""
        try:
            ip = request.client.host if request.client else None
            if ip and len(ip) <= 45:  # IPv6 max length
                return ip
        except:
            pass
        return None
    
    @staticmethod
    def _extract_safe_user_agent(request: Request) -> Optional[str]:
        """Safely extract user agent from request"""
        try:
            user_agent = request.headers.get("user-agent", "")
            # Limit length and remove potentially dangerous characters
            if user_agent:
                safe_user_agent = ''.join(c for c in user_agent if ord(c) < 128)[:500]
                return safe_user_agent if safe_user_agent else None
        except:
            pass
        return None
    
    @staticmethod
    def _extract_safe_tenant_id(request: Request) -> Optional[str]:
        """Safely extract tenant ID from request"""
        try:
            tenant_id = getattr(request.state, 'tenant_id', None)
            if tenant_id and isinstance(tenant_id, str) and len(tenant_id) <= 50:
                return tenant_id
        except:
            pass
        return None
    
    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> Optional[str]:
        """Sanitize details dictionary for safe storage"""
        if details is None:
            return None
        
        try:
            # Recursively sanitize dictionary
            sanitized = SecureAuditService._sanitize_dict(details)
            
            # Convert to JSON string
            json_str = json.dumps(sanitized, default=str)
            
            # Limit size
            if len(json_str) > 10000:  # 10KB limit
                logger.warning("Details too large, truncating")
                json_str = json_str[:10000] + "...[truncated]"
            
            return json_str
            
        except Exception as e:
            logger.warning(f"Failed to serialize details: {e}")
            return json.dumps({"error": "Failed to serialize details"})
    
    @staticmethod
    def _sanitize_dict(obj: Any, max_depth: int = 5, current_depth: int = 0) -> Any:
        """Recursively sanitize dictionary values"""
        if current_depth > max_depth:
            return "[max_depth_exceeded]"
        
        if isinstance(obj, dict):
            return {
                key[:100]: SecureAuditService._sanitize_dict(value, max_depth, current_depth + 1)
                for key, value in obj.items()
                if isinstance(key, (str, int, float))
            }
        elif isinstance(obj, list):
            return [
                SecureAuditService._sanitize_dict(item, max_depth, current_depth + 1)
                for item in obj[:100]  # Limit list size
            ]
        elif isinstance(obj, str):
            # Remove control characters and limit length
            safe_str = ''.join(c for c in obj if ord(c) >= 32 or c in '\n\r\t')
            return safe_str[:1000]  # Limit string length
        elif isinstance(obj, (int, float, bool)):
            return obj
        else:
            return str(obj)[:100]  # Convert to string and limit
    
    @staticmethod
    async def get_audit_logs_secure(
        limit: int = 50,
        offset: int = 0,
        action_filter: Optional[str] = None,
        resource_type_filter: Optional[str] = None,
        user_id_filter: Optional[int] = None,
        order_by: str = "created_at",
        order_direction: str = "desc",
        tenant_id: Optional[str] = None,
        db: Session = None
    ) -> List[AuditLog]:
        """
        Securely retrieve audit logs with SQL injection prevention
        
        Args:
            limit: Maximum number of records
            offset: Number of records to skip
            action_filter: Filter by action (sanitized)
            resource_type_filter: Filter by resource type (sanitized)
            user_id_filter: Filter by user ID
            order_by: Column to order by (whitelisted)
            order_direction: Order direction (asc/desc)
            tenant_id: Tenant ID for multi-tenant filtering
            db: Database session
            
        Returns:
            List of audit log entries
            
        Raises:
            SecurityError: If parameters are invalid
        """
        if db is None:
            raise ValueError("Database session is required")
        
        try:
            # Validate and sanitize parameters
            limit = SecureAuditService._validate_limit(limit)
            offset = SecureAuditService._validate_offset(offset)
            order_by = SecureAuditService._validate_order_by(order_by)
            order_direction = SecureAuditService._validate_order_direction(order_direction)
            
            # Build base query using SQLAlchemy ORM (prevents SQL injection)
            query = db.query(AuditLog)
            
            # Apply tenant filtering if specified
            if tenant_id:
                tenant_id = SecureAuditService._validate_resource_id(tenant_id)
                query = query.filter(AuditLog.tenant_id == tenant_id)
            
            # Apply filters using parameterized queries
            if action_filter:
                action_filter = SQLInjectionPrevention.validate_filter_value(action_filter)
                safe_pattern = SQLInjectionPrevention.build_safe_like_pattern(action_filter)
                query = query.filter(AuditLog.action.ilike(safe_pattern))
            
            if resource_type_filter:
                resource_type_filter = SQLInjectionPrevention.validate_filter_value(resource_type_filter)
                query = query.filter(AuditLog.resource_type == resource_type_filter)
            
            if user_id_filter:
                if not isinstance(user_id_filter, int) or user_id_filter < 0:
                    raise SecurityError("Invalid user ID filter")
                query = query.filter(AuditLog.user_id == user_id_filter)
            
            # Apply ordering
            order_column = getattr(AuditLog, order_by)
            if order_direction == "desc":
                query = query.order_by(desc(order_column))
            else:
                query = query.order_by(order_column)
            
            # Apply pagination
            query = query.offset(offset).limit(limit)
            
            # Execute query
            results = query.all()
            
            logger.info(f"Retrieved {len(results)} audit log entries")
            return results
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}")
            if isinstance(e, SecurityError):
                raise
            raise SecurityError(f"Audit log retrieval failed: {e}")
    
    @staticmethod
    def _validate_limit(limit: int) -> int:
        """Validate limit parameter"""
        if not isinstance(limit, int):
            raise SecurityError("Limit must be an integer")
        
        if limit < 1 or limit > 1000:
            raise SecurityError("Limit must be between 1 and 1000")
        
        return limit
    
    @staticmethod
    def _validate_offset(offset: int) -> int:
        """Validate offset parameter"""
        if not isinstance(offset, int):
            raise SecurityError("Offset must be an integer")
        
        if offset < 0:
            raise SecurityError("Offset must be non-negative")
        
        return offset
    
    @staticmethod
    def _validate_order_by(order_by: str) -> str:
        """Validate order_by parameter against whitelist"""
        if not isinstance(order_by, str):
            raise SecurityError("Order by must be a string")
        
        if order_by not in SecureAuditService.ALLOWED_ORDER_COLUMNS:
            raise SecurityError(f"Invalid order column: {order_by}")
        
        return order_by
    
    @staticmethod
    def _validate_order_direction(order_direction: str) -> str:
        """Validate order direction parameter"""
        if not isinstance(order_direction, str):
            raise SecurityError("Order direction must be a string")
        
        order_direction = order_direction.lower()
        if order_direction not in ['asc', 'desc']:
            raise SecurityError("Order direction must be 'asc' or 'desc'")
        
        return order_direction

# Convenience functions for common audit actions (using secure service)
async def log_user_login_secure(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Securely log user login event"""
    return await SecureAuditService.log_action(
        action="user_login",
        user_id=user_id,
        resource_type="user",
        resource_id=str(user_id),
        request=request,
        db=db
    )

async def log_user_logout_secure(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Securely log user logout event"""
    return await SecureAuditService.log_action(
        action="user_logout",
        user_id=user_id,
        resource_type="user",
        resource_id=str(user_id),
        request=request,
        db=db
    )

async def log_mfa_enabled_secure(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db)
):
    """Securely log MFA enabled event"""
    return await SecureAuditService.log_action(
        action="mfa_enabled",
        user_id=user_id,
        resource_type="user",
        resource_id=str(user_id),
        request=request,
        db=db
    )

async def log_security_event(
    event_type: str,
    user_id: Optional[int],
    details: Dict[str, Any],
    request: Request,
    db: Session = Depends(get_db)
):
    """Log security-related events"""
    return await SecureAuditService.log_action(
        action=f"security_{event_type}",
        user_id=user_id,
        resource_type="security",
        details=details,
        request=request,
        db=db
    )