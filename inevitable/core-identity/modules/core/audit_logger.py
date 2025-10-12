"""
Audit Logger Module
Provides comprehensive audit logging with tamper-proof mechanisms
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
import logging

from sqlalchemy import Column, String, Text, DateTime, Integer, Index
from sqlalchemy.orm import Session

from .database import Base, TimestampMixin, TenantMixin

logger = logging.getLogger(__name__)


class AuditAction(Enum):
    """Audit action types"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_REVOKE = "permission_revoke"
    ROLE_CREATE = "role_create"
    ROLE_UPDATE = "role_update"
    ROLE_DELETE = "role_delete"
    ROLE_ASSIGN = "role_assign"
    ROLE_UNASSIGN = "role_unassign"
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    MFA_VERIFY = "mfa_verify"
    PASSWORD_RESET = "password_reset"
    PASSWORD_CHANGE = "password_change"
    SESSION_CREATE = "session_create"
    SESSION_DESTROY = "session_destroy"
    SECURITY_ALERT = "security_alert"
    ACCESS_DENIED = "access_denied"
    CONFIGURATION_CHANGE = "configuration_change"


class AuditLog(Base, TimestampMixin, TenantMixin):
    """Audit log model with tamper-proof mechanisms"""
    
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    action = Column(String(50), nullable=False)
    user_id = Column(String(36))
    user_email = Column(String(255))
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_id = Column(String(36))
    session_id = Column(String(255))
    status = Column(String(20), default="success")
    error_message = Column(Text)
    
    # Tamper-proof hash of the log entry
    entry_hash = Column(String(64), nullable=False)
    previous_hash = Column(String(64))
    
    # Indexes for performance (tenant_id already indexed by TenantMixin)
    __table_args__ = (
        Index('ix_audit_logs_user_id', 'user_id'),
        Index('ix_audit_logs_action', 'action'),
        Index('ix_audit_logs_created_at', 'created_at'),
        Index('ix_audit_logs_resource', 'resource_type', 'resource_id'),
        {'extend_existing': True}
    )


class AuditLogger:
    """Audit logger with tamper-proof mechanisms"""
    
    def __init__(self, db_session: Optional[Session] = None):
        self.db_session = db_session
        
    def _calculate_hash(self, data: Dict[str, Any], previous_hash: Optional[str] = None) -> str:
        """Calculate tamper-proof hash of audit log entry"""
        # Create deterministic string representation
        hash_data = {
            'action': data.get('action'),
            'user_id': data.get('user_id'),
            'resource_type': data.get('resource_type'),
            'resource_id': data.get('resource_id'),
            'details': data.get('details'),
            'timestamp': data.get('timestamp'),
            'previous_hash': previous_hash or ''
        }
        
        # Sort keys for deterministic hashing
        hash_string = json.dumps(hash_data, sort_keys=True)
        
        # Calculate SHA-256 hash
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def _get_previous_hash(self, tenant_id: str) -> Optional[str]:
        """Get the hash of the previous audit log entry for chain validation"""
        if not self.db_session:
            return None
            
        try:
            last_entry = self.db_session.query(AuditLog).filter(
                AuditLog.tenant_id == tenant_id
            ).order_by(AuditLog.created_at.desc()).first()
            
            return last_entry.entry_hash if last_entry else None
        except Exception as e:
            logger.error(f"Error getting previous hash: {e}")
            return None
    
    def log(
        self,
        action: str,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        status: str = "success",
        error_message: Optional[str] = None
    ) -> Optional[AuditLog]:
        """Create audit log entry with tamper-proof hash"""
        
        try:
            # Prepare audit data
            audit_data = {
                'action': action,
                'user_id': user_id,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'details': json.dumps(details) if details else None,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Get previous hash for chain
            previous_hash = self._get_previous_hash(tenant_id) if tenant_id else None
            
            # Calculate entry hash
            entry_hash = self._calculate_hash(audit_data, previous_hash)
            
            # Create audit log entry
            audit_log = AuditLog(
                action=action,
                user_id=user_id,
                user_email=user_email,
                resource_type=resource_type,
                resource_id=resource_id,
                details=audit_data['details'],
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                session_id=session_id,
                tenant_id=tenant_id,
                status=status,
                error_message=error_message,
                entry_hash=entry_hash,
                previous_hash=previous_hash
            )
            
            # Save to database if session is available
            if self.db_session:
                self.db_session.add(audit_log)
                self.db_session.commit()
                
            # Also log to standard logger
            log_message = f"AUDIT: {action} by {user_email or user_id or 'anonymous'}"
            if resource_type and resource_id:
                log_message += f" on {resource_type}:{resource_id}"
            if status != "success":
                log_message += f" - Status: {status}"
                if error_message:
                    log_message += f" - Error: {error_message}"
                    
            logger.info(log_message, extra={
                'audit_action': action,
                'user_id': user_id,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'tenant_id': tenant_id,
                'status': status
            })
            
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            return None
    
    def verify_integrity(self, tenant_id: str, limit: int = 100) -> bool:
        """Verify the integrity of the audit log chain"""
        if not self.db_session:
            return False
            
        try:
            # Get recent audit logs
            logs = self.db_session.query(AuditLog).filter(
                AuditLog.tenant_id == tenant_id
            ).order_by(AuditLog.created_at.asc()).limit(limit).all()
            
            if not logs:
                return True
                
            # Verify chain integrity
            previous_hash = None
            for log in logs:
                # Recalculate hash
                audit_data = {
                    'action': log.action,
                    'user_id': log.user_id,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'details': log.details,
                    'timestamp': log.created_at.isoformat()
                }
                
                expected_hash = self._calculate_hash(audit_data, previous_hash)
                
                # Verify hash matches
                if log.entry_hash != expected_hash:
                    logger.error(f"Audit log integrity violation at entry {log.id}")
                    return False
                    
                # Verify chain
                if log.previous_hash != previous_hash:
                    logger.error(f"Audit log chain broken at entry {log.id}")
                    return False
                    
                previous_hash = log.entry_hash
                
            return True
            
        except Exception as e:
            logger.error(f"Error verifying audit log integrity: {e}")
            return False


# Global audit logger instance
audit_logger = AuditLogger()


def create_audit_log(
    action: str,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    status: str = "success",
    error_message: Optional[str] = None,
    db_session: Optional[Session] = None
) -> Optional[AuditLog]:
    """Helper function to create audit log entry"""
    
    # Use provided session or create new logger instance
    if db_session:
        logger_instance = AuditLogger(db_session)
    else:
        logger_instance = audit_logger
        
    return logger_instance.log(
        action=action,
        user_id=user_id,
        user_email=user_email,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        session_id=session_id,
        tenant_id=tenant_id,
        status=status,
        error_message=error_message
    )