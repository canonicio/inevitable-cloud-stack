"""
MCP Authentication Provider
"""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from .models import MCPSession, MCPPolicy, MCPAuditLog, MCPAccessLevel
from modules.auth.models import User
from modules.auth.service import auth_service
from modules.core.crypto import encrypt_data, decrypt_data


class MCPAuthProvider:
    """Handles MCP authentication and session management"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_session(
        self,
        user: User,
        tenant_id: str,
        policy_id: int,
        client_id: str,
        client_version: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        mfa_verified: bool = False
    ) -> MCPSession:
        """Create a new MCP session"""
        
        # Verify policy exists and is active
        policy = self.db.query(MCPPolicy).filter(
            MCPPolicy.id == policy_id,
            MCPPolicy.tenant_id == tenant_id,
            MCPPolicy.is_active == True
        ).first()
        
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Policy not found or inactive"
            )
        
        # Check if MFA is required
        if policy.require_mfa and not mfa_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification required for this policy"
            )
        
        # Generate tokens
        session_token = self._generate_session_token()
        refresh_token = self._generate_refresh_token()
        
        # Calculate expiration based on policy
        expires_at = datetime.utcnow() + timedelta(hours=24)  # Default 24 hours
        if policy.access_level == MCPAccessLevel.LIMITED:
            expires_at = datetime.utcnow() + timedelta(hours=1)
        elif policy.access_level == MCPAccessLevel.ELEVATED:
            expires_at = datetime.utcnow() + timedelta(hours=8)
        
        # Create session
        session = MCPSession(
            tenant_id=tenant_id,
            user_id=user.id,
            policy_id=policy_id,
            session_token=self._hash_token(session_token),
            refresh_token=self._hash_token(refresh_token),
            client_id=client_id,
            client_version=client_version,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            mfa_verified=mfa_verified,
            mfa_verified_at=datetime.utcnow() if mfa_verified else None
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        # Log session creation
        self._log_audit(
            session=session,
            action="session.create",
            resource_type="session",
            resource_name=str(session.id),
            response_status="success"
        )
        
        return {
            "session_id": str(session.id),
            "session_token": session_token,
            "refresh_token": refresh_token,
            "expires_at": session.expires_at.isoformat(),
            "access_level": policy.access_level,
            "permissions": policy.permissions
        }
    
    def validate_session(self, session_token: str) -> Optional[MCPSession]:
        """Validate and return active session"""
        hashed_token = self._hash_token(session_token)
        
        session = self.db.query(MCPSession).filter(
            MCPSession.session_token == hashed_token,
            MCPSession.expires_at > datetime.utcnow(),
            MCPSession.revoked_at.is_(None)
        ).first()
        
        if session:
            # Update last activity
            session.last_activity = datetime.utcnow()
            self.db.commit()
        
        return session
    
    def refresh_session(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh an MCP session"""
        hashed_token = self._hash_token(refresh_token)
        
        session = self.db.query(MCPSession).filter(
            MCPSession.refresh_token == hashed_token,
            MCPSession.revoked_at.is_(None)
        ).first()
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Check if session can be refreshed
        if session.expires_at < datetime.utcnow() - timedelta(days=7):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired"
            )
        
        # Generate new tokens
        new_session_token = self._generate_session_token()
        new_refresh_token = self._generate_refresh_token()
        
        # Update session
        session.session_token = self._hash_token(new_session_token)
        session.refresh_token = self._hash_token(new_refresh_token)
        session.expires_at = datetime.utcnow() + timedelta(hours=24)
        session.last_activity = datetime.utcnow()
        
        self.db.commit()
        
        # Log refresh
        self._log_audit(
            session=session,
            action="session.refresh",
            resource_type="session",
            resource_name=str(session.id),
            response_status="success"
        )
        
        return {
            "session_id": str(session.id),
            "session_token": new_session_token,
            "refresh_token": new_refresh_token,
            "expires_at": session.expires_at.isoformat()
        }
    
    def revoke_session(
        self,
        session_id: str,
        reason: str,
        revoked_by: User
    ) -> None:
        """Revoke an MCP session"""
        session = self.db.query(MCPSession).filter(
            MCPSession.id == session_id
        ).first()
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        session.revoked_at = datetime.utcnow()
        session.revoked_reason = reason
        
        self.db.commit()
        
        # Log revocation
        self._log_audit(
            session=session,
            action="session.revoke",
            resource_type="session",
            resource_name=str(session.id),
            response_status="success",
            request_data={"reason": reason, "revoked_by": revoked_by.id}
        )
    
    def get_active_sessions(
        self,
        tenant_id: str,
        user_id: Optional[int] = None
    ) -> List[MCPSession]:
        """Get active sessions for a tenant/user"""
        query = self.db.query(MCPSession).filter(
            MCPSession.tenant_id == tenant_id,
            MCPSession.expires_at > datetime.utcnow(),
            MCPSession.revoked_at.is_(None)
        )
        
        if user_id:
            query = query.filter(MCPSession.user_id == user_id)
        
        return query.all()
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        expired_sessions = self.db.query(MCPSession).filter(
            MCPSession.expires_at <= datetime.utcnow()
        ).all()
        
        count = len(expired_sessions)
        
        for session in expired_sessions:
            self.db.delete(session)
        
        self.db.commit()
        
        return count
    
    def _generate_session_token(self) -> str:
        """Generate a secure session token"""
        return f"mcp_sess_{secrets.token_urlsafe(32)}"
    
    def _generate_refresh_token(self) -> str:
        """Generate a secure refresh token"""
        return f"mcp_ref_{secrets.token_urlsafe(48)}"
    
    def _hash_token(self, token: str) -> str:
        """Hash a token for storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _log_audit(
        self,
        session: MCPSession,
        action: str,
        resource_type: str,
        resource_name: str,
        response_status: str,
        request_data: Optional[Dict] = None,
        response_data: Optional[Dict] = None,
        error_message: Optional[str] = None,
        duration_ms: Optional[int] = None
    ) -> None:
        """Log an audit event"""
        audit_log = MCPAuditLog(
            tenant_id=session.tenant_id,
            session_id=session.id,
            policy_id=session.policy_id,
            user_id=session.user_id,
            action=action,
            resource_type=resource_type,
            resource_name=resource_name,
            request_data=request_data,
            response_status=response_status,
            response_data=response_data,
            error_message=error_message,
            duration_ms=duration_ms,
            ip_address=session.ip_address,
            user_agent=session.user_agent
        )
        
        self.db.add(audit_log)
        self.db.commit()