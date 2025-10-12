"""
MFA Validator Module
Addresses RISK-H003: MFA Token Replay Attacks
"""
import hashlib
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Request
from sqlalchemy import Column, String, DateTime, Integer, Text, Index
from sqlalchemy.orm import Session

from ..core.database import Base
from ..core.config import settings

logger = logging.getLogger(__name__)


class UsedMFAToken(Base):
    """Track used MFA tokens for replay prevention"""
    __tablename__ = "used_mfa_tokens"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String(36), nullable=False)
    token_hash = Column(String(64), nullable=False, index=True)
    used_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(String(256))
    mfa_method = Column(String(20), nullable=False)
    
    # Composite index for fast lookups
    __table_args__ = (
        Index('idx_user_token', 'user_id', 'token_hash'),
        # Automatic cleanup of old tokens
        Index('idx_used_at', 'used_at'),
    )


class MFAValidator:
    """MFA validation with Redis and database fallback"""
    
    def __init__(self, redis_client: Optional[object], db: Session):
        self.redis = redis_client
        self.db = db
        self.token_ttl = 300  # 5 minutes
        self.cleanup_interval = 3600  # Run cleanup every hour
        self._last_cleanup = 0
    
    def validate_and_consume_token(
        self, 
        user_id: str, 
        token: str,
        method: str,
        request: Request
    ) -> None:
        """Validate MFA token and prevent reuse"""
        # Hash token for storage (prevent token exposure in logs/database)
        token_hash = self._hash_token(user_id, token)
        
        # Check if token was already used (try Redis first, then database)
        if self._is_token_used(user_id, token_hash):
            logger.warning(
                f"MFA token replay attempt detected for user {user_id}",
                extra={
                    "user_id": user_id,
                    "method": method,
                    "ip": request.client.host if hasattr(request, 'client') else None,
                    "action": "mfa_replay_blocked"
                }
            )
            raise HTTPException(
                status_code=400,
                detail="MFA token already used or invalid"
            )
        
        # Mark token as used immediately (before validation)
        self._mark_token_used(user_id, token_hash, method, request)
        
        # Run cleanup if needed
        self._maybe_cleanup()
    
    def _hash_token(self, user_id: str, token: str) -> str:
        """Generate secure hash of token with user context"""
        # Include user_id in hash to prevent cross-user token reuse
        combined = f"{user_id}:{token}:{settings.SECRET_KEY}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _is_token_used(self, user_id: str, token_hash: str) -> bool:
        """Check if token was used (Redis first, database fallback)"""
        # Try Redis first (fast cache)
        if self.redis and self._check_redis_token(user_id, token_hash):
            return True
        
        # Fallback to database (persistent storage)
        return self._check_database_token(user_id, token_hash)
    
    def _check_redis_token(self, user_id: str, token_hash: str) -> bool:
        """Check if token was used in Redis"""
        try:
            key = f"mfa_used:{user_id}:{token_hash}"
            return bool(self.redis.exists(key))
        except Exception as e:
            logger.warning(f"Redis error during MFA token check: {e}")
            return False
    
    def _check_database_token(self, user_id: str, token_hash: str) -> bool:
        """Check if token was used in database"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.token_ttl)
            
            used_token = self.db.query(UsedMFAToken).filter(
                UsedMFAToken.user_id == user_id,
                UsedMFAToken.token_hash == token_hash,
                UsedMFAToken.used_at > cutoff_time
            ).first()
            
            return used_token is not None
        except Exception as e:
            logger.error(f"Database error during MFA token check: {e}")
            # On database error, allow the token to prevent lockout
            return False
    
    def _mark_token_used(
        self, 
        user_id: str, 
        token_hash: str,
        method: str,
        request: Request
    ) -> None:
        """Mark token as used in both Redis and database"""
        current_time = datetime.utcnow()
        
        # Try Redis first (fast invalidation)
        if self.redis:
            try:
                key = f"mfa_used:{user_id}:{token_hash}"
                self.redis.setex(key, self.token_ttl, json.dumps({
                    "used_at": current_time.isoformat(),
                    "method": method,
                    "ip": getattr(request.client, 'host', None) if hasattr(request, 'client') else None
                }))
            except Exception as e:
                logger.warning(f"Redis error during MFA token marking: {e}")
        
        # Always store in database for durability and cross-instance sync
        try:
            used_token = UsedMFAToken(
                user_id=user_id,
                token_hash=token_hash,
                used_at=current_time,
                ip_address=getattr(request.client, 'host', None) if hasattr(request, 'client') else None,
                user_agent=(request.headers.get("User-Agent", "")[:256] 
                           if hasattr(request, 'headers') else ""),
                mfa_method=method
            )
            self.db.add(used_token)
            self.db.commit()
            
        except Exception as e:
            logger.error(f"Database error during MFA token marking: {e}")
            # Try to rollback
            try:
                self.db.rollback()
            except:
                pass
    
    def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all MFA tokens for a user (e.g., on password change)"""
        revoked_count = 0
        
        # Clear from Redis
        if self.redis:
            try:
                pattern = f"mfa_used:{user_id}:*"
                for key in self.redis.scan_iter(match=pattern):
                    self.redis.delete(key)
                    revoked_count += 1
            except Exception as e:
                logger.warning(f"Redis error during token revocation: {e}")
        
        # Mark all database tokens as expired by updating timestamp
        try:
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.token_ttl)
            updated = self.db.query(UsedMFAToken).filter(
                UsedMFAToken.user_id == user_id,
                UsedMFAToken.used_at > cutoff_time
            ).update({
                "used_at": datetime.utcnow() - timedelta(seconds=self.token_ttl + 1)
            })
            self.db.commit()
            revoked_count += updated
            
        except Exception as e:
            logger.error(f"Database error during token revocation: {e}")
            try:
                self.db.rollback()
            except:
                pass
        
        return revoked_count
    
    def _maybe_cleanup(self):
        """Run cleanup if enough time has passed"""
        current_time = time.time()
        
        if current_time - self._last_cleanup > self.cleanup_interval:
            self._last_cleanup = current_time
            self.cleanup_old_tokens()
    
    def cleanup_old_tokens(self) -> int:
        """Remove old MFA token records beyond retention period"""
        deleted_count = 0
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(seconds=self.token_ttl * 2)
            
            deleted_count = self.db.query(UsedMFAToken).filter(
                UsedMFAToken.used_at < cutoff_date
            ).delete()
            
            self.db.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old MFA token records")
                
        except Exception as e:
            logger.error(f"Error cleaning up MFA tokens: {e}")
            try:
                self.db.rollback()
            except:
                pass
        
        return deleted_count
    
    def get_token_usage_stats(self, user_id: str) -> Dict[str, Any]:
        """Get MFA token usage statistics for monitoring"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            
            # Count tokens used in last 24 hours
            recent_tokens = self.db.query(UsedMFAToken).filter(
                UsedMFAToken.user_id == user_id,
                UsedMFAToken.used_at > cutoff_time
            ).all()
            
            stats = {
                "total_tokens_24h": len(recent_tokens),
                "methods_used": list(set(t.mfa_method for t in recent_tokens)),
                "unique_ips": list(set(t.ip_address for t in recent_tokens if t.ip_address)),
                "last_used": max((t.used_at for t in recent_tokens), default=None)
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting MFA token stats: {e}")
            return {
                "total_tokens_24h": 0,
                "methods_used": [],
                "unique_ips": [],
                "last_used": None,
                "error": str(e)
            }
    
    def detect_suspicious_activity(self, user_id: str) -> Dict[str, Any]:
        """Detect suspicious MFA token activity"""
        try:
            # Check for rapid token consumption (potential brute force)
            recent_time = datetime.utcnow() - timedelta(minutes=5)
            recent_count = self.db.query(UsedMFAToken).filter(
                UsedMFAToken.user_id == user_id,
                UsedMFAToken.used_at > recent_time
            ).count()
            
            # Check for multiple IP addresses (potential account sharing/compromise)
            day_ago = datetime.utcnow() - timedelta(hours=24)
            unique_ips = self.db.query(UsedMFAToken.ip_address).filter(
                UsedMFAToken.user_id == user_id,
                UsedMFAToken.used_at > day_ago,
                UsedMFAToken.ip_address.is_not(None)
            ).distinct().count()
            
            suspicious_indicators = []
            
            if recent_count > 10:
                suspicious_indicators.append(f"High token usage: {recent_count} tokens in 5 minutes")
            
            if unique_ips > 5:
                suspicious_indicators.append(f"Multiple IP addresses: {unique_ips} unique IPs in 24h")
            
            return {
                "is_suspicious": len(suspicious_indicators) > 0,
                "indicators": suspicious_indicators,
                "recent_token_count": recent_count,
                "unique_ip_count": unique_ips
            }
            
        except Exception as e:
            logger.error(f"Error detecting suspicious MFA activity: {e}")
            return {
                "is_suspicious": False,
                "indicators": [],
                "error": str(e)
            }


# Global instances
_mfa_validators = {}


def get_mfa_validator(redis_client: Optional[object], db: Session) -> MFAValidator:
    """Get MFA validator instance (cached per session)"""
    session_id = id(db)
    
    if session_id not in _mfa_validators:
        _mfa_validators[session_id] = MFAValidator(redis_client, db)
    
    return _mfa_validators[session_id]


def cleanup_validator_cache():
    """Clean up validator cache (call on session close)"""
    global _mfa_validators
    _mfa_validators.clear()