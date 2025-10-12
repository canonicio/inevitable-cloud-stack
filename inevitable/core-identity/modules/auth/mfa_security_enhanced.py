"""
Enhanced MFA Security Module
Addresses all MFA-related vulnerabilities:
- MFA code replay attacks
- Session fixation during MFA
- MFA downgrade attacks
- Rate limiting for MFA attempts
"""

import time
import hmac
import hashlib
import secrets
import redis
import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from fastapi import HTTPException, status, Request

logger = logging.getLogger(__name__)


class EnhancedMFASecurity:
    """Comprehensive MFA security enhancements"""
    
    def __init__(self):
        try:
            from ..core.config import settings
            self.redis_client = redis.Redis.from_url(
                settings.REDIS_URL or "redis://localhost:6379",
                decode_responses=True
            )
            self.redis_client.ping()
        except Exception as e:
            logger.warning(f"Redis not available for MFA security: {e}")
            self.redis_client = None
        
        # Configuration
        self.max_attempts = 5
        self.rate_limit_window = 300  # 5 minutes
        self.code_validity_window = 90  # 90 seconds for TOTP
        self.replay_protection_window = 300  # 5 minutes
    
    def check_mfa_rate_limit(self, user_id: str, tenant_id: str) -> bool:
        """
        Check and enforce rate limiting for MFA attempts.
        Returns True if within limits, False if rate limited.
        """
        if not self.redis_client:
            return True  # Allow if Redis not available (graceful degradation)
        
        try:
            rate_limit_key = f"mfa_rate_limit:{tenant_id}:{user_id}"
            
            # Get current attempt count
            attempts = self.redis_client.get(rate_limit_key)
            if attempts and int(attempts) >= self.max_attempts:
                logger.warning(f"MFA rate limit exceeded for user {user_id}")
                return False
            
            # Increment attempt count with expiry
            pipe = self.redis_client.pipeline()
            pipe.incr(rate_limit_key)
            pipe.expire(rate_limit_key, self.rate_limit_window)
            pipe.execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking MFA rate limit: {e}")
            return True  # Fail open for availability
    
    def prevent_code_replay(self, user_id: str, tenant_id: str, code: str) -> bool:
        """
        Prevent MFA code replay attacks by tracking used codes.
        Returns True if code is fresh, False if it's a replay.
        """
        if not self.redis_client:
            # Without Redis, we can't track replays effectively
            logger.warning("Code replay protection unavailable without Redis")
            return True
        
        try:
            # Create unique key for this code
            code_hash = hashlib.sha256(f"{tenant_id}:{user_id}:{code}".encode()).hexdigest()
            replay_key = f"mfa_used_code:{code_hash}"
            
            # Try to set the key (will fail if already exists)
            if not self.redis_client.set(replay_key, "used", nx=True, ex=self.replay_protection_window):
                logger.warning(f"MFA code replay detected for user {user_id}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error in replay protection: {e}")
            return True  # Fail open
    
    def regenerate_session_after_mfa(self, request: Request, user_data: Dict[str, Any]) -> str:
        """
        Regenerate session ID after successful MFA to prevent session fixation.
        Returns new session ID.
        """
        # Generate new session ID
        new_session_id = f"sess_{secrets.token_urlsafe(32)}"
        
        # Store session data with new ID
        if self.redis_client:
            try:
                session_key = f"session:{new_session_id}"
                session_data = {
                    "user_id": user_data.get("sub"),
                    "tenant_id": user_data.get("tenant_id"),
                    "created_at": str(datetime.utcnow()),
                    "mfa_verified": True,
                    "ip_address": request.client.host if request.client else None
                }
                
                # Store session with expiry
                self.redis_client.setex(
                    session_key,
                    3600 * 24,  # 24 hour expiry
                    str(session_data)
                )
                
                logger.info(f"Session regenerated after MFA for user {user_data.get('sub')}")
                
            except Exception as e:
                logger.error(f"Error regenerating session: {e}")
        
        return new_session_id
    
    def check_mfa_downgrade_attempt(self, request: Request) -> bool:
        """
        Check for MFA downgrade attack attempts via headers or parameters.
        Returns True if downgrade attempt detected.
        """
        suspicious_headers = [
            "X-Skip-MFA",
            "X-Internal-Request",
            "X-OAuth-Flow",
            "X-Legacy-API",
            "X-Mobile-App"
        ]
        
        # Check headers
        for header in suspicious_headers:
            if header.lower() in [h.lower() for h in request.headers.keys()]:
                logger.warning(f"MFA downgrade attempt detected via header: {header}")
                return True
        
        # Check for legacy API version headers
        api_version = request.headers.get("API-Version", "")
        if api_version and float(api_version.split(".")[0]) < 2:
            logger.warning(f"MFA downgrade attempt via old API version: {api_version}")
            return True
        
        # Check query parameters
        if request.query_params.get("skip_mfa") or request.query_params.get("no_mfa"):
            logger.warning("MFA downgrade attempt via query parameters")
            return True
        
        return False
    
    def validate_mfa_token_scope(self, token_payload: Dict[str, Any]) -> bool:
        """
        Validate MFA token scope to prevent scope manipulation.
        Returns True if scope is valid for MFA flow.
        """
        # Check required MFA fields
        if not token_payload.get("mfa_pending", False):
            logger.warning("MFA token missing mfa_pending flag")
            return False
        
        # Ensure it's not already verified
        if token_payload.get("mfa_verified", False):
            logger.warning("MFA token already marked as verified")
            return False
        
        # Check scope restriction
        allowed_scopes = ["mfa_verification", "mfa_pending"]
        token_scope = token_payload.get("scope", "")
        if token_scope not in allowed_scopes:
            logger.warning(f"Invalid MFA token scope: {token_scope}")
            return False
        
        # Check token type
        if token_payload.get("typ") != "mfa_challenge":
            logger.warning(f"Invalid MFA token type: {token_payload.get('typ')}")
            return False
        
        return True
    
    def enforce_mfa_time_window(self, mfa_initiated_at: str) -> bool:
        """
        Enforce time window for MFA completion.
        Returns True if within allowed window.
        """
        try:
            initiated_time = datetime.fromisoformat(mfa_initiated_at)
            current_time = datetime.utcnow()
            
            # 5 minute window to complete MFA
            if (current_time - initiated_time).total_seconds() > 300:
                logger.warning("MFA time window expired")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking MFA time window: {e}")
            return False
    
    def track_mfa_attempt(self, user_id: str, tenant_id: str, success: bool):
        """Track MFA attempt for security monitoring"""
        if not self.redis_client:
            return
        
        try:
            # Track attempt
            attempt_key = f"mfa_attempts:{tenant_id}:{user_id}:{datetime.utcnow().date()}"
            
            # Increment appropriate counter
            if success:
                self.redis_client.hincrby(attempt_key, "success", 1)
            else:
                self.redis_client.hincrby(attempt_key, "failed", 1)
            
            # Set expiry (7 days)
            self.redis_client.expire(attempt_key, 604800)
            
            # Check for suspicious patterns
            failed_count = self.redis_client.hget(attempt_key, "failed")
            if failed_count and int(failed_count) > 10:
                logger.warning(f"High MFA failure rate for user {user_id}: {failed_count} failures")
                
        except Exception as e:
            logger.error(f"Error tracking MFA attempt: {e}")
    
    def get_mfa_security_headers(self) -> Dict[str, str]:
        """Get security headers for MFA responses"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "X-MFA-Protected": "true"
        }
    
    def validate_backup_code(self, user_id: str, tenant_id: str, code: str) -> bool:
        """
        Validate and consume backup code (one-time use).
        Returns True if valid and unused.
        """
        if not self.redis_client:
            return False
        
        try:
            backup_key = f"mfa_backup_codes:{tenant_id}:{user_id}"
            
            # Check if code exists and remove it atomically
            removed = self.redis_client.srem(backup_key, code)
            
            if removed:
                logger.info(f"Backup code used for user {user_id}")
                return True
            else:
                logger.warning(f"Invalid or used backup code for user {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error validating backup code: {e}")
            return False
    
    def generate_backup_codes(self, user_id: str, tenant_id: str, count: int = 10) -> list:
        """Generate one-time use backup codes"""
        codes = []
        
        for _ in range(count):
            # Generate cryptographically secure code
            code = f"{secrets.token_hex(4)}-{secrets.token_hex(4)}"
            codes.append(code)
        
        # Store in Redis if available
        if self.redis_client:
            try:
                backup_key = f"mfa_backup_codes:{tenant_id}:{user_id}"
                
                # Delete old codes
                self.redis_client.delete(backup_key)
                
                # Store new codes
                for code in codes:
                    self.redis_client.sadd(backup_key, code)
                
                # Set expiry (1 year)
                self.redis_client.expire(backup_key, 31536000)
                
            except Exception as e:
                logger.error(f"Error storing backup codes: {e}")
        
        return codes


# Singleton instance
mfa_security = EnhancedMFASecurity()