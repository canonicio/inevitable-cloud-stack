"""
Secure Session Configuration with Proper Timeouts
Addresses LOW-001: Session Timeout Configuration  
Addresses LOW-002: Rate Limiting Gaps
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import redis

from modules.core.config import settings

logger = logging.getLogger(__name__)


class SessionType(Enum):
    """Session types with different security requirements"""
    STANDARD = "standard"
    ELEVATED = "elevated"  # For sensitive operations
    REMEMBER_ME = "remember_me"  # Long-lived with reduced privileges
    API_KEY = "api_key"  # For API access
    # MEDIUM FIX: Additional session types for edge cases
    ADMIN = "admin"  # Admin sessions with strict timeouts
    GUEST = "guest"  # Guest sessions with very short timeouts
    MOBILE = "mobile"  # Mobile sessions with device binding
    IMPERSONATION = "impersonation"  # Admin impersonating users


class SecureSessionConfig:
    """
    Secure session configuration following security best practices.
    Addresses LOW-001: Session Timeout Configuration
    """
    
    # Session timeout configurations (in minutes)
    SESSION_TIMEOUTS = {
        SessionType.STANDARD: {
            "idle_timeout": 30,        # 30 minutes of inactivity
            "absolute_timeout": 240,    # 4 hours absolute (LOW-001 FIX)
            "renewal_threshold": 10,    # Renew if less than 10 minutes left
            "max_renewals": 5          # Maximum renewals before re-auth
        },
        SessionType.ELEVATED: {
            "idle_timeout": 15,        # 15 minutes for sensitive operations
            "absolute_timeout": 60,     # 1 hour absolute
            "renewal_threshold": 5,
            "max_renewals": 2
        },
        SessionType.REMEMBER_ME: {
            "idle_timeout": 1440,      # 24 hours idle
            "absolute_timeout": 43200,  # 30 days absolute
            "renewal_threshold": 1440,  # 1 day
            "max_renewals": 10,
            "reduced_privileges": True  # Cannot perform sensitive operations
        },
        SessionType.API_KEY: {
            "idle_timeout": 0,          # No idle timeout for API keys
            "absolute_timeout": 525600, # 1 year
            "renewal_threshold": 0,
            "max_renewals": 0,
            "requires_rotation": True   # Must be rotated periodically
        },
        # MEDIUM FIX: Additional session configurations for comprehensive coverage
        SessionType.ADMIN: {
            "idle_timeout": 15,         # Very strict for admin sessions
            "absolute_timeout": 120,    # 2 hours max
            "renewal_threshold": 5,
            "max_renewals": 3,
            "require_mfa_renewal": True, # Must re-verify MFA for renewals
            "ip_binding": True          # Bind to specific IP
        },
        SessionType.GUEST: {
            "idle_timeout": 5,          # 5 minutes idle
            "absolute_timeout": 30,     # 30 minutes max
            "renewal_threshold": 0,
            "max_renewals": 0,
            "readonly_only": True       # Cannot modify anything
        },
        SessionType.MOBILE: {
            "idle_timeout": 60,         # 1 hour idle (mobile-friendly)
            "absolute_timeout": 720,    # 12 hours
            "renewal_threshold": 60,
            "max_renewals": 8,
            "device_binding": True,     # Bind to device fingerprint
            "location_aware": True      # Track location changes
        },
        SessionType.IMPERSONATION: {
            "idle_timeout": 10,         # Very short for impersonation
            "absolute_timeout": 60,     # 1 hour max
            "renewal_threshold": 0,
            "max_renewals": 0,
            "audit_everything": True,   # Log all actions
            "original_user_tracking": True
        }
    }
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client or redis.Redis.from_url(
            settings.REDIS_URL or "redis://localhost:6379"
        )
    
    def get_session_config(self, session_type: SessionType) -> Dict[str, Any]:
        """Get configuration for session type."""
        return self.SESSION_TIMEOUTS.get(
            session_type,
            self.SESSION_TIMEOUTS[SessionType.STANDARD]
        )
    
    def create_session(
        self,
        user_id: int,
        session_type: SessionType = SessionType.STANDARD,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a new session with proper timeout configuration.
        MEDIUM FIX: Enhanced session ID generation with additional entropy
        """
        import secrets
        import hashlib
        import time
        
        config = self.get_session_config(session_type)
        now = datetime.utcnow()
        
        # MEDIUM FIX: Generate session ID with additional entropy from user context
        # Combine multiple entropy sources for unpredictable session IDs
        user_agent = metadata.get('user_agent', '') if metadata else ''
        ip_address = metadata.get('ip_address', '') if metadata else ''
        
        entropy_sources = [
            secrets.token_bytes(32),  # Primary cryptographically secure random
            str(time.time_ns()).encode(),  # High precision timestamp
            str(user_id).encode(),  # User context
            user_agent.encode()[:100],  # User agent (limited length)
            ip_address.encode(),  # IP address
            str(now.timestamp()).encode(),  # Current timestamp
            str(session_type.value).encode(),  # Session type
            secrets.token_bytes(16)  # Additional random data
        ]
        
        # Combine all entropy sources with SHA-256
        combined_entropy = b''.join(entropy_sources)
        entropy_hash = hashlib.sha256(combined_entropy).digest()
        
        # Generate final session ID from combined entropy + additional randomness
        session_id = secrets.token_urlsafe(32) + '-' + hashlib.sha256(
            entropy_hash + secrets.token_bytes(16)
        ).hexdigest()[:16]
        
        # Calculate expiration times
        idle_expiry = now + timedelta(minutes=config["idle_timeout"]) if config["idle_timeout"] > 0 else None
        absolute_expiry = now + timedelta(minutes=config["absolute_timeout"])
        
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "session_type": session_type.value,
            "created_at": now.isoformat(),
            "last_activity": now.isoformat(),
            "idle_expiry": idle_expiry.isoformat() if idle_expiry else None,
            "absolute_expiry": absolute_expiry.isoformat(),
            "renewal_count": 0,
            "max_renewals": config["max_renewals"],
            "metadata": metadata or {}
        }
        
        # Store in Redis with absolute timeout
        cache_key = f"session:{session_id}"
        self.redis_client.setex(
            cache_key,
            int(config["absolute_timeout"] * 60),  # Convert to seconds
            json.dumps(session_data)
        )
        
        logger.info(f"Created {session_type.value} session for user {user_id}")
        
        return session_data
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Validate session with timeout checks.
        """
        import json
        
        cache_key = f"session:{session_id}"
        session_data = self.redis_client.get(cache_key)
        
        if not session_data:
            return None
        
        try:
            session = json.loads(session_data)
        except json.JSONDecodeError:
            logger.error(f"Invalid session data for {session_id}")
            return None
        
        now = datetime.utcnow()
        
        # Check absolute timeout
        absolute_expiry = datetime.fromisoformat(session["absolute_expiry"])
        if now >= absolute_expiry:
            logger.info(f"Session {session_id} expired (absolute timeout)")
            self.redis_client.delete(cache_key)
            return None
        
        # Check idle timeout
        if session["idle_expiry"]:
            idle_expiry = datetime.fromisoformat(session["idle_expiry"])
            if now >= idle_expiry:
                logger.info(f"Session {session_id} expired (idle timeout)")
                self.redis_client.delete(cache_key)
                return None
        
        # Update last activity (sliding session)
        session["last_activity"] = now.isoformat()
        
        # Update idle expiry if configured
        session_type = SessionType(session["session_type"])
        config = self.get_session_config(session_type)
        
        if config["idle_timeout"] > 0:
            new_idle_expiry = now + timedelta(minutes=config["idle_timeout"])
            session["idle_expiry"] = new_idle_expiry.isoformat()
        
        # Check if session needs renewal warning
        time_remaining = (absolute_expiry - now).total_seconds() / 60
        if time_remaining <= config["renewal_threshold"]:
            session["needs_renewal"] = True
        
        # Update session in Redis
        remaining_ttl = int((absolute_expiry - now).total_seconds())
        self.redis_client.setex(cache_key, remaining_ttl, json.dumps(session))
        
        return session
    
    def renew_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Renew session if allowed.
        """
        session = self.validate_session(session_id)
        if not session:
            return None
        
        # Check renewal limit
        if session["renewal_count"] >= session["max_renewals"]:
            logger.info(f"Session {session_id} exceeded renewal limit")
            return None
        
        # Get configuration
        session_type = SessionType(session["session_type"])
        config = self.get_session_config(session_type)
        
        # Update expiration times
        now = datetime.utcnow()
        new_absolute_expiry = now + timedelta(minutes=config["absolute_timeout"])
        
        session["absolute_expiry"] = new_absolute_expiry.isoformat()
        session["renewal_count"] += 1
        session["last_renewed"] = now.isoformat()
        session.pop("needs_renewal", None)
        
        # Update in Redis
        import json
        cache_key = f"session:{session_id}"
        self.redis_client.setex(
            cache_key,
            int(config["absolute_timeout"] * 60),
            json.dumps(session)
        )
        
        logger.info(f"Renewed session {session_id} (renewal {session['renewal_count']})")
        
        return session
    
    def terminate_session(self, session_id: str) -> bool:
        """
        Explicitly terminate a session.
        """
        cache_key = f"session:{session_id}"
        result = self.redis_client.delete(cache_key)
        
        if result:
            logger.info(f"Terminated session {session_id}")
        
        return bool(result)
    
    def terminate_user_sessions(self, user_id: int) -> int:
        """
        Terminate all sessions for a user.
        """
        import json
        
        terminated = 0
        
        # Find all sessions for user (would need to maintain an index in production)
        for key in self.redis_client.scan_iter(match="session:*"):
            session_data = self.redis_client.get(key)
            if session_data:
                try:
                    session = json.loads(session_data)
                    if session.get("user_id") == user_id:
                        self.redis_client.delete(key)
                        terminated += 1
                except json.JSONDecodeError:
                    continue
        
        logger.info(f"Terminated {terminated} sessions for user {user_id}")
        return terminated


class SessionRateLimiter:
    """
    Rate limiting for authentication attempts.
    Addresses LOW-002: Rate Limiting Gaps
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client or redis.Redis.from_url(
            settings.REDIS_URL or "redis://localhost:6379"
        )
        
        # Rate limit configurations
        self.limits = {
            "login_attempts": {
                "max_attempts": 5,
                "window": 900,  # 15 minutes
                "lockout": 1800  # 30 minutes lockout
            },
            "password_reset": {
                "max_attempts": 3,
                "window": 3600,  # 1 hour
                "lockout": 3600
            },
            "mfa_attempts": {
                "max_attempts": 5,
                "window": 600,  # 10 minutes
                "lockout": 1800
            },
            "api_auth": {
                "max_attempts": 10,
                "window": 60,  # 1 minute
                "lockout": 300  # 5 minutes
            }
        }
    
    def check_rate_limit(
        self,
        identifier: str,
        action: str
    ) -> tuple[bool, Optional[int]]:
        """
        Check if action is rate limited.
        
        Returns:
            Tuple of (is_allowed, seconds_until_retry)
        """
        if action not in self.limits:
            return True, None
        
        config = self.limits[action]
        
        # Check if currently locked out
        lockout_key = f"ratelimit:lockout:{action}:{identifier}"
        if self.redis_client.exists(lockout_key):
            ttl = self.redis_client.ttl(lockout_key)
            return False, ttl
        
        # Check attempt count
        attempt_key = f"ratelimit:attempts:{action}:{identifier}"
        attempts = self.redis_client.incr(attempt_key)
        
        if attempts == 1:
            # Set expiration on first attempt
            self.redis_client.expire(attempt_key, config["window"])
        
        if attempts > config["max_attempts"]:
            # Apply lockout
            self.redis_client.setex(
                lockout_key,
                config["lockout"],
                "locked"
            )
            self.redis_client.delete(attempt_key)
            
            logger.warning(
                f"Rate limit exceeded for {action} by {identifier}. "
                f"Locked out for {config['lockout']} seconds."
            )
            
            return False, config["lockout"]
        
        return True, None
    
    def add_progressive_delay(self, attempts: int) -> int:
        """
        Calculate progressive delay based on attempt count.
        """
        if attempts <= 1:
            return 0
        elif attempts == 2:
            return 1
        elif attempts == 3:
            return 2
        elif attempts == 4:
            return 5
        else:
            return min(30, 5 * (attempts - 3))  # Cap at 30 seconds


# Import json at module level
import json