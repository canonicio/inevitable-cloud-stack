"""
MFA Token Validator with Scope Protection
Addresses HIGH-AUTH-001: MFA Token Scope Manipulation
"""
import hmac
import hashlib
import time
import json
import secrets
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
import redis
from redis.exceptions import RedisError
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class MFATokenScope:
    """Define valid MFA token scopes"""
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    SENSITIVE_ACTION = "sensitive_action"
    ADMIN_ACCESS = "admin_access"
    PAYMENT_AUTHORIZATION = "payment_authorization"
    ACCOUNT_DELETION = "account_deletion"
    API_KEY_GENERATION = "api_key_generation"
    
    @classmethod
    def is_valid(cls, scope: str) -> bool:
        """Check if scope is valid"""
        valid_scopes = {
            cls.LOGIN, cls.PASSWORD_RESET, cls.SENSITIVE_ACTION,
            cls.ADMIN_ACCESS, cls.PAYMENT_AUTHORIZATION,
            cls.ACCOUNT_DELETION, cls.API_KEY_GENERATION
        }
        return scope in valid_scopes


class MFATokenValidator:
    """
    Secure MFA token validation with scope binding
    Prevents token reuse across different operations
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL or "redis://localhost:6379"
        self.redis_client = None
        self.token_ttl = 300  # 5 minutes
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis for token storage"""
        try:
            self.redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            self.redis_client.ping()
            logger.info("MFA token validator connected to Redis")
        except (RedisError, Exception) as e:
            logger.error(f"Redis connection failed for MFA tokens: {e}")
            raise RuntimeError("MFA token validation requires Redis")
    
    def generate_mfa_token(
        self,
        user_id: str,
        scope: str,
        mfa_method: str,
        additional_claims: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """
        Generate a scope-bound MFA token
        
        Args:
            user_id: User identifier
            scope: Token scope (must be valid MFATokenScope)
            mfa_method: MFA method used (totp, email, sms)
            additional_claims: Additional data to bind to token
            ip_address: Client IP for binding
            user_agent: Client user agent for binding
        """
        # Validate scope
        if not MFATokenScope.is_valid(scope):
            raise ValueError(f"Invalid MFA token scope: {scope}")
        
        # Generate secure token
        token = secrets.token_urlsafe(32)
        
        # Create token data with scope binding
        token_data = {
            "token": token,
            "user_id": user_id,
            "scope": scope,  # Bind scope to token
            "mfa_method": mfa_method,
            "created_at": time.time(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "additional_claims": additional_claims or {},
            "used": False,
            "use_count": 0,
            "max_uses": 1,  # Single use by default
            "signature": None
        }
        
        # Add cryptographic signature to prevent tampering
        signature_data = f"{token}:{user_id}:{scope}:{mfa_method}:{time.time()}"
        token_data["signature"] = hmac.new(
            settings.SECRET_KEY.encode(),
            signature_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Store in Redis with scope-specific key
        key = f"mfa_token:{scope}:{user_id}:{token}"
        
        try:
            # Use SET with NX to prevent overwrites
            success = self.redis_client.set(
                key,
                json.dumps(token_data),
                ex=self.token_ttl,
                nx=True
            )
            
            if not success:
                logger.warning("MFA token collision detected, regenerating")
                return self.generate_mfa_token(
                    user_id, scope, mfa_method, additional_claims, ip_address, user_agent
                )
            
            # Also store in a user-specific set for tracking
            user_tokens_key = f"mfa_tokens:user:{user_id}"
            self.redis_client.sadd(user_tokens_key, key)
            self.redis_client.expire(user_tokens_key, self.token_ttl)
            
            logger.info(
                f"MFA token generated for user {user_id} "
                f"with scope {scope}: {token[:8]}..."
            )
            
            return token
            
        except Exception as e:
            logger.error(f"Failed to store MFA token: {e}")
            raise RuntimeError("Failed to generate MFA token")
    
    def validate_token(
        self,
        token: str,
        user_id: str,
        scope: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        consume: bool = True
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate MFA token with scope verification
        
        Args:
            token: MFA token to validate
            user_id: Expected user ID
            scope: Expected token scope
            ip_address: Client IP for verification
            user_agent: Client user agent for verification
            consume: Whether to consume (invalidate) the token
        
        Returns:
            (is_valid, token_data)
        """
        # Validate scope
        if not MFATokenScope.is_valid(scope):
            logger.warning(f"Invalid MFA token scope attempted: {scope}")
            return False, None
        
        if not token or not user_id:
            return False, None
        
        # Build key with scope
        key = f"mfa_token:{scope}:{user_id}:{token}"
        
        try:
            if consume:
                # Use Lua script for atomic get-and-delete
                lua_script = """
                local key = KEYS[1]
                local value = redis.call('get', key)
                if value then
                    local data = cjson.decode(value)
                    if data.used == false and data.use_count < data.max_uses then
                        data.used = true
                        data.use_count = data.use_count + 1
                        if data.use_count >= data.max_uses then
                            redis.call('del', key)
                        else
                            redis.call('set', key, cjson.encode(data))
                        end
                        return value
                    else
                        return nil
                    end
                else
                    return nil
                end
                """
                
                token_json = self.redis_client.eval(lua_script, 1, key)
            else:
                # Just retrieve without consuming
                token_json = self.redis_client.get(key)
            
            if not token_json:
                logger.warning(
                    f"MFA token not found or already used: "
                    f"user={user_id}, scope={scope}, token={token[:8]}..."
                )
                return False, None
            
            # Parse token data
            token_data = json.loads(token_json)
            
            # Verify token hasn't expired
            created_at = token_data.get("created_at", 0)
            if time.time() - created_at > self.token_ttl:
                logger.warning(f"MFA token expired for user {user_id}")
                # Clean up expired token
                self.redis_client.delete(key)
                return False, None
            
            # CRITICAL: Verify scope matches
            if token_data.get("scope") != scope:
                logger.error(
                    f"MFA token scope mismatch! "
                    f"Expected: {scope}, Got: {token_data.get('scope')}. "
                    f"Possible scope manipulation attempt by user {user_id}"
                )
                # Delete suspicious token
                self.redis_client.delete(key)
                return False, None
            
            # Verify user ID matches
            if token_data.get("user_id") != user_id:
                logger.error(
                    f"MFA token user mismatch! "
                    f"Expected: {user_id}, Got: {token_data.get('user_id')}"
                )
                return False, None
            
            # Verify signature
            signature_data = (
                f"{token_data['token']}:{token_data['user_id']}:"
                f"{token_data['scope']}:{token_data['mfa_method']}:"
                f"{token_data['created_at']}"
            )
            expected_signature = hmac.new(
                settings.SECRET_KEY.encode(),
                signature_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(token_data.get("signature", ""), expected_signature):
                logger.error(f"MFA token signature mismatch for user {user_id}")
                self.redis_client.delete(key)
                return False, None
            
            # Optional: Verify IP/User-Agent binding
            if ip_address and token_data.get("ip_address"):
                if token_data["ip_address"] != ip_address:
                    logger.warning(
                        f"MFA token IP mismatch for user {user_id}: "
                        f"expected {token_data['ip_address']}, got {ip_address}"
                    )
                    # Could be strict or lenient based on security requirements
                    # return False, None  # Strict mode
            
            if user_agent and token_data.get("user_agent"):
                if token_data["user_agent"] != user_agent:
                    logger.warning(
                        f"MFA token user agent mismatch for user {user_id}"
                    )
                    # Could be strict or lenient
                    # return False, None  # Strict mode
            
            logger.info(
                f"MFA token validated for user {user_id} "
                f"with scope {scope}: {token[:8]}..."
            )
            
            return True, token_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid MFA token data format: {e}")
            return False, None
        except Exception as e:
            logger.error(f"MFA token validation error: {e}")
            return False, None
    
    def revoke_user_tokens(
        self,
        user_id: str,
        scope: Optional[str] = None
    ) -> int:
        """
        Revoke all MFA tokens for a user
        Optionally filter by scope
        """
        try:
            revoked_count = 0
            
            # Get all user tokens
            user_tokens_key = f"mfa_tokens:user:{user_id}"
            token_keys = self.redis_client.smembers(user_tokens_key)
            
            for key in token_keys:
                # If scope specified, only revoke matching scope
                if scope and f":{ scope}:" not in key:
                    continue
                
                if self.redis_client.delete(key):
                    revoked_count += 1
            
            # Clean up user token set
            if not scope:
                self.redis_client.delete(user_tokens_key)
            
            if revoked_count > 0:
                logger.info(
                    f"Revoked {revoked_count} MFA tokens for user {user_id}"
                    f"{f' with scope {scope}' if scope else ''}"
                )
            
            return revoked_count
            
        except Exception as e:
            logger.error(f"Failed to revoke MFA tokens: {e}")
            return 0
    
    def create_multi_use_token(
        self,
        user_id: str,
        scope: str,
        mfa_method: str,
        max_uses: int = 3,
        ttl: Optional[int] = None
    ) -> str:
        """
        Create a multi-use MFA token for operations that require multiple validations
        """
        # Generate token with custom max_uses
        token = self.generate_mfa_token(user_id, scope, mfa_method)
        
        # Update max_uses
        key = f"mfa_token:{scope}:{user_id}:{token}"
        token_json = self.redis_client.get(key)
        
        if token_json:
            token_data = json.loads(token_json)
            token_data["max_uses"] = max_uses
            
            # Update TTL if specified
            actual_ttl = ttl or self.token_ttl
            
            self.redis_client.set(
                key,
                json.dumps(token_data),
                ex=actual_ttl
            )
            
            logger.info(
                f"Multi-use MFA token created for user {user_id}: "
                f"max_uses={max_uses}, ttl={actual_ttl}"
            )
        
        return token