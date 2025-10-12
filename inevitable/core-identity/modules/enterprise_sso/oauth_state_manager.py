"""
OAuth State Manager with Race Condition Protection
Addresses HIGH-SSO-002: OAuth State Race Condition
"""
import secrets
import hashlib
import time
import json
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import redis
from redis.exceptions import RedisError
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class OAuthStateManager:
    """
    Secure OAuth state management with atomic operations
    Prevents race conditions and CSRF attacks in OAuth flows
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL or "redis://localhost:6379"
        self.redis_client = None
        self.state_ttl = 600  # 10 minutes
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis for distributed state management"""
        try:
            self.redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            self.redis_client.ping()
            logger.info("OAuth state manager connected to Redis")
        except (RedisError, Exception) as e:
            logger.error(f"Redis connection failed for OAuth state: {e}")
            raise RuntimeError("OAuth state management requires Redis")
    
    def generate_state(
        self,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        provider: str = "generic",
        redirect_uri: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate a cryptographically secure OAuth state token
        Returns the state token to use in OAuth authorization URL
        """
        # Generate secure random state
        state_token = secrets.token_urlsafe(32)
        
        # Create state data
        state_data = {
            "token": state_token,
            "provider": provider,
            "created_at": time.time(),
            "user_id": user_id,
            "tenant_id": tenant_id,
            "redirect_uri": redirect_uri,
            "additional_data": additional_data or {},
            "validation_hash": None
        }
        
        # Add validation hash to detect tampering
        validation_string = f"{state_token}:{provider}:{user_id}:{tenant_id}"
        state_data["validation_hash"] = hashlib.sha256(
            f"{validation_string}:{settings.SECRET_KEY}".encode()
        ).hexdigest()
        
        # Store in Redis with TTL
        key = f"oauth_state:{state_token}"
        
        try:
            # Use SET with NX (only set if not exists) to prevent overwrites
            success = self.redis_client.set(
                key,
                json.dumps(state_data),
                ex=self.state_ttl,
                nx=True  # Only set if key doesn't exist
            )
            
            if not success:
                # Extremely unlikely collision, generate new token
                logger.warning("OAuth state token collision detected, regenerating")
                return self.generate_state(
                    user_id, tenant_id, provider, redirect_uri, additional_data
                )
            
            logger.info(f"OAuth state generated for provider {provider}: {state_token[:8]}...")
            return state_token
            
        except Exception as e:
            logger.error(f"Failed to store OAuth state: {e}")
            raise RuntimeError("Failed to generate OAuth state")
    
    def validate_and_consume_state(
        self,
        state_token: str,
        provider: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate and atomically consume OAuth state token
        Prevents race conditions and replay attacks
        Returns (is_valid, state_data)
        """
        if not state_token:
            logger.warning("OAuth state validation attempted with empty token")
            return False, None
        
        key = f"oauth_state:{state_token}"
        
        # Use Lua script for atomic get-and-delete operation
        # This prevents race conditions where multiple requests try to use the same state
        lua_script = """
        local key = KEYS[1]
        local value = redis.call('get', key)
        if value then
            redis.call('del', key)
            return value
        else
            return nil
        end
        """
        
        try:
            # Atomically get and delete the state
            state_json = self.redis_client.eval(lua_script, 1, key)
            
            if not state_json:
                logger.warning(f"OAuth state not found or already consumed: {state_token[:8]}...")
                return False, None
            
            # Parse state data
            state_data = json.loads(state_json)
            
            # Verify state hasn't expired (double-check even though Redis TTL should handle this)
            created_at = state_data.get("created_at", 0)
            if time.time() - created_at > self.state_ttl:
                logger.warning(f"OAuth state expired: {state_token[:8]}...")
                return False, None
            
            # Verify provider matches if specified
            if provider and state_data.get("provider") != provider:
                logger.warning(
                    f"OAuth state provider mismatch: expected {provider}, "
                    f"got {state_data.get('provider')}"
                )
                return False, None
            
            # Verify validation hash
            validation_string = (
                f"{state_data['token']}:{state_data['provider']}:"
                f"{state_data['user_id']}:{state_data['tenant_id']}"
            )
            expected_hash = hashlib.sha256(
                f"{validation_string}:{settings.SECRET_KEY}".encode()
            ).hexdigest()
            
            if state_data.get("validation_hash") != expected_hash:
                logger.error(f"OAuth state validation hash mismatch for {state_token[:8]}...")
                return False, None
            
            logger.info(
                f"OAuth state validated and consumed for provider "
                f"{state_data['provider']}: {state_token[:8]}..."
            )
            
            return True, state_data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid OAuth state data format: {e}")
            return False, None
        except Exception as e:
            logger.error(f"OAuth state validation error: {e}")
            return False, None
    
    def cleanup_expired_states(self) -> int:
        """
        Clean up expired OAuth states (Redis TTL should handle this automatically)
        Returns number of states cleaned up
        """
        try:
            # Redis automatically expires keys with TTL, but we can scan for any orphaned keys
            cursor = 0
            cleaned = 0
            
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor,
                    match="oauth_state:*",
                    count=100
                )
                
                for key in keys:
                    # Check if key has TTL set
                    ttl = self.redis_client.ttl(key)
                    if ttl == -1:  # No TTL set (shouldn't happen)
                        self.redis_client.expire(key, 60)  # Set 1 minute TTL
                        cleaned += 1
                
                if cursor == 0:
                    break
            
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} orphaned OAuth state entries")
            
            return cleaned
            
        except Exception as e:
            logger.error(f"OAuth state cleanup error: {e}")
            return 0
    
    def get_state_info(self, state_token: str) -> Optional[Dict[str, Any]]:
        """
        Get OAuth state info without consuming it (for debugging only)
        Should not be used in production OAuth flows
        """
        if not state_token:
            return None
        
        key = f"oauth_state:{state_token}"
        
        try:
            state_json = self.redis_client.get(key)
            if state_json:
                return json.loads(state_json)
            return None
        except Exception as e:
            logger.error(f"Failed to get OAuth state info: {e}")
            return None


class OAuthNonceManager:
    """
    Manage nonces for OAuth providers that support them (additional security)
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL or "redis://localhost:6379"
        self.redis_client = None
        self.nonce_ttl = 600  # 10 minutes
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            self.redis_client.ping()
        except (RedisError, Exception) as e:
            logger.error(f"Redis connection failed for OAuth nonce: {e}")
            raise RuntimeError("OAuth nonce management requires Redis")
    
    def generate_nonce(self) -> str:
        """Generate a cryptographically secure nonce"""
        nonce = secrets.token_urlsafe(32)
        
        # Store nonce with TTL
        key = f"oauth_nonce:{nonce}"
        self.redis_client.set(key, "1", ex=self.nonce_ttl)
        
        return nonce
    
    def validate_and_consume_nonce(self, nonce: str) -> bool:
        """
        Validate and consume nonce (one-time use)
        Prevents replay attacks
        """
        if not nonce:
            return False
        
        key = f"oauth_nonce:{nonce}"
        
        # Atomic delete returns number of keys deleted
        deleted = self.redis_client.delete(key)
        
        return deleted == 1