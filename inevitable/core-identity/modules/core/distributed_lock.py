"""
Distributed Lock Module
Addresses RISK-H002: Password Reset Race Condition
"""
import redis
import time
import uuid
import logging
from contextlib import contextmanager
from typing import Optional
from fastapi import HTTPException

logger = logging.getLogger(__name__)


class DistributedLock:
    """Redis-based distributed lock with fallback"""
    
    def __init__(self, redis_client: redis.Redis, key: str, timeout: int = 10):
        self.redis = redis_client
        self.key = f"lock:{key}"
        self.timeout = timeout
        self.identifier = str(uuid.uuid4())
        self.acquired = False
    
    def acquire(self, blocking: bool = True, timeout: Optional[int] = None) -> bool:
        """Acquire lock with optional blocking"""
        timeout = timeout or self.timeout
        end_time = time.time() + timeout if blocking else 0
        
        while True:
            try:
                # Try to acquire lock
                if self.redis.set(self.key, self.identifier, nx=True, ex=self.timeout):
                    self.acquired = True
                    logger.debug(f"Acquired lock: {self.key} with identifier: {self.identifier}")
                    return True
            except redis.RedisError as e:
                logger.error(f"Redis error during lock acquisition: {e}")
                # If Redis is down, allow operation to continue with warning
                logger.warning(f"Redis unavailable, proceeding without lock for: {self.key}")
                return True
            
            # Non-blocking mode or timeout
            if not blocking or time.time() > end_time:
                logger.warning(f"Failed to acquire lock: {self.key} (timeout)")
                return False
            
            # Small sleep to prevent spinning
            time.sleep(0.001)
    
    def release(self) -> bool:
        """Release lock if we own it"""
        if not self.acquired:
            return True
        
        # Lua script for atomic check-and-delete
        lua_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """
        
        try:
            result = bool(self.redis.eval(lua_script, 1, self.key, self.identifier))
            if result:
                logger.debug(f"Released lock: {self.key}")
            else:
                logger.warning(f"Lock was not owned by this process: {self.key}")
            self.acquired = False
            return result
        except redis.RedisError as e:
            logger.error(f"Redis error during lock release: {e}")
            self.acquired = False
            # Return True to avoid blocking the caller
            return True
    
    def extend(self, additional_time: int) -> bool:
        """Extend lock expiration if we own it"""
        if not self.acquired:
            return False
        
        lua_script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        
        try:
            return bool(self.redis.eval(lua_script, 1, self.key, self.identifier, additional_time))
        except redis.RedisError as e:
            logger.error(f"Redis error during lock extension: {e}")
            return False
    
    def is_locked(self) -> bool:
        """Check if lock exists (regardless of owner)"""
        try:
            return bool(self.redis.exists(self.key))
        except redis.RedisError:
            return False
    
    def get_lock_info(self) -> dict:
        """Get information about the current lock"""
        try:
            value = self.redis.get(self.key)
            ttl = self.redis.ttl(self.key)
            
            return {
                "exists": value is not None,
                "owned_by_us": value and value.decode() == self.identifier,
                "identifier": value.decode() if value else None,
                "ttl": ttl,
                "our_identifier": self.identifier
            }
        except redis.RedisError as e:
            logger.error(f"Redis error getting lock info: {e}")
            return {
                "exists": False,
                "owned_by_us": False,
                "identifier": None,
                "ttl": -1,
                "our_identifier": self.identifier,
                "error": str(e)
            }


@contextmanager
def distributed_lock(redis_client: redis.Redis, key: str, timeout: int = 10, blocking: bool = True):
    """Context manager for distributed locking"""
    lock = DistributedLock(redis_client, key, timeout)
    acquired = False
    
    try:
        acquired = lock.acquire(blocking=blocking, timeout=timeout)
        if not acquired:
            raise HTTPException(
                status_code=429,
                detail="Resource is currently being processed. Please try again later."
            )
        yield lock
    finally:
        if acquired:
            lock.release()


class PasswordResetTokenManager:
    """
    Secure password reset token manager with atomic operations
    Prevents race conditions in token consumption
    """
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.token_ttl = 3600  # 1 hour
    
    def create_token(self, user_id: str, token: str) -> bool:
        """Create a password reset token"""
        token_key = f"password_reset:{token}"
        
        token_data = {
            "user_id": user_id,
            "created_at": int(time.time()),
            "used": "false"
        }
        
        try:
            # Set token with expiration
            return bool(self.redis.hset(token_key, mapping=token_data)) and \
                   bool(self.redis.expire(token_key, self.token_ttl))
        except redis.RedisError as e:
            logger.error(f"Failed to create password reset token: {e}")
            return False
    
    def consume_token(self, token: str) -> Optional[dict]:
        """
        Atomically consume a password reset token
        Returns token data if successful, None if invalid/expired/already used
        """
        token_key = f"password_reset:{token}"
        
        # Lua script for atomic get-and-delete operation
        lua_script = """
        local token_key = KEYS[1]
        
        -- Check if token exists
        if redis.call("EXISTS", token_key) == 0 then
            return nil
        end
        
        -- Get all token data
        local token_data = redis.call("HGETALL", token_key)
        
        if #token_data == 0 then
            return nil
        end
        
        -- Parse token data into a table
        local data = {}
        for i = 1, #token_data, 2 do
            data[token_data[i]] = token_data[i + 1]
        end
        
        -- Check if token is already used
        if data["used"] == "true" then
            -- Token already consumed
            return nil
        end
        
        -- Delete token immediately (atomic consumption)
        local deleted = redis.call("DEL", token_key)
        
        if deleted == 1 then
            -- Return token data as JSON-like string
            return cjson.encode(data)
        else
            return nil
        end
        """
        
        try:
            result = self.redis.eval(lua_script, 1, token_key)
            
            if result is None:
                return None
            
            # Parse the result
            import json
            token_data = json.loads(result.decode() if isinstance(result, bytes) else result)
            
            # Validate token age
            created_at = int(token_data.get("created_at", 0))
            if time.time() - created_at > self.token_ttl:
                logger.warning(f"Expired password reset token accessed: {token}")
                return None
            
            return token_data
            
        except redis.RedisError as e:
            logger.error(f"Redis error during token consumption: {e}")
            return None
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Error parsing token data: {e}")
            return None
    
    def is_token_valid(self, token: str) -> bool:
        """Check if token exists and is valid (non-destructive)"""
        token_key = f"password_reset:{token}"
        
        try:
            if not self.redis.exists(token_key):
                return False
            
            token_data = self.redis.hgetall(token_key)
            
            if not token_data:
                return False
            
            # Check if already used
            if token_data.get(b"used", b"false").decode() == "true":
                return False
            
            # Check expiration
            created_at = int(token_data.get(b"created_at", b"0").decode())
            if time.time() - created_at > self.token_ttl:
                return False
            
            return True
            
        except redis.RedisError as e:
            logger.error(f"Redis error checking token validity: {e}")
            return False
    
    def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all password reset tokens for a user"""
        try:
            # Find all tokens for the user
            pattern = "password_reset:*"
            revoked_count = 0
            
            for key in self.redis.scan_iter(match=pattern):
                token_data = self.redis.hgetall(key)
                if token_data and token_data.get(b"user_id", b"").decode() == user_id:
                    self.redis.delete(key)
                    revoked_count += 1
            
            return revoked_count
            
        except redis.RedisError as e:
            logger.error(f"Redis error revoking user tokens: {e}")
            return 0
    
    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens (called periodically)"""
        try:
            pattern = "password_reset:*"
            cleaned_count = 0
            current_time = time.time()
            
            for key in self.redis.scan_iter(match=pattern):
                token_data = self.redis.hgetall(key)
                if token_data:
                    created_at = int(token_data.get(b"created_at", b"0").decode())
                    if current_time - created_at > self.token_ttl:
                        self.redis.delete(key)
                        cleaned_count += 1
            
            return cleaned_count
            
        except redis.RedisError as e:
            logger.error(f"Redis error during token cleanup: {e}")
            return 0


def get_token_manager(redis_client: redis.Redis) -> PasswordResetTokenManager:
    """Get password reset token manager instance"""
    return PasswordResetTokenManager(redis_client)