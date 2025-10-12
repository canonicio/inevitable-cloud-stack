"""
Secure Cache Manager for Platform Forge
CRITICAL FIX: Addresses Cache Key Collision vulnerability (CVSS 7.5)
Implements tenant-isolated, collision-resistant caching
"""

import json
import pickle
import logging
from typing import Any, Optional, List, Dict, Union
from datetime import timedelta
from enum import Enum
import redis
from redis.exceptions import RedisError
import hashlib

from ..core.config import settings
from ..core.database import get_db
from .cache_security import CacheKeyGenerator, CacheSecurity, CacheAccessControl

logger = logging.getLogger(__name__)


class CacheBackend(Enum):
    """Supported cache backends"""
    REDIS = "redis"
    MEMORY = "memory"  # For testing/development
    DATABASE = "database"  # Fallback option


class SecureCacheManager:
    """
    Secure cache manager with tenant isolation and collision prevention
    
    CRITICAL SECURITY FIXES:
    1. Uses HMAC-SHA256 for key generation (not MD5)
    2. Enforces tenant isolation at cache level
    3. Prevents cache poisoning attacks
    4. Implements cache stampede prevention
    """
    
    def __init__(
        self,
        backend: CacheBackend = CacheBackend.REDIS,
        redis_url: Optional[str] = None,
        key_generator: Optional[CacheKeyGenerator] = None,
        enable_security: bool = True
    ):
        """
        Initialize secure cache manager
        
        Args:
            backend: Cache backend to use
            redis_url: Redis connection URL
            key_generator: Custom key generator (uses secure default)
            enable_security: Enable security features (integrity, access control)
        """
        self.backend = backend
        self.enable_security = enable_security
        
        # CRITICAL: Use secure key generator
        self.key_generator = key_generator or CacheKeyGenerator()
        self.security = CacheSecurity(self.key_generator)
        self.access_control = CacheAccessControl(self.key_generator)
        
        # Initialize backend
        if backend == CacheBackend.REDIS:
            self._init_redis(redis_url or settings.REDIS_URL)
        elif backend == CacheBackend.MEMORY:
            self._init_memory()
        elif backend == CacheBackend.DATABASE:
            self._init_database()
        else:
            raise ValueError(f"Unsupported cache backend: {backend}")
    
    def _init_redis(self, redis_url: str):
        """Initialize Redis backend"""
        try:
            self.redis_client = redis.from_url(
                redis_url,
                decode_responses=False,  # We'll handle encoding
                socket_keepalive=True,
                socket_keepalive_options={
                    1: 1,  # TCP_KEEPIDLE
                    2: 2,  # TCP_KEEPINTVL
                    3: 3,  # TCP_KEEPCNT
                }
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache backend initialized")
        except (RedisError, ConnectionError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            # Fall back to memory cache
            logger.warning("Falling back to memory cache backend")
            self.backend = CacheBackend.MEMORY
            self._init_memory()
    
    def _init_memory(self):
        """Initialize in-memory cache backend"""
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        logger.info("Memory cache backend initialized")
    
    def _init_database(self):
        """Initialize database cache backend"""
        # This would use a cache table in the database
        logger.info("Database cache backend initialized")
    
    def get(
        self,
        key: str,
        tenant_id: str,
        namespace: Optional[str] = None,
        default: Any = None
    ) -> Any:
        """
        Get value from cache with tenant isolation
        
        CRITICAL: Always requires tenant_id to prevent cross-tenant access
        """
        # Generate secure cache key
        cache_key = self.key_generator.generate_secure_key(
            prefix="cache",
            tenant_id=tenant_id,
            key=key,
            namespace=namespace
        )
        
        # Sanitize key to prevent injection
        cache_key = self.security.sanitize_cache_key(cache_key)
        
        try:
            if self.backend == CacheBackend.REDIS:
                raw_value = self.redis_client.get(cache_key)
                if raw_value is None:
                    return default
                    
                # Deserialize value
                value = self._deserialize(raw_value)
                
            elif self.backend == CacheBackend.MEMORY:
                value = self.memory_cache.get(cache_key, {}).get("value", default)
                
            else:  # DATABASE
                value = self._get_from_database(cache_key, default)
            
            # Verify integrity and tenant ownership if security enabled
            if self.enable_security and value != default:
                if isinstance(value, dict) and "_tenant_id" in value:
                    if not self.security.verify_integrity(value, tenant_id):
                        logger.warning(f"Cache integrity check failed for key: {key}")
                        return default
                    # Extract original value
                    if "value" in value:
                        value = value["value"]
                    else:
                        # Remove metadata
                        value = {k: v for k, v in value.items() 
                               if not k.startswith("_")}
            
            return value
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return default
    
    def set(
        self,
        key: str,
        value: Any,
        tenant_id: str,
        ttl: Optional[int] = None,
        namespace: Optional[str] = None
    ) -> bool:
        """
        Set value in cache with tenant isolation
        
        CRITICAL: Always requires tenant_id to maintain isolation
        """
        # Generate secure cache key
        cache_key = self.key_generator.generate_secure_key(
            prefix="cache",
            tenant_id=tenant_id,
            key=key,
            namespace=namespace
        )
        
        # Sanitize key
        cache_key = self.security.sanitize_cache_key(cache_key)
        
        # Add integrity metadata if security enabled
        if self.enable_security:
            value = self.security.add_integrity_check(value, tenant_id)
        
        try:
            if self.backend == CacheBackend.REDIS:
                # Serialize value
                serialized = self._serialize(value)
                
                # Set with optional TTL
                if ttl:
                    return bool(self.redis_client.setex(cache_key, ttl, serialized))
                else:
                    return bool(self.redis_client.set(cache_key, serialized))
                    
            elif self.backend == CacheBackend.MEMORY:
                self.memory_cache[cache_key] = {
                    "value": value,
                    "ttl": ttl,
                    "timestamp": time.time() if ttl else None
                }
                return True
                
            else:  # DATABASE
                return self._set_in_database(cache_key, value, ttl)
                
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    def delete(
        self,
        key: str,
        tenant_id: str,
        namespace: Optional[str] = None
    ) -> bool:
        """
        Delete value from cache with tenant isolation
        """
        # Generate secure cache key
        cache_key = self.key_generator.generate_secure_key(
            prefix="cache",
            tenant_id=tenant_id,
            key=key,
            namespace=namespace
        )
        
        # Sanitize key
        cache_key = self.security.sanitize_cache_key(cache_key)
        
        try:
            if self.backend == CacheBackend.REDIS:
                return bool(self.redis_client.delete(cache_key))
            elif self.backend == CacheBackend.MEMORY:
                if cache_key in self.memory_cache:
                    del self.memory_cache[cache_key]
                    return True
                return False
            else:  # DATABASE
                return self._delete_from_database(cache_key)
                
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    def clear_tenant_cache(self, tenant_id: str) -> int:
        """
        Clear all cache entries for a specific tenant
        
        CRITICAL: Only clears the specified tenant's data
        """
        pattern = f"cache:{tenant_id}:*"
        cleared_count = 0
        
        try:
            if self.backend == CacheBackend.REDIS:
                # Use SCAN to avoid blocking on large datasets
                cursor = 0
                while True:
                    cursor, keys = self.redis_client.scan(
                        cursor,
                        match=pattern,
                        count=100
                    )
                    if keys:
                        # Only delete keys that truly belong to this tenant
                        tenant_keys = self.access_control.filter_keys_by_tenant(
                            [k.decode() if isinstance(k, bytes) else k for k in keys],
                            tenant_id
                        )
                        if tenant_keys:
                            cleared_count += self.redis_client.delete(*tenant_keys)
                    
                    if cursor == 0:
                        break
                        
            elif self.backend == CacheBackend.MEMORY:
                keys_to_delete = [
                    k for k in self.memory_cache.keys()
                    if self.access_control.can_access(tenant_id, k)
                ]
                for key in keys_to_delete:
                    del self.memory_cache[key]
                    cleared_count += 1
                    
            else:  # DATABASE
                cleared_count = self._clear_database_cache(tenant_id)
                
        except Exception as e:
            logger.error(f"Failed to clear tenant cache for {tenant_id}: {e}")
            
        logger.info(f"Cleared {cleared_count} cache entries for tenant {tenant_id}")
        return cleared_count
    
    def get_with_lock(
        self,
        key: str,
        tenant_id: str,
        generator_func: callable,
        ttl: int = 300,
        lock_timeout: int = 5,
        namespace: Optional[str] = None
    ) -> Any:
        """
        Get value from cache with stampede prevention
        
        If cache miss, acquires lock before regenerating to prevent
        multiple simultaneous regenerations (cache stampede)
        """
        # Try to get from cache first
        value = self.get(key, tenant_id, namespace)
        if value is not None:
            return value
        
        # Generate lock key
        lock_key = self.security.prevent_cache_stampede(key)
        lock_acquired = False
        
        try:
            if self.backend == CacheBackend.REDIS:
                # Try to acquire lock
                lock_acquired = self.redis_client.set(
                    lock_key,
                    "locked",
                    nx=True,  # Only set if not exists
                    ex=lock_timeout
                )
                
                if not lock_acquired:
                    # Someone else is regenerating, wait and retry
                    import time
                    time.sleep(0.1)
                    value = self.get(key, tenant_id, namespace)
                    if value is not None:
                        return value
                    
                    # Still no value, generate anyway (lock may have expired)
                    lock_acquired = True
            else:
                # For non-Redis backends, always regenerate
                lock_acquired = True
            
            if lock_acquired:
                # Generate new value
                value = generator_func()
                
                # Store in cache
                self.set(key, value, tenant_id, ttl, namespace)
                
                return value
                
        finally:
            # Release lock if we acquired it
            if lock_acquired and self.backend == CacheBackend.REDIS:
                try:
                    self.redis_client.delete(lock_key)
                except:
                    pass
        
        # Fallback: generate without caching
        return generator_func()
    
    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            # Try JSON first (more portable)
            return json.dumps(value).encode()
        except (TypeError, ValueError):
            # Fall back to pickle for complex objects
            return pickle.dumps(value)
    
    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            # Try JSON first
            return json.loads(data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fall back to pickle
            return pickle.loads(data)
    
    def _get_from_database(self, key: str, default: Any) -> Any:
        """Get value from database cache table"""
        # Implementation would query a cache table
        # For now, return default
        return default
    
    def _set_in_database(self, key: str, value: Any, ttl: Optional[int]) -> bool:
        """Set value in database cache table"""
        # Implementation would insert/update cache table
        # For now, return success
        return True
    
    def _delete_from_database(self, key: str) -> bool:
        """Delete value from database cache table"""
        # Implementation would delete from cache table
        # For now, return success
        return True
    
    def _clear_database_cache(self, tenant_id: str) -> int:
        """Clear tenant cache from database"""
        # Implementation would delete all tenant entries
        # For now, return 0
        return 0


# Global cache instance
_cache_instance: Optional[SecureCacheManager] = None


def get_cache() -> SecureCacheManager:
    """Get global cache instance"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = SecureCacheManager()
    return _cache_instance


import time