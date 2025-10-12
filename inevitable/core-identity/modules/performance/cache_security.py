"""
Cache Security Module
CRITICAL FIX: Addresses Cache Key Collision vulnerability (CVSS 7.5)
Uses HMAC-SHA256 instead of MD5 for cache key generation
"""

import hmac
import hashlib
import json
import time
from typing import Any, Optional, Dict
from datetime import datetime, timezone
import logging

from ..core.config import settings
from ..core.security import SecurityUtils

logger = logging.getLogger(__name__)


class CacheKeyGenerator:
    """
    Secure cache key generation with collision resistance
    CRITICAL FIX: Uses HMAC-SHA256 instead of MD5 to prevent cache key collisions
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """Initialize with secret key for HMAC"""
        self.secret_key = (secret_key or settings.SECRET_KEY).encode()
        
    def generate_secure_key(
        self, 
        prefix: str, 
        tenant_id: str, 
        key: str,
        namespace: Optional[str] = None
    ) -> str:
        """
        Generate a secure cache key using HMAC-SHA256
        
        CRITICAL FIX: This replaces the vulnerable MD5 implementation
        that allowed cache key collisions and cross-tenant data exposure
        
        Args:
            prefix: Cache key prefix (e.g., 'user', 'session')
            tenant_id: Tenant identifier for isolation
            key: The actual cache key
            namespace: Optional namespace for additional isolation
            
        Returns:
            Secure cache key that is collision-resistant
        """
        # Validate tenant_id to prevent injection
        if not self._validate_tenant_id(tenant_id):
            raise ValueError(f"Invalid tenant_id: {tenant_id}")
        
        # Build the cache key components
        components = [prefix, tenant_id]
        if namespace:
            components.append(namespace)
        components.append(key)
        
        # Create the base key
        base_key = ":".join(components)
        
        # CRITICAL FIX: Use HMAC-SHA256 instead of MD5
        # This prevents collision attacks and ensures cryptographic security
        secure_hash = hmac.new(
            self.secret_key,
            base_key.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Return a formatted cache key with hash
        return f"{prefix}:{tenant_id}:{secure_hash[:16]}"
    
    def _validate_tenant_id(self, tenant_id: str) -> bool:
        """Validate tenant ID format to prevent injection"""
        if not tenant_id or not isinstance(tenant_id, str):
            return False
        
        # Only allow alphanumeric, hyphens, and underscores
        import re
        return bool(re.match(r'^[a-zA-Z0-9_-]{1,64}$', tenant_id))
    
    def generate_permission_key(self, tenant_id: str, user_id: str, resource: str) -> str:
        """Generate cache key for permission checks"""
        return self.generate_secure_key(
            prefix="perm",
            tenant_id=tenant_id,
            key=f"{user_id}:{resource}",
            namespace="rbac"
        )
    
    def generate_session_key(self, tenant_id: str, session_id: str) -> str:
        """Generate cache key for session data"""
        return self.generate_secure_key(
            prefix="sess",
            tenant_id=tenant_id,
            key=session_id,
            namespace="auth"
        )
    
    def generate_rate_limit_key(self, tenant_id: str, identifier: str, endpoint: str) -> str:
        """Generate cache key for rate limiting"""
        return self.generate_secure_key(
            prefix="rate",
            tenant_id=tenant_id,
            key=f"{identifier}:{endpoint}",
            namespace="limit"
        )


class CacheSecurity:
    """
    Cache security features to prevent poisoning and ensure data integrity
    """
    
    def __init__(self, key_generator: Optional[CacheKeyGenerator] = None):
        """Initialize cache security"""
        self.key_generator = key_generator or CacheKeyGenerator()
        
    def validate_cache_value(self, value: Any, expected_tenant: str) -> bool:
        """
        Validate that cached value belongs to the expected tenant
        Prevents cache poisoning attacks
        """
        if not value:
            return True
        
        # If value is a dict with tenant_id, validate it
        if isinstance(value, dict) and 'tenant_id' in value:
            return value['tenant_id'] == expected_tenant
        
        # If value is a string that looks like JSON, parse and check
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict) and 'tenant_id' in parsed:
                    return parsed['tenant_id'] == expected_tenant
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Default to allowing if we can't determine tenant
        return True
    
    def add_integrity_check(self, value: Any, tenant_id: str) -> Dict[str, Any]:
        """
        Add integrity and ownership metadata to cached values
        """
        # Convert value to serializable format
        if isinstance(value, dict):
            data = value.copy()
        else:
            data = {"value": value}
        
        # Add security metadata
        data.update({
            "_tenant_id": tenant_id,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_integrity": self._calculate_integrity_hash(value, tenant_id)
        })
        
        return data
    
    def verify_integrity(self, cached_data: Dict[str, Any], tenant_id: str) -> bool:
        """
        Verify the integrity of cached data
        """
        if not isinstance(cached_data, dict):
            return False
        
        # Check tenant ownership
        if cached_data.get("_tenant_id") != tenant_id:
            logger.warning(f"Cache tenant mismatch: expected {tenant_id}, got {cached_data.get('_tenant_id')}")
            return False
        
        # Verify integrity hash
        if "_integrity" in cached_data:
            # Extract original value
            original_value = cached_data.get("value")
            if "value" not in cached_data:
                # If no explicit value key, remove metadata to get original
                original_value = {k: v for k, v in cached_data.items() 
                                if not k.startswith("_")}
            
            expected_hash = self._calculate_integrity_hash(original_value, tenant_id)
            if cached_data["_integrity"] != expected_hash:
                logger.warning("Cache integrity check failed")
                return False
        
        # Check timestamp freshness (optional)
        if "_timestamp" in cached_data:
            try:
                timestamp = datetime.fromisoformat(cached_data["_timestamp"])
                age = (datetime.now(timezone.utc) - timestamp).total_seconds()
                
                # Warn if cache is very old (>24 hours)
                if age > 86400:
                    logger.warning(f"Cache entry is {age/3600:.1f} hours old")
            except (ValueError, TypeError):
                pass
        
        return True
    
    def _calculate_integrity_hash(self, value: Any, tenant_id: str) -> str:
        """Calculate integrity hash for cached value"""
        # Serialize the value deterministically
        if isinstance(value, dict):
            serialized = json.dumps(value, sort_keys=True)
        else:
            serialized = str(value)
        
        # Create HMAC with tenant context
        integrity_data = f"{tenant_id}:{serialized}".encode()
        return hmac.new(
            settings.SECRET_KEY.encode(),
            integrity_data,
            hashlib.sha256
        ).hexdigest()[:32]
    
    def prevent_cache_stampede(self, key: str, lock_timeout: int = 5) -> str:
        """
        Generate a lock key to prevent cache stampede
        Multiple requests won't regenerate the same cache simultaneously
        """
        return f"lock:{key}"
    
    def sanitize_cache_key(self, key: str) -> str:
        """
        Sanitize cache key to prevent injection attacks
        """
        # Remove any control characters or special Redis commands
        dangerous_patterns = [
            '\r', '\n', '\x00',  # Control characters
            'EVAL', 'SCRIPT',    # Redis scripting commands
            'CONFIG', 'FLUSHDB', # Dangerous Redis commands
            'SHUTDOWN', 'SAVE'   # System commands
        ]
        
        sanitized = key
        for pattern in dangerous_patterns:
            sanitized = sanitized.replace(pattern, '')
        
        # Limit key length to prevent DoS
        max_length = 250  # Redis key limit is 512MB but we're conservative
        if len(sanitized) > max_length:
            # Hash long keys to maintain uniqueness
            key_hash = hashlib.sha256(sanitized.encode()).hexdigest()
            sanitized = f"{sanitized[:100]}:{key_hash}"
        
        return sanitized


class CacheAccessControl:
    """
    Access control for cache operations
    Ensures users can only access their tenant's cached data
    """
    
    def __init__(self, key_generator: CacheKeyGenerator):
        self.key_generator = key_generator
        
    def can_access(self, user_tenant: str, cache_key: str) -> bool:
        """
        Check if a user from a given tenant can access a cache key
        """
        # Extract tenant from cache key
        try:
            parts = cache_key.split(":")
            if len(parts) >= 2:
                key_tenant = parts[1]
                return key_tenant == user_tenant
        except (IndexError, AttributeError):
            pass
        
        # Deny by default
        return False
    
    def filter_keys_by_tenant(self, keys: list, tenant_id: str) -> list:
        """
        Filter a list of cache keys to only those accessible by tenant
        """
        return [key for key in keys if self.can_access(tenant_id, key)]