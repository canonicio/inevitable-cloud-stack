"""
Rate limiting for authentication endpoints
Addresses HIGH-001: Insufficient Rate Limiting on Authentication Endpoints
"""
import time
import hashlib
from typing import Dict, Optional, Tuple
from fastapi import Request, HTTPException, status
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Enhanced rate limiter with multiple strategies and cleanup"""
    
    def __init__(self):
        # Separate stores for different endpoint types
        self._login_attempts: Dict[str, list] = defaultdict(list)
        self._registration_attempts: Dict[str, list] = defaultdict(list)
        self._password_reset_attempts: Dict[str, list] = defaultdict(list)
        
        # Track failed login attempts for security
        self._failed_login_attempts: Dict[str, int] = defaultdict(int)
        
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
        
        # Start cleanup task
        self._cleanup_task = None
        
    async def start_cleanup(self):
        """Start background cleanup task"""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Periodically clean up old entries to prevent memory exhaustion"""
        while True:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                await self._cleanup_old_entries()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    async def _cleanup_old_entries(self):
        """Remove entries older than window"""
        async with self._lock:
            current_time = time.time()
            
            # Clean up each store
            for store in [self._login_attempts, self._registration_attempts, 
                         self._password_reset_attempts]:
                keys_to_remove = []
                for key, timestamps in store.items():
                    # Keep only recent timestamps
                    store[key] = [t for t in timestamps if current_time - t < 3600]
                    if not store[key]:
                        keys_to_remove.append(key)
                
                # Remove empty keys
                for key in keys_to_remove:
                    del store[key]
            
            # Clean up failed attempts older than 24 hours
            keys_to_remove = []
            for key in self._failed_login_attempts:
                # Extract timestamp from key if it includes one
                if ':' in key:
                    _, timestamp_str = key.rsplit(':', 1)
                    try:
                        timestamp = float(timestamp_str)
                        if current_time - timestamp > 86400:  # 24 hours
                            keys_to_remove.append(key)
                    except ValueError:
                        pass
            
            for key in keys_to_remove:
                del self._failed_login_attempts[key]
    
    def _get_identifier(self, request: Request) -> str:
        """
        Enhanced identifier generation to prevent distributed attack bypasses
        Addresses MEDIUM-001: Insufficient Rate Limiting on Authentication
        """
        # Get the most reliable IP address
        forwarded_for = request.headers.get("X-Forwarded-For")
        real_ip = request.headers.get("X-Real-IP")
        
        if forwarded_for:
            # Take the first IP (original client) and validate
            client_ip = forwarded_for.split(",")[0].strip()
            # Validate IP format to prevent header injection
            import ipaddress
            try:
                ipaddress.ip_address(client_ip)
            except ValueError:
                client_ip = "invalid_ip"
        elif real_ip:
            client_ip = real_ip.strip()
            try:
                ipaddress.ip_address(client_ip)
            except ValueError:
                client_ip = "invalid_ip"
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        # Create multiple identifiers for layered rate limiting
        identifiers = [client_ip]
        
        # Add subnet-based limiting (for IPv4 /24, IPv6 /64)
        try:
            ip = ipaddress.ip_address(client_ip)
            if isinstance(ip, ipaddress.IPv4Address):
                subnet = str(ipaddress.IPv4Network(f"{client_ip}/24", strict=False).network_address)
                identifiers.append(f"subnet:{subnet}")
            elif isinstance(ip, ipaddress.IPv6Address):
                subnet = str(ipaddress.IPv6Network(f"{client_ip}/64", strict=False).network_address)
                identifiers.append(f"subnet:{subnet}")
        except ValueError:
            pass
        
        # Add user agent fingerprint to prevent simple UA rotation
        user_agent = request.headers.get("User-Agent", "")
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:12]
        identifiers.append(f"ua:{ua_hash}")
        
        # Add TLS fingerprint if available (helps identify same client)
        if hasattr(request, 'client') and hasattr(request.client, 'host'):
            tls_info = request.headers.get("X-TLS-Cipher", "")
            if tls_info:
                tls_hash = hashlib.md5(tls_info.encode()).hexdigest()[:8]
                identifiers.append(f"tls:{tls_hash}")
        
        # Return primary identifier (will check others separately)
        return f"{client_ip}:{ua_hash}"
    
    def _get_all_identifiers(self, request: Request) -> list:
        """Get all identifiers for comprehensive rate limiting"""
        primary = self._get_identifier(request)
        
        # Extract components for additional checks
        client_ip = primary.split(":")[0]
        
        identifiers = [primary]
        
        # Add subnet identifier
        try:
            import ipaddress
            ip = ipaddress.ip_address(client_ip)
            if isinstance(ip, ipaddress.IPv4Address):
                subnet = str(ipaddress.IPv4Network(f"{client_ip}/24", strict=False).network_address)
                identifiers.append(f"subnet:{subnet}")
        except (ValueError, AttributeError):
            pass
        
        return identifiers
    
    async def check_rate_limit(
        self, 
        request: Request, 
        endpoint_type: str,
        max_requests: int,
        window_seconds: int
    ) -> Tuple[bool, Optional[int]]:
        """
        Enhanced rate limit check with multiple identifier validation
        Addresses MEDIUM-001: Prevents distributed attack bypasses
        Returns: (is_allowed, retry_after_seconds)
        """
        all_identifiers = self._get_all_identifiers(request)
        current_time = time.time()
        
        async with self._lock:
            # Select appropriate store
            if endpoint_type == "login":
                store = self._login_attempts
                # Stricter limits for login attempts
                subnet_limit = max(2, max_requests // 3)  # Subnet gets 1/3 of individual limit
            elif endpoint_type == "register":
                store = self._registration_attempts
                subnet_limit = max(1, max_requests // 2)  # Even stricter for registration
            elif endpoint_type == "password_reset":
                store = self._password_reset_attempts
                subnet_limit = max(1, max_requests // 2)
            else:
                raise ValueError(f"Unknown endpoint type: {endpoint_type}")
            
            max_retry_after = 0
            
            # Check each identifier
            for identifier in all_identifiers:
                # Use different limits for subnet vs individual
                if identifier.startswith("subnet:"):
                    current_limit = subnet_limit
                else:
                    current_limit = max_requests
                
                # Get timestamps for this identifier
                timestamps = store[identifier]
                
                # Remove old timestamps outside window
                timestamps = [t for t in timestamps if current_time - t < window_seconds]
                store[identifier] = timestamps
                
                # Check if limit exceeded for this identifier
                if len(timestamps) >= current_limit:
                    # Calculate retry after
                    oldest_timestamp = min(timestamps)
                    retry_after = int(window_seconds - (current_time - oldest_timestamp))
                    max_retry_after = max(max_retry_after, retry_after)
                    
                    # Log the rate limit hit with identifier type
                    logger.warning(
                        f"Rate limit exceeded for {endpoint_type}: "
                        f"identifier={identifier}, limit={current_limit}, "
                        f"requests={len(timestamps)}, retry_after={retry_after}"
                    )
            
            # If any identifier is rate limited, deny the request
            if max_retry_after > 0:
                return False, max_retry_after
            
            # Add current timestamp to all identifiers
            for identifier in all_identifiers:
                store[identifier].append(current_time)
            
            return True, None
    
    async def record_failed_login(self, request: Request, username: str):
        """Record failed login attempt for security tracking"""
        identifier = self._get_identifier(request)
        key = f"{identifier}:{username}:{int(time.time())}"
        
        async with self._lock:
            self._failed_login_attempts[key] += 1
            
            # Check for brute force pattern
            failed_count = sum(
                1 for k, v in self._failed_login_attempts.items()
                if k.startswith(f"{identifier}:{username}") and v > 0
            )
            
            if failed_count > 10:
                logger.warning(
                    f"Potential brute force attack detected: {identifier} -> {username}"
                )
    
    def get_limits(self, endpoint_type: str) -> Tuple[int, int]:
        """Get rate limits for endpoint type"""
        limits = {
            "login": (5, 60),  # 5 attempts per minute
            "register": (3, 300),  # 3 registrations per 5 minutes
            "password_reset": (3, 900),  # 3 reset requests per 15 minutes
            "verify_token": (10, 60),  # 10 verifications per minute
        }
        return limits.get(endpoint_type, (10, 60))


# Global rate limiter instance
_rate_limiter = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


async def rate_limit_middleware(request: Request, endpoint_type: str):
    """
    Rate limiting middleware for authentication endpoints
    Use as dependency: Depends(lambda r: rate_limit_middleware(r, "login"))
    """
    rate_limiter = get_rate_limiter()
    
    # Ensure cleanup is running
    await rate_limiter.start_cleanup()
    
    # Get limits for this endpoint
    max_requests, window_seconds = rate_limiter.get_limits(endpoint_type)
    
    # Check rate limit
    is_allowed, retry_after = await rate_limiter.check_rate_limit(
        request, endpoint_type, max_requests, window_seconds
    )
    
    if not is_allowed:
        # Log rate limit violation
        logger.warning(
            f"Rate limit exceeded for {endpoint_type} from {rate_limiter._get_identifier(request)}"
        )
        
        # Return 429 with retry information
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )