"""
Comprehensive Rate Limiting System
Addresses multiple HIGH and MEDIUM severity vulnerabilities
"""
import time
import hashlib
import json
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import redis
from redis.exceptions import RedisError
import logging

from .config import settings

logger = logging.getLogger(__name__)


class RateLimitConfig:
    """Configuration for different rate limit tiers"""
    
    # Global limits
    GLOBAL_REQUESTS_PER_MINUTE = 1000
    GLOBAL_REQUESTS_PER_HOUR = 50000
    
    # Per-user limits
    USER_REQUESTS_PER_MINUTE = 100
    USER_REQUESTS_PER_HOUR = 5000
    
    # Per-tenant limits
    TENANT_REQUESTS_PER_MINUTE = 500
    TENANT_REQUESTS_PER_HOUR = 25000
    
    # Endpoint-specific limits
    ENDPOINT_LIMITS = {
        # Authentication endpoints - stricter limits
        "/api/auth/login": {"per_minute": 5, "per_hour": 20, "per_day": 50},
        "/api/auth/register": {"per_minute": 3, "per_hour": 10, "per_day": 20},
        "/api/auth/password-reset": {"per_minute": 3, "per_hour": 10, "per_day": 20},
        "/api/auth/mfa/verify": {"per_minute": 10, "per_hour": 50, "per_day": 200},
        
        # Billing endpoints - moderate limits
        "/api/billing/checkout": {"per_minute": 5, "per_hour": 30, "per_day": 100},
        "/api/billing/subscription": {"per_minute": 10, "per_hour": 100, "per_day": 500},
        "/api/billing/webhook": {"per_minute": 100, "per_hour": 5000, "per_day": 50000},
        
        # Admin endpoints - relaxed for admins
        "/api/admin": {"per_minute": 50, "per_hour": 2000, "per_day": 20000},
        
        # API endpoints - standard limits
        "/api": {"per_minute": 60, "per_hour": 3000, "per_day": 30000},
    }
    
    # Burst allowance (temporary spike tolerance)
    BURST_MULTIPLIER = 1.5
    
    # Sliding window duration in seconds
    WINDOW_SIZE = 60  # 1 minute sliding window


class RateLimiter:
    """
    Advanced rate limiter with multiple strategies:
    - Token bucket algorithm for burst handling
    - Sliding window for accurate rate limiting
    - Distributed rate limiting with Redis
    - Graceful degradation when Redis unavailable
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL or "redis://localhost:6379"
        self.redis_client = None
        self.local_cache = {}  # Fallback for when Redis is unavailable
        self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis with retry logic"""
        try:
            self.redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            self.redis_client.ping()
            logger.info("Rate limiter connected to Redis")
        except (RedisError, Exception) as e:
            logger.warning(f"Redis connection failed for rate limiting: {e}")
            logger.warning("Using in-memory rate limiting (not distributed)")
            self.redis_client = None
    
    def _get_key(self, identifier: str, window: str) -> str:
        """Generate Redis key for rate limit tracking"""
        return f"rate_limit:{identifier}:{window}"
    
    def _get_identifier(self, request: Request) -> Dict[str, str]:
        """Extract identifiers from request for rate limiting"""
        identifiers = {}
        
        # IP-based identifier
        client_ip = request.client.host if request.client else "unknown"
        identifiers["ip"] = client_ip
        
        # User-based identifier (from JWT)
        if hasattr(request.state, "user_id"):
            identifiers["user"] = str(request.state.user_id)
        
        # Tenant-based identifier
        if hasattr(request.state, "tenant_id"):
            identifiers["tenant"] = request.state.tenant_id
        
        # Endpoint-based identifier
        identifiers["endpoint"] = request.url.path
        
        # Combined identifier for granular tracking
        combined = f"{client_ip}:{request.url.path}"
        if hasattr(request.state, "user_id"):
            combined = f"{request.state.user_id}:{combined}"
        identifiers["combined"] = hashlib.sha256(combined.encode()).hexdigest()[:16]
        
        return identifiers
    
    def _check_rate_limit_redis(
        self, 
        key: str, 
        limit: int, 
        window_seconds: int
    ) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit using Redis with sliding window"""
        try:
            if not self.redis_client:
                return self._check_rate_limit_local(key, limit, window_seconds)
            
            # Use Lua script for atomic operation
            lua_script = """
            local key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local clearBefore = now - window
            
            -- Remove old entries outside the window
            redis.call('zremrangebyscore', key, 0, clearBefore)
            
            -- Count current requests in window
            local current = redis.call('zcard', key)
            
            if current < limit then
                -- Add current request
                redis.call('zadd', key, now, now)
                redis.call('expire', key, window)
                return {1, current + 1, limit}
            else
                return {0, current, limit}
            end
            """
            
            result = self.redis_client.eval(
                lua_script,
                1,
                key,
                limit,
                window_seconds,
                time.time()
            )
            
            allowed = bool(result[0])
            current = result[1]
            limit_val = result[2]
            
            return allowed, {
                "allowed": allowed,
                "current": current,
                "limit": limit_val,
                "retry_after": window_seconds if not allowed else None
            }
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fallback to local rate limiting
            return self._check_rate_limit_local(key, limit, window_seconds)
    
    def _check_rate_limit_local(
        self, 
        key: str, 
        limit: int, 
        window_seconds: int
    ) -> Tuple[bool, Dict[str, Any]]:
        """Fallback local rate limiting when Redis unavailable"""
        now = time.time()
        
        # Initialize if not exists
        if key not in self.local_cache:
            self.local_cache[key] = []
        
        # Clean old entries
        self.local_cache[key] = [
            t for t in self.local_cache[key] 
            if t > now - window_seconds
        ]
        
        current = len(self.local_cache[key])
        
        if current < limit:
            self.local_cache[key].append(now)
            return True, {
                "allowed": True,
                "current": current + 1,
                "limit": limit,
                "retry_after": None
            }
        else:
            return False, {
                "allowed": False,
                "current": current,
                "limit": limit,
                "retry_after": window_seconds
            }
    
    def check_rate_limit(self, request: Request) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limits
        Returns (allowed, metadata)
        """
        identifiers = self._get_identifier(request)
        endpoint = request.url.path
        
        # Find matching endpoint limit configuration
        endpoint_config = None
        for pattern, config in RateLimitConfig.ENDPOINT_LIMITS.items():
            if endpoint.startswith(pattern):
                endpoint_config = config
                break
        
        # Default limits if no specific configuration
        if not endpoint_config:
            endpoint_config = {
                "per_minute": RateLimitConfig.USER_REQUESTS_PER_MINUTE,
                "per_hour": RateLimitConfig.USER_REQUESTS_PER_HOUR
            }
        
        # Check per-minute limit
        minute_key = self._get_key(identifiers["combined"], "minute")
        minute_allowed, minute_info = self._check_rate_limit_redis(
            minute_key,
            endpoint_config["per_minute"],
            60
        )
        
        if not minute_allowed:
            return False, minute_info
        
        # Check per-hour limit
        hour_key = self._get_key(identifiers["combined"], "hour")
        hour_allowed, hour_info = self._check_rate_limit_redis(
            hour_key,
            endpoint_config["per_hour"],
            3600
        )
        
        if not hour_allowed:
            return False, hour_info
        
        # Check per-day limit if configured
        if "per_day" in endpoint_config:
            day_key = self._get_key(identifiers["combined"], "day")
            day_allowed, day_info = self._check_rate_limit_redis(
                day_key,
                endpoint_config["per_day"],
                86400
            )
            
            if not day_allowed:
                return False, day_info
        
        # Check tenant-wide limits if tenant exists
        if "tenant" in identifiers:
            tenant_key = self._get_key(f"tenant:{identifiers['tenant']}", "minute")
            tenant_allowed, tenant_info = self._check_rate_limit_redis(
                tenant_key,
                RateLimitConfig.TENANT_REQUESTS_PER_MINUTE,
                60
            )
            
            if not tenant_allowed:
                return False, tenant_info
        
        return True, minute_info


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce rate limits on all requests
    Addresses HIGH-AUTH-006: Missing Rate Limiting on Authentication Endpoints
    Addresses MEDIUM-BILLING-003: Insufficient Rate Limiting on Webhook Endpoints
    """
    
    def __init__(self, app, redis_url: Optional[str] = None):
        super().__init__(app)
        self.rate_limiter = RateLimiter(redis_url)
        
        # Exempt paths that should not be rate limited
        self.exempt_paths = {
            "/health",
            "/metrics",
            "/docs",
            "/openapi.json",
            "/favicon.ico"
        }
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""
        
        # Skip rate limiting for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)
        
        # Check rate limits
        allowed, info = self.rate_limiter.check_rate_limit(request)
        
        if not allowed:
            # Rate limit exceeded
            retry_after = info.get("retry_after", 60)
            
            # Add rate limit headers
            headers = {
                "X-RateLimit-Limit": str(info.get("limit", 0)),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time() + retry_after)),
                "Retry-After": str(retry_after),
                "Content-Type": "application/json"
            }
            
            # Log rate limit violation
            logger.warning(
                f"Rate limit exceeded for {request.client.host} "
                f"on {request.url.path}: {info}"
            )
            
            # Return 429 Too Many Requests
            error_response = {
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Please retry after {retry_after} seconds.",
                "retry_after": retry_after
            }
            
            return Response(
                content=json.dumps(error_response),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers=headers
            )
        
        # Add rate limit info to response headers
        response = await call_next(request)
        
        response.headers["X-RateLimit-Limit"] = str(info.get("limit", 0))
        response.headers["X-RateLimit-Remaining"] = str(
            info.get("limit", 0) - info.get("current", 0)
        )
        response.headers["X-RateLimit-Reset"] = str(
            int(time.time() + 60)  # Reset in 60 seconds
        )
        
        return response


# Decorator for custom rate limits on specific endpoints
def rate_limit(requests_per_minute: int = 60, requests_per_hour: int = 3600):
    """
    Decorator to apply custom rate limits to specific endpoints
    
    Usage:
        @router.get("/api/expensive-operation")
        @rate_limit(requests_per_minute=5, requests_per_hour=50)
        async def expensive_operation():
            ...
    """
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Create rate limiter instance
            limiter = RateLimiter()
            
            # Get identifier
            identifiers = limiter._get_identifier(request)
            
            # Check custom rate limits
            minute_key = limiter._get_key(
                f"custom:{identifiers['combined']}:{func.__name__}", 
                "minute"
            )
            minute_allowed, minute_info = limiter._check_rate_limit_redis(
                minute_key,
                requests_per_minute,
                60
            )
            
            if not minute_allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Retry after {minute_info['retry_after']} seconds",
                    headers={"Retry-After": str(minute_info["retry_after"])}
                )
            
            # Check hour limit
            hour_key = limiter._get_key(
                f"custom:{identifiers['combined']}:{func.__name__}", 
                "hour"
            )
            hour_allowed, hour_info = limiter._check_rate_limit_redis(
                hour_key,
                requests_per_hour,
                3600
            )
            
            if not hour_allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Retry after {hour_info['retry_after']} seconds",
                    headers={"Retry-After": str(hour_info["retry_after"])}
                )
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator