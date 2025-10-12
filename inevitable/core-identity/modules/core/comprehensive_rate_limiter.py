"""
Comprehensive Rate Limiting System with Full Coverage
Addresses MEDIUM-004: Rate Limiting Coverage Gaps
"""
import asyncio
import json
import logging
import time
import hashlib
import redis
from typing import Dict, Optional, List, Tuple, Any
from fastapi import Request, HTTPException, status
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict
import ipaddress

from modules.core.config import settings

logger = logging.getLogger(__name__)


class RateLimitType(Enum):
    """Types of rate limiting strategies"""
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window" 
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


class EndpointCategory(Enum):
    """Endpoint categories with different rate limiting requirements"""
    AUTHENTICATION = "auth"
    API_PUBLIC = "api_public"
    API_PRIVATE = "api_private"
    ADMIN = "admin"
    BILLING = "billing"
    WEBHOOKS = "webhooks"
    FILE_UPLOAD = "upload"
    PASSWORD_RESET = "password_reset"
    MFA = "mfa"
    REGISTRATION = "registration"
    SEARCH = "search"
    EXPORT = "export"


@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int  # Maximum burst requests
    lockout_duration: int  # Seconds to lockout after limit exceeded
    progressive_delay: bool = True  # Enable progressive delays
    whitelist_admin: bool = False  # Exempt admin users
    subnet_limiting: bool = True  # Enable subnet-based limiting


class ComprehensiveRateLimiter:
    """
    Comprehensive rate limiting system addressing all coverage gaps.
    MEDIUM FIX: Covers authentication, API, admin, billing, webhooks, uploads, etc.
    """
    
    # MEDIUM FIX: Comprehensive rate limiting rules for all endpoint types
    RATE_LIMIT_RULES = {
        EndpointCategory.AUTHENTICATION: RateLimitRule(
            requests_per_minute=10,
            requests_per_hour=50,
            requests_per_day=200,
            burst_limit=5,
            lockout_duration=300,  # 5 minutes
            progressive_delay=True
        ),
        EndpointCategory.API_PUBLIC: RateLimitRule(
            requests_per_minute=100,
            requests_per_hour=5000,
            requests_per_day=50000,
            burst_limit=50,
            lockout_duration=60,
            progressive_delay=False
        ),
        EndpointCategory.API_PRIVATE: RateLimitRule(
            requests_per_minute=200,
            requests_per_hour=10000,
            requests_per_day=100000,
            burst_limit=100,
            lockout_duration=30,
            progressive_delay=False,
            whitelist_admin=True
        ),
        EndpointCategory.ADMIN: RateLimitRule(
            requests_per_minute=50,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_limit=20,
            lockout_duration=120,  # 2 minutes
            progressive_delay=True,
            whitelist_admin=True
        ),
        EndpointCategory.BILLING: RateLimitRule(
            requests_per_minute=20,
            requests_per_hour=200,
            requests_per_day=1000,
            burst_limit=10,
            lockout_duration=600,  # 10 minutes
            progressive_delay=True
        ),
        EndpointCategory.WEBHOOKS: RateLimitRule(
            requests_per_minute=1000,  # High limit for legitimate webhooks
            requests_per_hour=10000,
            requests_per_day=100000,
            burst_limit=500,
            lockout_duration=30,
            progressive_delay=False,
            subnet_limiting=False  # Webhooks come from various IPs
        ),
        EndpointCategory.FILE_UPLOAD: RateLimitRule(
            requests_per_minute=5,
            requests_per_hour=50,
            requests_per_day=200,
            burst_limit=2,
            lockout_duration=600,  # 10 minutes
            progressive_delay=True
        ),
        EndpointCategory.PASSWORD_RESET: RateLimitRule(
            requests_per_minute=3,
            requests_per_hour=10,
            requests_per_day=20,
            burst_limit=1,
            lockout_duration=1800,  # 30 minutes
            progressive_delay=True
        ),
        EndpointCategory.MFA: RateLimitRule(
            requests_per_minute=10,
            requests_per_hour=30,
            requests_per_day=100,
            burst_limit=5,
            lockout_duration=900,  # 15 minutes
            progressive_delay=True
        ),
        EndpointCategory.REGISTRATION: RateLimitRule(
            requests_per_minute=5,
            requests_per_hour=20,
            requests_per_day=50,
            burst_limit=2,
            lockout_duration=1800,  # 30 minutes
            progressive_delay=True,
            subnet_limiting=True
        ),
        EndpointCategory.SEARCH: RateLimitRule(
            requests_per_minute=30,
            requests_per_hour=500,
            requests_per_day=2000,
            burst_limit=15,
            lockout_duration=60,
            progressive_delay=True
        ),
        EndpointCategory.EXPORT: RateLimitRule(
            requests_per_minute=2,
            requests_per_hour=10,
            requests_per_day=25,
            burst_limit=1,
            lockout_duration=3600,  # 1 hour
            progressive_delay=True
        )
    }
    
    # MEDIUM FIX: Enhanced endpoint pattern matching with comprehensive coverage
    ENDPOINT_PATTERNS = {
        # Authentication endpoints
        r'^/auth/login/?$': EndpointCategory.AUTHENTICATION,
        r'^/auth/register/?$': EndpointCategory.REGISTRATION,
        r'^/auth/refresh/?$': EndpointCategory.AUTHENTICATION,
        r'^/auth/logout/?$': EndpointCategory.AUTHENTICATION,
        r'^/auth/password-reset/?$': EndpointCategory.PASSWORD_RESET,
        r'^/auth/verify-email/?$': EndpointCategory.AUTHENTICATION,
        r'^/auth/change-password/?$': EndpointCategory.AUTHENTICATION,
        
        # MFA endpoints
        r'^/auth/mfa/.*$': EndpointCategory.MFA,
        r'^/admin/mfa/.*$': EndpointCategory.MFA,
        
        # Public API endpoints
        r'^/api/public/.*$': EndpointCategory.API_PUBLIC,
        r'^/api/docs/?$': EndpointCategory.API_PUBLIC,
        r'^/health/?$': EndpointCategory.API_PUBLIC,
        
        # Private API endpoints
        r'^/api/v1/.*$': EndpointCategory.API_PRIVATE,
        r'^/api/users/.*$': EndpointCategory.API_PRIVATE,
        r'^/api/data/.*$': EndpointCategory.API_PRIVATE,
        
        # Admin endpoints
        r'^/admin/.*$': EndpointCategory.ADMIN,
        r'^/admin/users/.*$': EndpointCategory.ADMIN,
        r'^/admin/audit/.*$': EndpointCategory.ADMIN,
        r'^/admin/settings/.*$': EndpointCategory.ADMIN,
        
        # Billing endpoints
        r'^/billing/.*$': EndpointCategory.BILLING,
        r'^/billing/stripe/.*$': EndpointCategory.BILLING,
        r'^/billing/checkout/?$': EndpointCategory.BILLING,
        r'^/billing/subscriptions/.*$': EndpointCategory.BILLING,
        
        # Webhook endpoints
        r'^/webhooks/.*$': EndpointCategory.WEBHOOKS,
        r'^/webhook/stripe/?$': EndpointCategory.WEBHOOKS,
        r'^/webhook/github/?$': EndpointCategory.WEBHOOKS,
        
        # File upload endpoints
        r'^/upload/.*$': EndpointCategory.FILE_UPLOAD,
        r'^/api/upload/?$': EndpointCategory.FILE_UPLOAD,
        r'^/files/upload/?$': EndpointCategory.FILE_UPLOAD,
        
        # Search endpoints
        r'^/search/.*$': EndpointCategory.SEARCH,
        r'^/api/search/?$': EndpointCategory.SEARCH,
        
        # Export endpoints
        r'^/export/.*$': EndpointCategory.EXPORT,
        r'^/api/export/.*$': EndpointCategory.EXPORT,
        r'^/admin/export/.*$': EndpointCategory.EXPORT,
    }
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """Initialize comprehensive rate limiter"""
        self.redis_client = redis_client or self._create_redis_client()
        self.memory_fallback = defaultdict(lambda: defaultdict(list))
        self.lockout_cache = {}
        self.progressive_delays = {}
        
        # Start cleanup tasks
        self._cleanup_task = None
        self._start_background_cleanup()
    
    def _create_redis_client(self) -> redis.Redis:
        """Create Redis client with fallback"""
        try:
            redis_url = getattr(settings, 'REDIS_URL', 'redis://localhost:6379')
            client = redis.Redis.from_url(redis_url, decode_responses=True)
            # Test connection
            client.ping()
            logger.info("Connected to Redis for rate limiting")
            return client
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}. Using memory fallback.")
            return None
    
    def _start_background_cleanup(self):
        """Start background cleanup task"""
        if not self._cleanup_task:
            loop = asyncio.get_event_loop()
            self._cleanup_task = loop.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Periodically clean up old entries"""
        while True:
            try:
                await asyncio.sleep(300)  # Clean every 5 minutes
                await self._cleanup_old_entries()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Rate limiter cleanup error: {e}")
    
    async def _cleanup_old_entries(self):
        """Clean up expired rate limit entries"""
        current_time = time.time()
        
        # Clean memory fallback
        expired_keys = []
        for identifier, windows in self.memory_fallback.items():
            for window_type, timestamps in windows.items():
                # Keep only recent entries (last 24 hours)
                timestamps[:] = [ts for ts in timestamps if current_time - ts < 86400]
                if not timestamps:
                    expired_keys.append((identifier, window_type))
        
        for identifier, window_type in expired_keys:
            del self.memory_fallback[identifier][window_type]
            if not self.memory_fallback[identifier]:
                del self.memory_fallback[identifier]
        
        # Clean lockout cache
        self.lockout_cache = {
            key: expiry for key, expiry in self.lockout_cache.items()
            if expiry > current_time
        }
        
        # Clean Redis if available
        if self.redis_client:
            try:
                # Use pipeline for efficiency
                pipe = self.redis_client.pipeline()
                
                # Find and clean expired keys
                pattern = "rate_limit:*"
                for key in self.redis_client.scan_iter(match=pattern):
                    ttl = self.redis_client.ttl(key)
                    if ttl == -1:  # Key without expiration
                        pipe.expire(key, 86400)  # Set 24 hour expiration
                
                pipe.execute()
                
            except Exception as e:
                logger.error(f"Redis cleanup error: {e}")
    
    def _get_endpoint_category(self, path: str) -> Optional[EndpointCategory]:
        """
        MEDIUM FIX: Enhanced pattern matching for comprehensive endpoint coverage
        """
        import re
        
        # Normalize path
        path = path.rstrip('/')
        
        # Check patterns
        for pattern, category in self.ENDPOINT_PATTERNS.items():
            if re.match(pattern, path, re.IGNORECASE):
                return category
        
        # MEDIUM FIX: Default categorization for uncovered endpoints
        if path.startswith('/api/'):
            return EndpointCategory.API_PRIVATE
        elif path.startswith('/admin/'):
            return EndpointCategory.ADMIN
        elif 'upload' in path.lower():
            return EndpointCategory.FILE_UPLOAD
        elif 'auth' in path.lower():
            return EndpointCategory.AUTHENTICATION
        else:
            # Default to private API with moderate limits
            return EndpointCategory.API_PRIVATE
    
    def _generate_identifiers(self, request: Request) -> List[str]:
        """
        MEDIUM FIX: Enhanced identifier generation for comprehensive rate limiting
        """
        identifiers = []
        
        # Primary IP-based identifier
        client_ip = self._get_client_ip(request)
        identifiers.append(f"ip:{client_ip}")
        
        # User-based identifier (if authenticated)
        user_id = getattr(request.state, 'user_id', None)
        if user_id:
            identifiers.append(f"user:{user_id}")
        
        # Tenant-based identifier
        tenant_id = getattr(request.state, 'tenant_id', 'default')
        identifiers.append(f"tenant:{tenant_id}")
        
        # Subnet-based identifier (for preventing distributed attacks)
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
        
        # User-Agent fingerprint (for bot detection)
        user_agent = request.headers.get("User-Agent", "")
        if user_agent:
            ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:12]
            identifiers.append(f"ua:{ua_hash}")
        
        # Authorization header hash (for API key limiting)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]
            identifiers.append(f"token:{token_hash}")
        
        return identifiers
    
    def _get_client_ip(self, request: Request) -> str:
        """Get the most reliable client IP address"""
        # Check X-Forwarded-For header
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (original client)
            client_ip = forwarded_for.split(",")[0].strip()
            try:
                ipaddress.ip_address(client_ip)
                return client_ip
            except ValueError:
                pass
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
                return real_ip
            except ValueError:
                pass
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    async def check_rate_limit(
        self,
        request: Request,
        endpoint_category: Optional[EndpointCategory] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        MEDIUM FIX: Comprehensive rate limit checking with multiple strategies
        
        Returns:
            Tuple of (is_allowed, limit_info)
        """
        # Determine endpoint category
        if not endpoint_category:
            endpoint_category = self._get_endpoint_category(request.url.path)
        
        if not endpoint_category:
            return True, None  # No limits for unclassified endpoints
        
        # Get rate limit rules
        rules = self.RATE_LIMIT_RULES.get(endpoint_category)
        if not rules:
            return True, None
        
        # Check if user should be whitelisted
        if rules.whitelist_admin and self._is_admin_user(request):
            return True, None
        
        # Generate identifiers
        identifiers = self._generate_identifiers(request)
        current_time = time.time()
        
        # Check each identifier
        for identifier in identifiers:
            # Check for active lockout
            lockout_key = f"lockout:{endpoint_category.value}:{identifier}"
            if lockout_key in self.lockout_cache:
                if self.lockout_cache[lockout_key] > current_time:
                    remaining = int(self.lockout_cache[lockout_key] - current_time)
                    return False, {
                        "error": "rate_limited",
                        "message": "Too many requests - locked out",
                        "retry_after": remaining,
                        "identifier": identifier,
                        "category": endpoint_category.value
                    }
                else:
                    # Lockout expired
                    del self.lockout_cache[lockout_key]
            
            # Check rate limits for different time windows
            windows = [
                ("minute", 60, rules.requests_per_minute),
                ("hour", 3600, rules.requests_per_hour),
                ("day", 86400, rules.requests_per_day)
            ]
            
            for window_name, window_seconds, limit in windows:
                if limit <= 0:
                    continue
                
                violated, retry_after = await self._check_window_limit(
                    identifier, endpoint_category, window_name, window_seconds, 
                    limit, current_time
                )
                
                if violated:
                    # Apply lockout
                    if rules.lockout_duration > 0:
                        lockout_expiry = current_time + rules.lockout_duration
                        self.lockout_cache[lockout_key] = lockout_expiry
                    
                    # Log rate limit violation
                    logger.warning(
                        f"Rate limit exceeded: {identifier} on {endpoint_category.value} "
                        f"({window_name} window: {limit} requests)"
                    )
                    
                    return False, {
                        "error": "rate_limited",
                        "message": f"Too many requests in {window_name}",
                        "retry_after": retry_after,
                        "limit": limit,
                        "window": window_name,
                        "identifier": identifier,
                        "category": endpoint_category.value
                    }
        
        # All checks passed - record the request
        await self._record_request(identifiers, endpoint_category, current_time)
        
        return True, None
    
    async def _check_window_limit(
        self,
        identifier: str,
        category: EndpointCategory,
        window_name: str,
        window_seconds: int,
        limit: int,
        current_time: float
    ) -> Tuple[bool, int]:
        """Check rate limit for specific time window"""
        key = f"rate_limit:{category.value}:{window_name}:{identifier}"
        window_start = current_time - window_seconds
        
        if self.redis_client:
            try:
                # Use Redis sorted set for sliding window
                pipe = self.redis_client.pipeline()
                
                # Remove expired entries
                pipe.zremrangebyscore(key, 0, window_start)
                
                # Count current requests
                pipe.zcard(key)
                
                # Execute pipeline
                results = pipe.execute()
                current_count = results[1]
                
                if current_count >= limit:
                    # Calculate retry after
                    oldest_score = self.redis_client.zrange(key, 0, 0, withscores=True)
                    if oldest_score:
                        oldest_time = oldest_score[0][1]
                        retry_after = int(window_seconds - (current_time - oldest_time))
                        return True, retry_after
                
                return False, 0
                
            except Exception as e:
                logger.error(f"Redis rate limit check failed: {e}")
                # Fall through to memory fallback
        
        # Memory fallback
        if identifier not in self.memory_fallback:
            self.memory_fallback[identifier] = defaultdict(list)
        
        timestamps = self.memory_fallback[identifier][key]
        
        # Remove expired entries
        timestamps[:] = [ts for ts in timestamps if ts > window_start]
        
        if len(timestamps) >= limit:
            retry_after = int(window_seconds - (current_time - timestamps[0]))
            return True, retry_after
        
        return False, 0
    
    async def _record_request(
        self,
        identifiers: List[str],
        category: EndpointCategory,
        current_time: float
    ):
        """Record request for rate limiting"""
        if self.redis_client:
            try:
                pipe = self.redis_client.pipeline()
                
                for identifier in identifiers:
                    for window_name, window_seconds, _ in [
                        ("minute", 60, 0), ("hour", 3600, 0), ("day", 86400, 0)
                    ]:
                        key = f"rate_limit:{category.value}:{window_name}:{identifier}"
                        pipe.zadd(key, {str(current_time): current_time})
                        pipe.expire(key, window_seconds)
                
                pipe.execute()
                return
                
            except Exception as e:
                logger.error(f"Redis rate limit recording failed: {e}")
        
        # Memory fallback
        for identifier in identifiers:
            if identifier not in self.memory_fallback:
                self.memory_fallback[identifier] = defaultdict(list)
            
            for window_name in ["minute", "hour", "day"]:
                key = f"rate_limit:{category.value}:{window_name}:{identifier}"
                self.memory_fallback[identifier][key].append(current_time)
    
    def _is_admin_user(self, request: Request) -> bool:
        """Check if user is admin and should be whitelisted"""
        # Check if user has admin role
        user_id = getattr(request.state, 'user_id', None)
        if not user_id:
            return False
        
        # This could be enhanced to check actual user roles from database
        # For now, check if user_id indicates admin (implementation dependent)
        return False  # Conservative default
    
    async def get_rate_limit_status(
        self,
        request: Request,
        endpoint_category: Optional[EndpointCategory] = None
    ) -> Dict[str, Any]:
        """
        Get current rate limit status for debugging/monitoring
        """
        if not endpoint_category:
            endpoint_category = self._get_endpoint_category(request.url.path)
        
        if not endpoint_category:
            return {"status": "no_limits"}
        
        rules = self.RATE_LIMIT_RULES.get(endpoint_category)
        if not rules:
            return {"status": "no_limits"}
        
        identifiers = self._generate_identifiers(request)
        current_time = time.time()
        
        status = {
            "category": endpoint_category.value,
            "rules": {
                "requests_per_minute": rules.requests_per_minute,
                "requests_per_hour": rules.requests_per_hour,
                "requests_per_day": rules.requests_per_day,
                "burst_limit": rules.burst_limit,
                "lockout_duration": rules.lockout_duration
            },
            "identifiers": {},
            "lockouts": {}
        }
        
        # Check status for each identifier
        for identifier in identifiers:
            identifier_status = {}
            
            # Check lockout status
            lockout_key = f"lockout:{endpoint_category.value}:{identifier}"
            if lockout_key in self.lockout_cache:
                if self.lockout_cache[lockout_key] > current_time:
                    remaining = int(self.lockout_cache[lockout_key] - current_time)
                    status["lockouts"][identifier] = remaining
            
            # Check current usage for each window
            for window_name, window_seconds, limit in [
                ("minute", 60, rules.requests_per_minute),
                ("hour", 3600, rules.requests_per_hour),
                ("day", 86400, rules.requests_per_day)
            ]:
                if limit <= 0:
                    continue
                
                key = f"rate_limit:{endpoint_category.value}:{window_name}:{identifier}"
                current_count = 0
                
                if self.redis_client:
                    try:
                        window_start = current_time - window_seconds
                        self.redis_client.zremrangebyscore(key, 0, window_start)
                        current_count = self.redis_client.zcard(key)
                    except:
                        pass
                else:
                    # Memory fallback
                    if identifier in self.memory_fallback and key in self.memory_fallback[identifier]:
                        window_start = current_time - window_seconds
                        timestamps = [
                            ts for ts in self.memory_fallback[identifier][key] 
                            if ts > window_start
                        ]
                        current_count = len(timestamps)
                
                identifier_status[window_name] = {
                    "used": current_count,
                    "limit": limit,
                    "remaining": max(0, limit - current_count),
                    "percentage": min(100, (current_count / limit) * 100)
                }
            
            status["identifiers"][identifier] = identifier_status
        
        return status


# Global instance
_comprehensive_rate_limiter = None


def get_comprehensive_rate_limiter() -> ComprehensiveRateLimiter:
    """Get global comprehensive rate limiter instance"""
    global _comprehensive_rate_limiter
    if _comprehensive_rate_limiter is None:
        _comprehensive_rate_limiter = ComprehensiveRateLimiter()
    return _comprehensive_rate_limiter


async def comprehensive_rate_limit_middleware(
    request: Request,
    endpoint_category: Optional[EndpointCategory] = None
):
    """
    Comprehensive rate limiting middleware for all endpoints.
    Use as dependency: Depends(comprehensive_rate_limit_middleware)
    """
    rate_limiter = get_comprehensive_rate_limiter()
    
    # Check rate limits
    is_allowed, limit_info = await rate_limiter.check_rate_limit(
        request, endpoint_category
    )
    
    if not is_allowed and limit_info:
        # Add rate limit headers
        headers = {}
        if "retry_after" in limit_info:
            headers["Retry-After"] = str(limit_info["retry_after"])
        if "limit" in limit_info:
            headers["X-RateLimit-Limit"] = str(limit_info["limit"])
        if "window" in limit_info:
            headers["X-RateLimit-Window"] = limit_info["window"]
        
        # Log rate limit violation
        logger.warning(
            f"Rate limit exceeded for {request.client.host} on {request.url.path}: "
            f"{limit_info.get('message', 'Unknown violation')}"
        )
        
        # Return 429 Too Many Requests
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=limit_info.get("message", "Too many requests"),
            headers=headers
        )


# MEDIUM FIX: Specific rate limiting functions for different endpoint types
async def auth_rate_limit(request: Request):
    """Rate limiting for authentication endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.AUTHENTICATION)


async def admin_rate_limit(request: Request):
    """Rate limiting for admin endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.ADMIN)


async def billing_rate_limit(request: Request):
    """Rate limiting for billing endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.BILLING)


async def webhook_rate_limit(request: Request):
    """Rate limiting for webhook endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.WEBHOOKS)


async def upload_rate_limit(request: Request):
    """Rate limiting for file upload endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.FILE_UPLOAD)


async def mfa_rate_limit(request: Request):
    """Rate limiting for MFA endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.MFA)


async def password_reset_rate_limit(request: Request):
    """Rate limiting for password reset endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.PASSWORD_RESET)


async def registration_rate_limit(request: Request):
    """Rate limiting for registration endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.REGISTRATION)


async def search_rate_limit(request: Request):
    """Rate limiting for search endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.SEARCH)


async def export_rate_limit(request: Request):
    """Rate limiting for export endpoints"""
    return await comprehensive_rate_limit_middleware(request, EndpointCategory.EXPORT)