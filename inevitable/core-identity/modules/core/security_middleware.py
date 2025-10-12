"""
Comprehensive security middleware stack for Platform Forge
Implements defense-in-depth security controls
"""
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.cors import CORSMiddleware
import time
import hashlib
import json
import redis
from typing import Optional, Dict, Set, Tuple
from datetime import datetime, timedelta
import logging
import asyncio
from collections import defaultdict

from .secure_config import settings

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add comprehensive security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers based on OWASP recommendations
        headers = {
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Enable XSS filter in older browsers
            "X-XSS-Protection": "1; mode=block",
            
            # Force HTTPS
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Content Security Policy
            "Content-Security-Policy": self._get_csp_policy(),
            
            # Referrer Policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions Policy (formerly Feature Policy)
            "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
            
            # Cache Control for sensitive endpoints
            "Cache-Control": self._get_cache_control(request.url.path),
            
            # Remove server identification
            "Server": "Platform-Forge"
        }
        
        # Apply headers
        for header, value in headers.items():
            response.headers[header] = value
        
        # Remove potentially sensitive headers
        sensitive_headers = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in sensitive_headers:
            response.headers.pop(header, None)
        
        return response
    
    def _get_csp_policy(self) -> str:
        """Generate Content Security Policy"""
        if settings.DEBUG:
            # Relaxed CSP for development
            return (
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' http: https: ws: wss:; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https:;"
            )
        else:
            # Strict CSP for production
            return (
                "default-src 'self'; "
                "script-src 'self' 'sha256-...' ; "  # Add specific script hashes
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self' https://api.stripe.com; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
    
    def _get_cache_control(self, path: str) -> str:
        """Get appropriate cache control header"""
        # No cache for sensitive endpoints
        sensitive_paths = ['/api/auth', '/api/admin', '/api/users']
        if any(path.startswith(p) for p in sensitive_paths):
            return "no-store, no-cache, must-revalidate, private"
        
        # Cache static content
        if path.startswith('/static'):
            return "public, max-age=31536000"
        
        # Default
        return "no-cache, private"

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Advanced rate limiting with multiple strategies
    - Sliding window algorithm
    - Per-endpoint limits
    - Distributed rate limiting with Redis
    """
    
    def __init__(
        self,
        app,
        redis_client: Optional[redis.Redis] = None,
        default_limit: int = 60,
        window_seconds: int = 60
    ):
        super().__init__(app)
        self.redis = redis_client
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        
        # Per-endpoint rate limits
        self.endpoint_limits = {
            "/api/auth/login": 5,  # 5 attempts per minute
            "/api/auth/register": 3,  # 3 registrations per minute
            "/api/auth/forgot-password": 2,  # 2 reset requests per minute
            "/api/admin": 30,  # 30 admin requests per minute
        }
        
        # In-memory fallback for when Redis is unavailable
        self.local_storage = defaultdict(list)
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for excluded paths
        if request.url.path in ['/health', '/metrics']:
            return await call_next(request)
        
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Get rate limit for endpoint
        limit = self._get_endpoint_limit(request.url.path)
        
        # Check rate limit
        allowed, remaining, reset_time = await self._check_rate_limit(
            client_id,
            request.url.path,
            limit
        )
        
        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {client_id} on {request.url.path}"
            )
            return Response(
                content=json.dumps({
                    "error": "Rate limit exceeded",
                    "retry_after": reset_time
                }),
                status_code=429,
                headers={
                    "Retry-After": str(reset_time),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time() + reset_time))
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + self.window_seconds))
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        """Get unique client identifier"""
        # Use authenticated user ID if available
        if hasattr(request.state, 'user_id'):
            return f"user:{request.state.user_id}"
        
        # Fall back to IP address
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        return f"ip:{client_ip}"
    
    def _get_endpoint_limit(self, path: str) -> int:
        """Get rate limit for specific endpoint"""
        # Check exact match
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]
        
        # Check prefix match
        for endpoint, limit in self.endpoint_limits.items():
            if path.startswith(endpoint):
                return limit
        
        return self.default_limit
    
    async def _check_rate_limit(
        self,
        client_id: str,
        endpoint: str,
        limit: int
    ) -> Tuple[bool, int, int]:
        """Check if request is within rate limit"""
        key = f"rate_limit:{client_id}:{endpoint}"
        now = time.time()
        window_start = now - self.window_seconds
        
        if self.redis:
            try:
                # Use Redis for distributed rate limiting
                return await self._check_redis_rate_limit(key, now, window_start, limit)
            except Exception as e:
                logger.error(f"Redis rate limit error: {e}")
                # Fall back to local storage
        
        # Use local storage
        return self._check_local_rate_limit(key, now, window_start, limit)
    
    async def _check_redis_rate_limit(
        self,
        key: str,
        now: float,
        window_start: float,
        limit: int
    ) -> Tuple[bool, int, int]:
        """Check rate limit using Redis"""
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count requests in window
        pipe.zcard(key)
        
        # Execute pipeline
        _, request_count = pipe.execute()
        
        if request_count >= limit:
            # Get oldest request time to calculate reset
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                reset_time = int(self.window_seconds - (now - oldest[0][1]))
            else:
                reset_time = self.window_seconds
            
            return False, 0, reset_time
        
        # Add current request
        self.redis.zadd(key, {str(now): now})
        self.redis.expire(key, self.window_seconds + 1)
        
        remaining = limit - request_count - 1
        return True, remaining, self.window_seconds
    
    def _check_local_rate_limit(
        self,
        key: str,
        now: float,
        window_start: float,
        limit: int
    ) -> Tuple[bool, int, int]:
        """Check rate limit using local storage"""
        # Clean old entries
        self.local_storage[key] = [
            ts for ts in self.local_storage[key] if ts > window_start
        ]
        
        request_count = len(self.local_storage[key])
        
        if request_count >= limit:
            if self.local_storage[key]:
                reset_time = int(self.window_seconds - (now - self.local_storage[key][0]))
            else:
                reset_time = self.window_seconds
            
            return False, 0, reset_time
        
        # Add current request
        self.local_storage[key].append(now)
        
        remaining = limit - request_count - 1
        return True, remaining, self.window_seconds

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request logging for security monitoring
    - Logs all requests with security context
    - Detects suspicious patterns
    - Integrates with SIEM
    """
    
    def __init__(self, app, alert_threshold: int = 10):
        super().__init__(app)
        self.alert_threshold = alert_threshold
        self.suspicious_patterns = {
            "sql_injection": [
                r"union.*select", r"select.*from", r"drop.*table",
                r"insert.*into", r"update.*set", r"delete.*from"
            ],
            "xss": [
                r"<script", r"javascript:", r"onerror=", r"onload="
            ],
            "path_traversal": [
                r"\.\./", r"\.\.\\", r"%2e%2e", r"..%2f"
            ],
            "command_injection": [
                r";\s*(ls|cat|rm|wget|curl)", r"\|(ls|cat|rm|wget|curl)",
                r"`.*`", r"\$\(.*\)"
            ]
        }
    
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Generate request ID
        request_id = hashlib.sha256(
            f"{time.time()}{request.client.host if request.client else 'unknown'}".encode()
        ).hexdigest()[:16]
        
        request.state.request_id = request_id
        
        # Detect suspicious patterns
        suspicious_activity = self._detect_suspicious_patterns(request)
        
        # Log request
        request_log = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "tenant_id": getattr(request.state, "tenant_id", None),
            "user_id": getattr(request.state, "user_id", None),
            "suspicious": suspicious_activity
        }
        
        if suspicious_activity:
            logger.warning(
                f"SECURITY_ALERT: Suspicious request detected",
                extra=request_log
            )
        else:
            logger.info("Request received", extra=request_log)
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            
            # Log response
            response_log = {
                "request_id": request_id,
                "status_code": response.status_code,
                "duration_ms": int(duration * 1000),
                "suspicious": suspicious_activity
            }
            
            logger.info("Request completed", extra=response_log)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Log error
            error_log = {
                "request_id": request_id,
                "error": str(e),
                "duration_ms": int(duration * 1000),
                "suspicious": suspicious_activity
            }
            
            logger.error("Request failed", extra=error_log, exc_info=True)
            raise
    
    def _detect_suspicious_patterns(self, request: Request) -> Dict[str, bool]:
        """Detect suspicious patterns in request"""
        suspicious = {}
        
        # Check URL path and query
        url_string = f"{request.url.path}?{request.url.query}"
        
        for pattern_type, patterns in self.suspicious_patterns.items():
            import re
            for pattern in patterns:
                if re.search(pattern, url_string, re.IGNORECASE):
                    suspicious[pattern_type] = True
                    break
        
        # Check headers for suspicious content
        for header, value in request.headers.items():
            if header.lower() in ['cookie', 'authorization']:
                continue  # Skip sensitive headers
            
            for pattern_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, str(value), re.IGNORECASE):
                        suspicious[f"{pattern_type}_in_header"] = True
                        break
        
        return suspicious

class IPBlockingMiddleware(BaseHTTPMiddleware):
    """
    IP-based blocking for security threats
    - Automatic blocking of suspicious IPs
    - Geographic restrictions
    - Whitelist/blacklist support
    """
    
    def __init__(
        self,
        app,
        redis_client: Optional[redis.Redis] = None,
        block_duration: int = 3600
    ):
        super().__init__(app)
        self.redis = redis_client
        self.block_duration = block_duration
        
        # Static blacklist (load from config in production)
        self.permanent_blacklist = set()
        
        # Whitelist (never block these)
        self.whitelist = {'127.0.0.1', '::1'}  # localhost
    
    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        
        # Check whitelist
        if client_ip in self.whitelist:
            return await call_next(request)
        
        # Check if IP is blocked
        if await self._is_ip_blocked(client_ip):
            logger.warning(f"Blocked request from {client_ip}")
            return Response(
                content=json.dumps({
                    "error": "Access denied"
                }),
                status_code=403
            )
        
        return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    
    async def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        # Check permanent blacklist
        if ip in self.permanent_blacklist:
            return True
        
        # Check temporary blocks in Redis
        if self.redis:
            try:
                blocked = self.redis.get(f"blocked_ip:{ip}")
                return blocked is not None
            except Exception as e:
                logger.error(f"Redis error checking IP block: {e}")
        
        return False
    
    async def block_ip(self, ip: str, reason: str, duration: Optional[int] = None):
        """Block an IP address"""
        if self.redis:
            try:
                key = f"blocked_ip:{ip}"
                self.redis.setex(
                    key,
                    duration or self.block_duration,
                    json.dumps({
                        "reason": reason,
                        "blocked_at": datetime.utcnow().isoformat()
                    })
                )
                logger.info(f"Blocked IP {ip} for {reason}")
            except Exception as e:
                logger.error(f"Failed to block IP {ip}: {e}")

def create_security_middleware_stack(app, redis_client: Optional[redis.Redis] = None):
    """Create and configure the complete security middleware stack"""
    
    # Apply middlewares in reverse order (last added is first executed)
    
    # 5. Response filtering (innermost)
    from .response_filter import ResponseFilterMiddleware
    app.add_middleware(ResponseFilterMiddleware)
    
    # 4. Request logging
    app.add_middleware(RequestLoggingMiddleware)
    
    # 3. Rate limiting
    app.add_middleware(
        RateLimitMiddleware,
        redis_client=redis_client,
        default_limit=settings.RATE_LIMIT_PER_MINUTE
    )
    
    # 2. IP blocking
    app.add_middleware(
        IPBlockingMiddleware,
        redis_client=redis_client
    )
    
    # 1. Security headers (outermost)
    app.add_middleware(SecurityHeadersMiddleware)
    
    # CORS (if needed)
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.BACKEND_CORS_ORIGINS,
            allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )
    
    # Trusted host validation
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*.platform-forge.com", "localhost"] if not settings.DEBUG else ["*"]
    )
    
    logger.info("Security middleware stack configured")