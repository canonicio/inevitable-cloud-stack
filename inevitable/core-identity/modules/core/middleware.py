"""
Security middleware for Platform Forge
Addresses critical vulnerabilities identified in security assessment
"""
import logging
import time
import os
from typing import Optional, Dict, Any, List
from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from sqlalchemy.orm import Session
from modules.core.database import get_db
from modules.core.security import TenantSecurity, InputValidator, SecurityError
from modules.auth.service import auth_service
import json

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Core security middleware that handles:
    - Tenant isolation validation
    - Input sanitization
    - SQL injection prevention
    - Authorization enforcement
    """
    
    def __init__(self, app, excluded_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or [
            "/docs", "/redoc", "/openapi.json", "/health", 
            "/auth/login", "/auth/register", "/auth/refresh"
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Skip security checks for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        try:
            # CRITICAL FIX: Validate Host header to prevent host header injection
            self._validate_host_header(request)
            
            # Validate tenant isolation
            await self._validate_tenant_isolation(request)
            
            # Sanitize query parameters
            self._sanitize_query_params(request)
            
            # Validate request body
            await self._validate_request_body(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            return response
            
        except SecurityError as e:
            logger.warning(f"Security violation: {e} from {request.client.host}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Security violation detected"}
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal security error"}
            )
    
    def _validate_host_header(self, request: Request):
        """
        Validate Host header to prevent host header injection attacks
        Addresses CRITICAL: Host Header Injection vulnerability
        """
        host_header = request.headers.get("host", "").lower()
        
        # Get allowed hosts from environment or config
        allowed_hosts = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
        allowed_hosts = [h.strip().lower() for h in allowed_hosts]
        
        # Also check X-Forwarded-Host and other proxy headers
        forwarded_host = request.headers.get("x-forwarded-host", "").lower()
        
        # Extract hostname without port
        import re
        host_pattern = re.compile(r'^([^:]+)(:\d+)?$')
        
        def extract_hostname(host: str) -> str:
            match = host_pattern.match(host)
            if match:
                return match.group(1)
            return host
        
        actual_host = extract_hostname(host_header)
        
        # Check if host is in allowed list
        if actual_host not in allowed_hosts:
            # Check if it's a subdomain of an allowed host
            is_valid = False
            for allowed in allowed_hosts:
                if actual_host == allowed or actual_host.endswith(f".{allowed}"):
                    is_valid = True
                    break
            
            if not is_valid:
                logger.warning(f"Host header injection attempt: {host_header}")
                raise SecurityError(f"Invalid host header: {host_header}")
        
        # If forwarded host is present, validate it too
        if forwarded_host:
            forwarded_hostname = extract_hostname(forwarded_host)
            if forwarded_hostname not in allowed_hosts:
                logger.warning(f"X-Forwarded-Host injection attempt: {forwarded_host}")
                # Don't raise error, just log and ignore the header
    
    async def _validate_tenant_isolation(self, request: Request):
        """
        Enhanced tenant isolation validation
        Addresses CRITICAL-003: Tenant Isolation Bypass
        """
        # Skip if no authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return
        
        # Extract JWT token
        if not auth_header.startswith("Bearer "):
            return
        
        token = auth_header[7:]
        
        try:
            # Decode JWT to get tenant
            jwt_payload = auth_service.verify_token(token)
            if not jwt_payload:
                return  # Invalid token, let auth dependencies handle it
            jwt_tenant_id = TenantSecurity.extract_tenant_from_jwt(jwt_payload)
            user_id = jwt_payload.get("sub")
            
            # SECURITY FIX: Use JWT as single source of truth, ignore headers completely
            # This prevents tenant isolation bypass attacks via header manipulation
            if jwt_tenant_id:
                validated_tenant = jwt_tenant_id
                
                # Log and ignore any X-Tenant-ID header to prevent confusion
                header_tenant_id = request.headers.get("X-Tenant-ID")
                if header_tenant_id and header_tenant_id != jwt_tenant_id:
                    logger.warning(
                        f"SECURITY: Ignoring X-Tenant-ID header ({header_tenant_id}) - "
                        f"using JWT tenant ({jwt_tenant_id}) as source of truth. "
                        f"User: {user_id}, IP: {request.client.host}"
                    )
            else:
                # No tenant in JWT - single tenant mode
                validated_tenant = "default"
            
            # Store validated tenant in request state
            request.state.tenant_id = validated_tenant
            request.state.user_id = user_id
            
            # Generate tenant-specific encryption key for this request
            request.state.tenant_key = self._derive_tenant_key(validated_tenant)
            
        except SecurityError:
            raise
        except Exception as e:
            logger.warning(f"JWT validation failed: {e}")
            # Don't raise error here - let auth dependency handle it
    
    def _derive_tenant_key(self, tenant_id: str) -> bytes:
        """
        Derive unique encryption key for tenant using Argon2id
        Addresses CRITICAL-008: Weak PBKDF2 in Middleware vs Strong Argon2 Elsewhere
        """
        # Get master key from environment - NO FALLBACK for security
        master_key = os.environ.get('PLATFORM_FORGE_MASTER_KEY')
        if not master_key:
            logger.critical("PLATFORM_FORGE_MASTER_KEY environment variable not set")
            raise SecurityError("Master encryption key not configured")
        
        if len(master_key) < 32:
            logger.critical(f"PLATFORM_FORGE_MASTER_KEY too short: {len(master_key)} chars (minimum 32)")
            raise SecurityError("Master key insufficient strength")
        
        # Use Argon2id for consistency with security.py module
        from argon2.low_level import hash_secret_raw, Type
        
        master_key_bytes = master_key.encode()
        salt = f"tenant_{tenant_id}_middleware".encode()
        
        # Use same parameters as security.py for consistency
        key_bytes = hash_secret_raw(
            secret=master_key_bytes,
            salt=salt,
            time_cost=3,           # iterations
            memory_cost=65536,     # 64MB in KB
            parallelism=4,
            hash_len=32,           # 32 bytes for encryption
            type=Type.ID           # Argon2id variant
        )
        
        return key_bytes
    
    def _sanitize_query_params(self, request: Request):
        """
        Sanitize query parameters to prevent injection attacks
        """
        for key, value in request.query_params.items():
            if not self._is_safe_query_value(value):
                raise SecurityError(f"Unsafe query parameter: {key}")
    
    def _is_safe_query_value(self, value: str) -> bool:
        """
        Enhanced SQL injection protection using comprehensive pattern matching
        Addresses HIGH-004: Insufficient SQL Injection Protection
        """
        import re
        
        if not value:
            return True
        
        # Remove all whitespace and normalize case for analysis
        normalized = re.sub(r'\s+', '', value.lower())
        
        # SQL keywords that indicate injection attempts (comprehensive list)
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'truncate', 'union', 'join', 'where', 'having', 'group', 'order',
            'exec', 'execute', 'sp_', 'xp_', 'cmdshell', 'openquery', 'openrowset'
        ]
        
        # Check for SQL keywords with word boundaries
        for keyword in sql_keywords:
            # Use regex with word boundaries to prevent false positives
            if re.search(rf'\b{re.escape(keyword)}\b', normalized):
                return False
        
        # Check for SQL comment patterns (various forms)
        comment_patterns = [
            r'--',           # SQL line comment
            r'/\*.*?\*/',    # SQL block comment
            r'#',            # MySQL comment
        ]
        
        for pattern in comment_patterns:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                return False
        
        # Check for SQL string delimiters and escapes
        string_patterns = [
            r"'",            # Single quote
            r'"',            # Double quote
            r'\\',           # Backslash escape
            r';',            # Statement separator
        ]
        
        for pattern in string_patterns:
            if pattern in value:
                return False
        
        # Check for encoded payloads
        encoded_patterns = [
            r'%27',          # URL encoded single quote
            r'%22',          # URL encoded double quote
            r'%3b',          # URL encoded semicolon
            r'%2d%2d',       # URL encoded --
            r'0x[0-9a-f]+',  # Hexadecimal encoding
        ]
        
        for pattern in encoded_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        # Check for suspicious character sequences
        if len(value) > 1000:  # Unusually long values
            return False
        
        # Check for repeated dangerous characters
        if value.count('\'') > 0 or value.count('"') > 0 or value.count(';') > 0:
            return False
            
        return True
    
    async def _validate_request_body(self, request: Request):
        """
        Validate request body for security issues
        """
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            
            if "application/json" in content_type:
                # Read body (this will be available for the actual handler)
                body = await request.body()
                if body:
                    try:
                        data = json.loads(body)
                        if not InputValidator.validate_json_input(data):
                            raise SecurityError("Invalid JSON input")
                    except json.JSONDecodeError:
                        raise SecurityError("Malformed JSON")
    
    def _add_security_headers(self, response: Response):
        """
        Add comprehensive security headers to response
        Addresses MEDIUM-004: Missing Security Headers
        """
        # Prevent MIME type sniffing attacks
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"
        
        # XSS Protection (deprecated but still supported by older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Force HTTPS and prevent protocol downgrade attacks
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Comprehensive Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.stripe.com https://js.stripe.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            "connect-src 'self' https://api.stripe.com",
            "frame-src https://js.stripe.com https://hooks.stripe.com",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "media-src 'self'",
            "worker-src 'none'",
            "manifest-src 'self'",
            "upgrade-insecure-requests"
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
        # Permissions Policy (formerly Feature Policy)
        permissions_directives = [
            "camera=()",
            "microphone=()",
            "geolocation=()",
            "payment=(self)",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()",
            "ambient-light-sensor=()",
            "autoplay=()",
            "encrypted-media=()",
            "fullscreen=(self)",
            "picture-in-picture=()"
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions_directives)
        
        # Cross-Origin policies
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        
        # Prevent information disclosure
        response.headers["X-Powered-By"] = ""  # Remove server fingerprinting
        response.headers["Server"] = "Platform-Forge"  # Generic server identification
        
        # Cache control for sensitive responses
        if hasattr(response, 'path') and any(sensitive in str(response.path) for sensitive in ['/auth/', '/admin/', '/billing/']):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        
        # Add custom security headers
        response.headers["X-Security-Policy"] = "Platform-Forge-Security-v1.0"
        response.headers["X-Request-ID"] = getattr(request.state, 'request_id', 'unknown') if hasattr(self, 'request') else "middleware"

class SQLInjectionPrevention:
    """
    SQL injection prevention utilities
    Addresses CRITICAL-002: SQL Injection in Admin Audit Logs
    """
    
    @staticmethod
    def validate_order_by_column(column: str, allowed_columns: List[str]) -> str:
        """Validate ORDER BY column to prevent SQL injection"""
        if column not in allowed_columns:
            raise SecurityError(f"Invalid order column: {column}")
        return InputValidator.sanitize_sql_identifier(column)
    
    @staticmethod
    def validate_filter_value(value: str, max_length: int = 1000) -> str:
        """Validate filter values"""
        if len(value) > max_length:
            raise SecurityError("Filter value too long")
        
        # Check for SQL injection patterns
        dangerous_patterns = [
            "'", '"', '--', '/*', '*/', ';', 'union', 'select', 
            'insert', 'update', 'delete', 'drop', 'create', 'alter'
        ]
        
        value_lower = value.lower()
        for pattern in dangerous_patterns:
            if pattern in value_lower:
                raise SecurityError(f"Dangerous pattern in filter: {pattern}")
        
        return value
    
    @staticmethod
    def build_safe_like_pattern(user_input: str) -> str:
        """Build safe LIKE pattern by escaping special characters"""
        # Escape SQL LIKE special characters
        escaped = user_input.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        return f"%{escaped}%"

class AuthorizationMiddleware:
    """
    Authorization middleware for endpoint protection
    Addresses CRITICAL-006: Authorization Bypass in Billing Module
    """
    
    def __init__(self):
        self.protected_patterns = {
            "/admin/": ["admin", "super_admin"],
            "/billing/": ["user", "admin", "super_admin"],
            "/api/": ["user", "admin", "super_admin"]
        }
    
    def check_authorization(self, request: Request, required_roles: List[str]) -> bool:
        """Check if user has required roles"""
        # Get user from request state (set by SecurityMiddleware)
        user_id = getattr(request.state, 'user_id', None)
        tenant_id = getattr(request.state, 'tenant_id', None)
        
        if not user_id:
            return False
        
        # Get user roles from database
        user_roles = self._get_user_roles(user_id, tenant_id)
        
        # Check if user has any of the required roles
        return any(role in user_roles for role in required_roles)
    
    def _get_user_roles(self, user_id: int, tenant_id: str) -> List[str]:
        """Get user roles from database with caching"""
        from ..core.database import SessionLocal
        from ..auth.models import User, Role
        
        try:
            db = SessionLocal()
            user = db.query(User).filter(
                User.id == user_id,
                User.tenant_id == tenant_id
            ).first()
            
            if not user:
                return []
            
            # Get role names
            role_names = [role.name for role in user.roles]
            
            # All authenticated users have 'user' role by default
            if 'user' not in role_names:
                role_names.append('user')
            
            return role_names
            
        except Exception as e:
            logger.error(f"Error getting user roles: {e}")
            return []
        finally:
            db.close()

class ResourceOwnershipValidator:
    """
    Validate resource ownership to prevent IDOR attacks
    Addresses CRITICAL-006: Authorization Bypass in Billing Module
    """
    
    @staticmethod
    def validate_customer_access(
        user_id: str, 
        customer_id: str, 
        tenant_id: str,
        db: Session
    ) -> bool:
        """Validate user can access customer resource"""
        from modules.billing.models import Customer
        
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == customer_id,
            Customer.tenant_id == tenant_id
        ).first()
        
        if not customer:
            return False
        
        # CRITICAL-010 FIX: Implement proper user-customer relationship check
        # Validate that the requesting user actually owns/can access this customer
        
        # Import User model for validation
        from modules.auth.models import User
        
        # Get the user to verify ownership
        user = db.query(User).filter(
            User.id == user_id,
            User.tenant_id == tenant_id,
            User.is_active == True
        ).first()
        
        if not user:
            return False
        
        # Check if this customer belongs to the requesting user
        # Method 1: Direct ownership (customer belongs to user)
        if hasattr(customer, 'user_id') and customer.user_id == user_id:
            return True
            
        # Method 2: Email-based ownership (customer email matches user email)  
        if customer.email == user.email:
            return True
            
        # Method 3: Admin override (admin can access any customer in their tenant)
        if user.is_superuser or user.is_admin:
            return True
            
        # Method 4: Team-based access (if customer is in user's team/organization)
        # Check if user has explicit access to this customer through team membership
        if hasattr(customer, 'team_id') and hasattr(user, 'team_id'):
            if customer.team_id and user.team_id == customer.team_id:
                return True
        
        # No valid ownership relationship found
        logger.warning(
            f"SECURITY: User {user_id} attempted unauthorized access to customer {customer_id} "
            f"in tenant {tenant_id}"
        )
        return False
    
    @staticmethod
    def validate_subscription_access(
        user_id: str,
        subscription_id: str,
        tenant_id: str,
        db: Session
    ) -> bool:
        """Validate user can access subscription resource"""
        from modules.billing.models import Package
        
        subscription = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id,
            Package.tenant_id == tenant_id
        ).first()
        
        if not subscription:
            return False
        
        # Validate user owns the customer that owns this subscription
        return ResourceOwnershipValidator.validate_customer_access(
            user_id, subscription.customer.stripe_customer_id, tenant_id, db
        )

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Enhanced rate limiting middleware
    Addresses HIGH-002: Missing Rate Limiting
    """
    
    def __init__(self, app, redis_client=None):
        super().__init__(app)
        self.redis_client = redis_client
        self.memory_store = {}  # Fallback to memory if Redis unavailable
        
        # Rate limits per endpoint pattern
        self.limits = {
            "/auth/login": (5, 300),      # 5 attempts per 5 minutes
            "/auth/register": (3, 3600),   # 3 registrations per hour
            "/api/": (1000, 3600),         # 1000 API calls per hour
            "/admin/": (100, 3600),        # 100 admin calls per hour
        }
    
    async def dispatch(self, request: Request, call_next):
        # Get rate limit for this endpoint
        limit_info = self._get_rate_limit(request.url.path)
        if not limit_info:
            return await call_next(request)
        
        requests_limit, window_seconds = limit_info
        
        # Create rate limit key using validated tenant from request state
        client_ip = request.client.host
        tenant_id = getattr(request.state, 'tenant_id', 'default')
        key = f"rate_limit:{tenant_id}:{client_ip}:{request.url.path}"
        
        # Check rate limit
        if await self._is_rate_limited(key, requests_limit, window_seconds):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"}
            )
        
        return await call_next(request)
    
    def _get_rate_limit(self, path: str) -> Optional[tuple[int, int]]:
        """Get rate limit for path"""
        for pattern, limit in self.limits.items():
            if path.startswith(pattern):
                return limit
        return None
    
    async def _is_rate_limited(self, key: str, limit: int, window: int) -> bool:
        """Check if request should be rate limited"""
        current_time = int(time.time())
        window_start = current_time - window
        
        if self.redis_client:
            # Use Redis for distributed rate limiting
            try:
                # Remove expired entries
                await self.redis_client.zremrangebyscore(key, 0, window_start)
                
                # Count current requests
                current_count = await self.redis_client.zcard(key)
                
                if current_count >= limit:
                    return True
                
                # Add current request
                await self.redis_client.zadd(key, {str(current_time): current_time})
                await self.redis_client.expire(key, window)
                
                return False
            except:
                # Fall back to memory store
                pass
        
        # HIGH-006 FIX: Enhanced memory fallback with database persistence
        return await self._memory_rate_limit_with_db_fallback(key, limit, window, window_start, current_time)
    
    async def _memory_rate_limit_with_db_fallback(
        self, key: str, limit: int, window: int, window_start: int, current_time: int
    ) -> bool:
        """
        Enhanced memory-based rate limiting with database persistence fallback
        HIGH-006 FIX: Prevents bypass through app restarts
        """
        # Try database persistence first for better reliability
        try:
            from modules.core.database import get_db
            from sqlalchemy import text
            
            db_gen = get_db()
            db = next(db_gen)
            
            try:
                # Create rate_limit table if not exists (idempotent)
                db.execute(text("""
                    CREATE TABLE IF NOT EXISTS rate_limit_entries (
                        key_hash VARCHAR(64) PRIMARY KEY,
                        requests_json TEXT NOT NULL,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                db.commit()
                
                # Clean old entries first
                db.execute(text("""
                    DELETE FROM rate_limit_entries 
                    WHERE last_updated < datetime('now', '-1 hour')
                """))
                
                # Get key hash for safe storage
                import hashlib
                key_hash = hashlib.sha256(key.encode()).hexdigest()
                
                # Get existing requests
                result = db.execute(
                    text("SELECT requests_json FROM rate_limit_entries WHERE key_hash = :key_hash"),
                    {"key_hash": key_hash}
                ).fetchone()
                
                if result:
                    import json
                    requests = json.loads(result[0])
                else:
                    requests = []
                
                # Filter to current window
                requests = [ts for ts in requests if ts > window_start]
                
                # Check limit
                if len(requests) >= limit:
                    return True
                
                # Add current request
                requests.append(current_time)
                
                # Save back to database
                import json
                db.execute(text("""
                    INSERT OR REPLACE INTO rate_limit_entries (key_hash, requests_json, last_updated)
                    VALUES (:key_hash, :requests_json, datetime('now'))
                """), {
                    "key_hash": key_hash,
                    "requests_json": json.dumps(requests)
                })
                db.commit()
                
                return False
                
            finally:
                db.close()
                
        except Exception as e:
            # Fall back to pure memory (less reliable but functional)
            logger.warning(f"Database rate limit fallback failed: {e}")
            
            if key not in self.memory_store:
                self.memory_store[key] = []
            
            # Clean old entries
            self.memory_store[key] = [
                timestamp for timestamp in self.memory_store[key] 
                if timestamp > window_start
            ]
            
            if len(self.memory_store[key]) >= limit:
                return True
            
            self.memory_store[key].append(current_time)
            return False