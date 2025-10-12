"""
Security configuration for MEDIUM and LOW vulnerability fixes
Addresses MEDIUM-001 through MEDIUM-006 and LOW-001 through LOW-003
"""
from typing import Dict, List, Optional
from datetime import timedelta
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time
import hashlib
import hmac

logger = logging.getLogger(__name__)


class PaymentValidationService:
    """MEDIUM-001 FIX: Enhanced payment validation"""
    
    @staticmethod
    def validate_payment_amount(
        amount: float,
        currency: str,
        min_amount: float = 0.50,
        max_amount: float = 999999.99
    ) -> bool:
        """Validate payment amounts to prevent manipulation"""
        # Check amount bounds
        if amount < min_amount or amount > max_amount:
            return False
        
        # Check for precision issues (max 2 decimal places for most currencies)
        if currency in ['USD', 'EUR', 'GBP']:
            if round(amount, 2) != amount:
                return False
        
        return True
    
    @staticmethod
    def validate_payment_metadata(metadata: dict) -> dict:
        """Sanitize and validate payment metadata"""
        # Limit metadata size
        if len(str(metadata)) > 5000:
            raise ValueError("Payment metadata too large")
        
        # Sanitize metadata keys and values
        sanitized = {}
        for key, value in metadata.items():
            # Only allow alphanumeric keys
            if not key.replace('_', '').isalnum():
                continue
            
            # Limit value length
            if isinstance(value, str) and len(value) > 500:
                value = value[:500]
            
            sanitized[key] = value
        
        return sanitized


class MFARateLimiter:
    """MEDIUM-002 FIX: Rate limiting for MFA operations"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.limits = {
            'verify': (5, 300),     # 5 attempts per 5 minutes
            'generate': (3, 3600),  # 3 generations per hour
            'resend': (3, 600),     # 3 resends per 10 minutes
        }
    
    async def check_rate_limit(
        self,
        user_id: str,
        operation: str,
        ip_address: str = None
    ) -> bool:
        """Check if MFA operation is rate limited"""
        limit, window = self.limits.get(operation, (10, 60))
        
        # Use both user ID and IP for rate limiting
        keys = [f"mfa_rate:{operation}:{user_id}"]
        if ip_address:
            keys.append(f"mfa_rate:{operation}:ip:{ip_address}")
        
        for key in keys:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, window)
            
            if count > limit:
                logger.warning(f"MFA rate limit exceeded - Operation: {operation}, User: {user_id}")
                return False
        
        return True


class EnhancedTOTPConfig:
    """MEDIUM-003 FIX: Stronger TOTP configuration"""
    
    # Increased window for clock skew (90 seconds = 3 intervals)
    TOTP_WINDOW = 3
    
    # Longer secret for better entropy (32 bytes = 256 bits)
    SECRET_LENGTH = 32
    
    # Algorithm upgrade
    ALGORITHM = "SHA256"  # Instead of default SHA1
    
    # Issuer name for authenticator apps
    ISSUER_NAME = "Platform Forge"
    
    @staticmethod
    def generate_totp_uri(secret: str, email: str) -> str:
        """Generate TOTP URI with enhanced parameters"""
        import urllib.parse
        
        params = {
            'secret': secret,
            'issuer': EnhancedTOTPConfig.ISSUER_NAME,
            'algorithm': EnhancedTOTPConfig.ALGORITHM,
            'digits': '6',
            'period': '30'
        }
        
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{EnhancedTOTPConfig.ISSUER_NAME}:{email}?{query}"


class TimingAttackPrevention:
    """MEDIUM-004 FIX: Prevent information disclosure via timing attacks"""
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """Use constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(val1, val2)
    
    @staticmethod
    def add_random_delay(min_ms: int = 50, max_ms: int = 150):
        """
        Add random delay to prevent timing analysis.
        CRITICAL-010 FIX: Use cryptographically secure random for timing delays
        """
        import secrets
        delay_range = max_ms - min_ms
        delay = (secrets.randbelow(delay_range) + min_ms) / 1000.0
        time.sleep(delay)
    
    @staticmethod
    def hash_then_compare(value: str, expected_hash: str) -> bool:
        """Hash value before comparison to normalize timing"""
        value_hash = hashlib.sha256(value.encode()).hexdigest()
        return hmac.compare_digest(value_hash, expected_hash)


class WebhookReplayProtection:
    """MEDIUM-005 FIX: Enhanced webhook replay protection"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.replay_window = 86400  # 24 hours
    
    async def is_replay(self, webhook_id: str, timestamp: int) -> bool:
        """Check if webhook is a replay attack"""
        current_time = int(time.time())
        
        # Check if timestamp is too old
        if current_time - timestamp > self.replay_window:
            return True
        
        # Check if webhook ID was already processed
        key = f"webhook_processed:{webhook_id}"
        if await self.redis.exists(key):
            return True
        
        # Mark as processed
        await self.redis.setex(key, self.replay_window, "1")
        return False


def configure_cors(app: FastAPI):
    """MEDIUM-006 FIX: Secure CORS configuration"""
    
    # Get allowed origins from environment
    import os
    allowed_origins = os.getenv("CORS_ORIGINS", "").split(",")
    
    # Default to restrictive CORS
    if not allowed_origins or allowed_origins == [""]:
        allowed_origins = ["https://app.platformforge.com"]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        max_age=3600,  # 1 hour
        expose_headers=["X-Request-ID", "X-RateLimit-Remaining"]
    )


class SessionConfiguration:
    """LOW-001 FIX: Proper session timeout configuration"""
    
    # Session timeout values
    IDLE_TIMEOUT = timedelta(minutes=30)
    ABSOLUTE_TIMEOUT = timedelta(hours=12)
    
    # Remember me extends timeout
    REMEMBER_ME_TIMEOUT = timedelta(days=30)
    
    @staticmethod
    def should_refresh_token(issued_at: int, last_activity: int) -> bool:
        """Check if token should be refreshed"""
        current_time = int(time.time())
        
        # Check idle timeout
        if current_time - last_activity > SessionConfiguration.IDLE_TIMEOUT.total_seconds():
            return False  # Session expired
        
        # Check absolute timeout
        if current_time - issued_at > SessionConfiguration.ABSOLUTE_TIMEOUT.total_seconds():
            return False  # Session expired
        
        # Refresh if more than 50% through idle timeout
        if current_time - last_activity > (SessionConfiguration.IDLE_TIMEOUT.total_seconds() / 2):
            return True
        
        return False


class SecureErrorHandler:
    """LOW-002 FIX: Generic error messages to prevent information disclosure"""
    
    ERROR_MESSAGES = {
        400: "Bad request",
        401: "Authentication required",
        403: "Access denied",
        404: "Resource not found",
        409: "Conflict",
        422: "Validation error",
        429: "Too many requests",
        500: "Internal server error",
        503: "Service unavailable"
    }
    
    @staticmethod
    async def handle_error(request: Request, exc: Exception) -> JSONResponse:
        """Return generic error messages in production"""
        import os
        import uuid
        
        # Generate error ID for tracking
        error_id = str(uuid.uuid4())
        
        # Log detailed error internally
        logger.error(
            f"Error {error_id}: {exc}",
            extra={
                "error_id": error_id,
                "path": request.url.path,
                "method": request.method
            }
        )
        
        # In production, return generic message
        if os.getenv("ENVIRONMENT", "production") == "production":
            status_code = getattr(exc, 'status_code', 500)
            message = SecureErrorHandler.ERROR_MESSAGES.get(
                status_code,
                "An error occurred"
            )
            
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": message,
                    "error_id": error_id
                }
            )
        else:
            # In development, return full error
            return JSONResponse(
                status_code=getattr(exc, 'status_code', 500),
                content={
                    "error": str(exc),
                    "error_id": error_id,
                    "debug": True
                }
            )


def add_security_headers(response: Response):
    """LOW-003 FIX: Add comprehensive security headers"""
    
    # Prevent XSS
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Permissions Policy
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), "
        "gyroscope=(), magnetometer=(), microphone=(), "
        "payment=*, usb=()"
    )
    
    # HSTS (only in production with HTTPS)
    import os
    if os.getenv("ENVIRONMENT") == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    
    return response


class SecurityMiddleware:
    """Middleware to apply all security configurations"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, request: Request, call_next):
        # Apply security headers to response
        response = await call_next(request)
        return add_security_headers(response)