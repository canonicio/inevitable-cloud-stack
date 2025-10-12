"""
CSRF Protection for Platform Forge
Addresses HIGH-003: Missing CSRF Protection
"""
import secrets
import time
import hmac
import hashlib
from typing import Optional, Tuple
from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import logging

from .config import settings
from .security import SecurityError
from .secure_cookie_manager import get_cookie_manager, CookieType

logger = logging.getLogger(__name__)


class CSRFToken(BaseModel):
    """CSRF token response model"""
    csrf_token: str


class CSRFProtection:
    """
    Double Submit Cookie pattern for CSRF protection
    - Generates cryptographically secure tokens
    - Validates tokens on state-changing requests
    - Supports both cookie and header validation
    """
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        cookie_name: str = "csrf_token",
        token_lifetime: int = 3600,  # 1 hour
        secure_cookie: bool = True,
        samesite: str = "strict"
    ):
        self.secret_key = (secret_key or settings.SECRET_KEY).encode()
        self.token_name = token_name
        self.header_name = header_name
        self.cookie_name = cookie_name
        self.token_lifetime = token_lifetime
        self.secure_cookie = secure_cookie and not settings.DEBUG
        self.samesite = samesite
        
        # Methods that require CSRF protection
        self.protected_methods = {"POST", "PUT", "DELETE", "PATCH"}
        
        # Paths to exclude from CSRF protection
        self.excluded_paths = {
            "/api/auth/login",  # Login uses credentials
            "/api/auth/register",  # Registration is public
            "/api/auth/forgot-password",  # Password reset is public
            "/billing/webhook",  # Webhooks use signature validation
            "/health",
            "/metrics"
        }
    
    def generate_token(self, session_id: Optional[str] = None) -> str:
        """Generate a new CSRF token"""
        # Create token with timestamp
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(32)
        
        # If session_id provided, bind token to session
        if session_id:
            payload = f"{timestamp}:{nonce}:{session_id}"
        else:
            payload = f"{timestamp}:{nonce}"
        
        # Create HMAC signature
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine payload and signature
        token = f"{payload}:{signature}"
        return token
    
    def validate_token(
        self,
        token: str,
        session_id: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate CSRF token
        Returns: (is_valid, error_message)
        """
        try:
            # Split token into components
            parts = token.split(":")
            
            if session_id:
                if len(parts) != 4:
                    return False, "Invalid token format"
                timestamp, nonce, token_session, signature = parts
                payload = f"{timestamp}:{nonce}:{token_session}"
                
                # Validate session binding
                if token_session != session_id:
                    return False, "Token not bound to session"
            else:
                if len(parts) != 3:
                    return False, "Invalid token format"
                timestamp, nonce, signature = parts
                payload = f"{timestamp}:{nonce}"
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key,
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False, "Invalid token signature"
            
            # Check token age
            token_age = int(time.time()) - int(timestamp)
            if token_age > self.token_lifetime:
                return False, "Token expired"
            
            return True, None
            
        except Exception as e:
            logger.error(f"CSRF token validation error: {e}")
            return False, "Token validation failed"
    
    def set_csrf_cookie(self, response: Response, token: str):
        """Set CSRF token cookie using secure cookie manager"""
        cookie_manager = get_cookie_manager()
        
        # Use secure cookie manager with CSRF policy
        cookie_manager.set_secure_cookie(
            response=response,
            name=self.cookie_name,
            value=token,
            cookie_type=CookieType.CSRF
        )
    
    async def validate_request(self, request: Request) -> bool:
        """Validate CSRF token for a request"""
        # Skip validation for safe methods
        if request.method not in self.protected_methods:
            return True
        
        # Skip validation for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return True
        
        # Get token from header
        header_token = request.headers.get(self.header_name)
        if not header_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing"
            )
        
        # Get token from cookie using secure cookie manager
        cookie_manager = get_cookie_manager()
        cookie_token = cookie_manager.get_secure_cookie(
            request=request,
            name=self.cookie_name,
            cookie_type=CookieType.CSRF
        )
        
        if not cookie_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF cookie missing"
            )
        
        # Tokens must match (double submit cookie)
        if header_token != cookie_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token mismatch"
            )
        
        # Get session ID if available
        session_id = getattr(request.state, "session_id", None)
        
        # Validate token
        is_valid, error = self.validate_token(header_token, session_id)
        if not is_valid:
            logger.warning(f"CSRF validation failed: {error}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"CSRF validation failed: {error}"
            )
        
        return True


# Global CSRF protection instance
_csrf_protection = None


def get_csrf_protection() -> CSRFProtection:
    """Get global CSRF protection instance"""
    global _csrf_protection
    if _csrf_protection is None:
        _csrf_protection = CSRFProtection()
    return _csrf_protection


async def require_csrf_token(request: Request):
    """FastAPI dependency to require CSRF token"""
    csrf = get_csrf_protection()
    await csrf.validate_request(request)
    return True


async def generate_csrf_token(
    request: Request,
    response: Response
) -> CSRFToken:
    """Generate and set CSRF token"""
    csrf = get_csrf_protection()
    
    # Get session ID if available
    session_id = getattr(request.state, "session_id", None)
    
    # Generate token
    token = csrf.generate_token(session_id)
    
    # Set cookie
    csrf.set_csrf_cookie(response, token)
    
    return CSRFToken(csrf_token=token)


from starlette.middleware.base import BaseHTTPMiddleware


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection middleware
    Automatically validates CSRF tokens for state-changing requests
    """
    
    def __init__(self, app, csrf_protection: Optional[CSRFProtection] = None):
        super().__init__(app)
        self.csrf = csrf_protection or get_csrf_protection()
    
    async def dispatch(self, request: Request, call_next):
        # For API requests, validate CSRF token
        if request.url.path.startswith("/api/"):
            try:
                await self.csrf.validate_request(request)
            except HTTPException as e:
                # Return JSON error for API requests
                return Response(
                    content=f'{{"error": "{e.detail}"}}',
                    status_code=e.status_code,
                    media_type="application/json"
                )
        
        response = await call_next(request)
        return response