"""
Secure Error Handler with Information Disclosure Prevention
Addresses MEDIUM-003: Debug Mode Information Disclosure
"""
import logging
import traceback
import uuid
import os
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from modules.core.config import settings

logger = logging.getLogger(__name__)


class ErrorResponse(BaseModel):
    """Standardized error response model"""
    error_id: str
    message: str
    status_code: int
    detail: Optional[str] = None  # Only included in development mode


class SecureErrorHandler:
    """
    Secure error handler that prevents information disclosure.
    Addresses MEDIUM-003: Debug Mode Information Disclosure
    """
    
    # Generic error messages for production
    GENERIC_ERROR_MESSAGES = {
        400: "Bad Request",
        401: "Authentication Required",
        403: "Access Denied",
        404: "Resource Not Found",
        405: "Method Not Allowed",
        409: "Request Conflict",
        422: "Invalid Request Data",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Service Temporarily Unavailable",
        503: "Service Unavailable",
        504: "Request Timeout"
    }
    
    def __init__(self, debug_mode: bool = False):
        """
        Initialize error handler.
        
        Args:
            debug_mode: Whether to include detailed error info (NEVER use in production)
        """
        # MEDIUM FIX: Enhanced debug mode protection with multiple safety checks
        # Addresses MEDIUM-002: Information disclosure in debug mode
        
        # Check environment variable override
        env_debug = settings.DEBUG if hasattr(settings, 'DEBUG') else False
        
        # Multiple safety checks to prevent debug mode in production
        production_indicators = [
            settings.ENVIRONMENT == "production",
            hasattr(settings, 'ENVIRONMENT') and 'prod' in settings.ENVIRONMENT.lower(),
            os.getenv('ENVIRONMENT', '').lower() in ['production', 'prod'],
            os.getenv('NODE_ENV', '').lower() == 'production',
            not os.getenv('DEVELOPMENT', '').lower() in ['true', '1', 'yes']
        ]
        
        # Force disable debug mode if any production indicator is present
        if any(production_indicators):
            self.debug_mode = False
            if debug_mode or env_debug:
                logger.critical(
                    "SECURITY: Debug mode requested but disabled due to production environment. "
                    f"Environment: {settings.ENVIRONMENT}, Debug requested: {debug_mode}"
                )
        else:
            # Only allow debug mode in development
            self.debug_mode = debug_mode and settings.ENVIRONMENT == "development"
        
        if self.debug_mode:
            logger.warning("DEBUG MODE ENABLED - Detailed errors will be exposed")
        else:
            logger.info("Debug mode disabled - Generic error messages will be used")
    
    def handle_error(
        self,
        request: Request,
        exc: Exception,
        status_code: Optional[int] = None
    ) -> JSONResponse:
        """
        Handle errors securely without exposing sensitive information.
        """
        # Generate unique error ID for tracking
        error_id = str(uuid.uuid4())
        
        # Determine status code
        if isinstance(exc, HTTPException):
            status_code = exc.status_code
            user_message = str(exc.detail) if self.debug_mode else None
        else:
            status_code = status_code or 500
            user_message = None
        
        # Get generic message for status code
        generic_message = self.GENERIC_ERROR_MESSAGES.get(
            status_code,
            "An error occurred processing your request"
        )
        
        # Log full error details server-side
        self._log_error(error_id, request, exc, status_code)
        
        # Build response
        response_data = {
            "error_id": error_id,
            "message": generic_message,
            "status_code": status_code
        }
        
        # MEDIUM-003 FIX: Only include details in development mode
        if self.debug_mode and user_message:
            response_data["detail"] = user_message
            # Include stack trace only in development
            if not isinstance(exc, HTTPException):
                response_data["traceback"] = traceback.format_exc()
        else:
            # In production, provide error ID for support
            response_data["support_message"] = (
                f"If this issue persists, please contact support with error ID: {error_id}"
            )
        
        return JSONResponse(
            status_code=status_code,
            content=response_data
        )
    
    def _log_error(
        self,
        error_id: str,
        request: Request,
        exc: Exception,
        status_code: int
    ):
        """Log detailed error information server-side."""
        # Build detailed error context
        error_context = {
            "error_id": error_id,
            "status_code": status_code,
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_host": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "error_type": type(exc).__name__,
            "error_message": str(exc)
        }
        
        # Log at appropriate level
        if status_code >= 500:
            logger.error(
                f"Server error {error_id}",
                extra=error_context,
                exc_info=True
            )
        elif status_code >= 400:
            logger.warning(
                f"Client error {error_id}",
                extra=error_context
            )
        else:
            logger.info(
                f"Error {error_id}",
                extra=error_context
            )
    
    @staticmethod
    def sanitize_error_message(message: str) -> str:
        """
        Sanitize error messages to remove sensitive information.
        """
        # List of patterns that might leak sensitive info
        sensitive_patterns = [
            r"password[=:]\s*\S+",
            r"token[=:]\s*\S+",
            r"api[_-]?key[=:]\s*\S+",
            r"secret[=:]\s*\S+",
            r"\/[a-zA-Z0-9]+\/[a-zA-Z0-9]+\/[a-zA-Z0-9]+",  # File paths
            r"[a-zA-Z]:\\\\[^\\s]+",  # Windows paths
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IP addresses
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email addresses
        ]
        
        import re
        sanitized = message
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized


class SAMLErrorHandler(SecureErrorHandler):
    """
    Specialized error handler for SAML that prevents information disclosure.
    Addresses MEDIUM-003 specifically for SSO errors.
    """
    
    SAML_ERROR_MESSAGES = {
        "invalid_response": "Authentication failed. Please try again.",
        "invalid_signature": "Authentication validation failed.",
        "expired_assertion": "Authentication expired. Please log in again.",
        "invalid_audience": "Authentication configuration error.",
        "replay_detected": "Authentication security check failed.",
        "missing_attributes": "Required user information not provided.",
        "invalid_issuer": "Authentication source not recognized."
    }
    
    def handle_saml_error(
        self,
        error_type: str,
        request: Request,
        details: Optional[Dict[str, Any]] = None
    ) -> JSONResponse:
        """
        Handle SAML errors without exposing implementation details.
        """
        error_id = str(uuid.uuid4())
        
        # Get generic message
        message = self.SAML_ERROR_MESSAGES.get(
            error_type,
            "Authentication failed"
        )
        
        # Log detailed error server-side
        logger.error(
            f"SAML error {error_id}: {error_type}",
            extra={
                "error_id": error_id,
                "error_type": error_type,
                "details": details,
                "path": request.url.path,
                "client": request.client.host if request.client else "unknown"
            }
        )
        
        # Return generic response
        response_data = {
            "error": "authentication_failed",
            "message": message,
            "error_id": error_id
        }
        
        # Only include details in development
        if self.debug_mode and details:
            response_data["debug_details"] = details
        
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=response_data
        )


# Global error handler instance
error_handler = SecureErrorHandler(debug_mode=settings.DEBUG if hasattr(settings, 'DEBUG') else False)