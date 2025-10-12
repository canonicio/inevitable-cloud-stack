"""
Secure Error Message System - Prevents Information Leakage
Addresses MEDIUM-003: Error Message Information Leakage
"""
import re
import logging
import uuid
from typing import Dict, Any, Optional, Union, List
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from enum import Enum
import traceback
import os

from modules.core.config import settings

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels for logging and response handling"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


class SecureErrorMessageHandler:
    """
    Secure error message handler that prevents information disclosure.
    MEDIUM FIX: Comprehensive error message sanitization and classification
    """
    
    # MEDIUM FIX: Comprehensive patterns for sensitive information detection
    SENSITIVE_PATTERNS = [
        # Database-related patterns
        (r'duplicate key.*constraint', 'Database constraint violation'),
        (r'foreign key.*constraint', 'Database relationship error'),
        (r'table.*does not exist', 'Database resource not found'),
        (r'column.*does not exist', 'Database schema error'),
        (r'relation.*does not exist', 'Database resource error'),
        (r'syntax error.*near', 'Database query error'),
        (r'invalid input syntax', 'Invalid request format'),
        
        # File system patterns
        (r'permission denied.*file', 'Access denied'),
        (r'no such file or directory.*\/[^\s]+', 'Resource not found'),
        (r'file.*already exists', 'Resource conflict'),
        (r'disk.*full|no space left', 'Storage unavailable'),
        
        # Network patterns
        (r'connection.*refused.*host.*port', 'Service unavailable'),
        (r'timeout.*connecting to.*host', 'Service timeout'),
        (r'dns.*resolution.*failed', 'Service unavailable'),
        (r'ssl.*certificate.*verify failed', 'Security verification failed'),
        
        # Authentication patterns
        (r'user.*not found', 'Authentication failed'),
        (r'invalid.*password.*user', 'Authentication failed'),
        (r'token.*expired.*user', 'Session expired'),
        (r'insufficient.*privileges.*user', 'Access denied'),
        
        # API/Service patterns
        (r'stripe.*error:.*card', 'Payment processing failed'),
        (r'stripe.*error:.*customer', 'Payment account error'),
        (r'aws.*error.*access denied', 'Service access denied'),
        (r'redis.*connection.*failed', 'Cache service unavailable'),
        
        # Security patterns
        (r'rate.*limit.*exceeded.*ip', 'Too many requests'),
        (r'csrf.*token.*invalid', 'Security validation failed'),
        (r'signature.*verification.*failed', 'Request verification failed'),
        
        # Internal error patterns
        (r'traceback.*most recent call', 'Internal processing error'),
        (r'exception.*occurred.*line.*\d+', 'Internal processing error'),
        (r'module.*has no attribute', 'Internal configuration error'),
        (r'cannot import.*module', 'Internal dependency error'),
        
        # Path/URL patterns
        (r'\/[a-zA-Z0-9\/\-_.]+\.(py|js|html|php)', 'Internal resource error'),
        (r'[a-zA-Z]:\\\\[^\\s]+\\\\[^\\s]+', 'Internal resource error'),
        
        # Email/contact patterns
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Contact information error'),
        
        # IP/hostname patterns
        (r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', 'Network configuration error'),
        (r'localhost:[0-9]+', 'Service configuration error'),
        
        # Version/configuration patterns
        (r'version.*[0-9]+\\.[0-9]+\\.[0-9]+', 'Service version error'),
        (r'config.*not found.*[a-zA-Z_]+', 'Configuration error'),
        
        # Environment-specific patterns
        (r'environment.*variable.*[A-Z_]+', 'Configuration error'),
        (r'missing.*required.*parameter.*[a-zA-Z_]+', 'Missing required information'),
    ]
    
    # MEDIUM FIX: Generic error messages by category
    GENERIC_ERROR_MESSAGES = {
        # HTTP status codes
        400: "Invalid request. Please check your input and try again.",
        401: "Authentication required. Please log in and try again.", 
        403: "You don't have permission to perform this action.",
        404: "The requested resource was not found.",
        405: "This operation is not allowed on this resource.",
        409: "This action conflicts with the current state. Please refresh and try again.",
        422: "The provided data is invalid. Please check your input.",
        429: "Too many requests. Please wait a moment and try again.",
        500: "An internal error occurred. Please try again later.",
        502: "The service is temporarily unavailable. Please try again later.",
        503: "The service is currently unavailable. Please try again later.",
        504: "The request took too long to complete. Please try again.",
        
        # Error categories
        'database': "A data processing error occurred. Please try again.",
        'authentication': "Authentication failed. Please check your credentials.",
        'authorization': "You don't have permission to perform this action.",
        'validation': "The provided information is invalid. Please check your input.",
        'network': "A network error occurred. Please check your connection and try again.",
        'payment': "Payment processing failed. Please check your payment information.",
        'file': "File processing failed. Please check the file and try again.",
        'rate_limit': "Too many requests. Please wait a moment and try again.",
        'configuration': "A configuration error occurred. Please contact support.",
        'security': "A security validation failed. Please try again.",
        'session': "Your session has expired. Please log in again.",
        'service': "An external service error occurred. Please try again later.",
        'unknown': "An unexpected error occurred. Please try again later."
    }
    
    # MEDIUM FIX: Context-specific error mappings
    CONTEXT_ERROR_MAPPINGS = {
        # Authentication context
        'auth_login': {
            'invalid_credentials': 'Invalid username or password.',
            'account_locked': 'Account temporarily locked. Please try again later.',
            'account_disabled': 'Account access has been disabled.',
            'mfa_required': 'Multi-factor authentication is required.',
            'session_expired': 'Your session has expired. Please log in again.'
        },
        
        # Registration context
        'auth_register': {
            'user_exists': 'Registration failed. Please check your information.',
            'email_exists': 'Registration failed. Please check your information.',
            'weak_password': 'Password does not meet security requirements.',
            'invalid_email': 'Please provide a valid email address.',
            'terms_not_accepted': 'Please accept the terms of service.'
        },
        
        # Billing context
        'billing': {
            'card_declined': 'Payment method declined. Please try a different card.',
            'insufficient_funds': 'Payment failed due to insufficient funds.',
            'expired_card': 'Payment method has expired. Please update your card.',
            'invalid_card': 'Payment method is invalid. Please check the details.',
            'customer_not_found': 'Billing account not found.',
            'subscription_error': 'Subscription processing failed. Please try again.'
        },
        
        # File upload context
        'upload': {
            'file_too_large': 'File is too large. Please upload a smaller file.',
            'invalid_file_type': 'File type not supported. Please upload a different format.',
            'upload_failed': 'File upload failed. Please try again.',
            'virus_detected': 'File failed security scan. Please check the file.',
            'storage_full': 'Upload failed. Please try again later.'
        },
        
        # API context
        'api': {
            'invalid_request': 'Invalid request format. Please check the documentation.',
            'missing_parameter': 'Required parameter is missing.',
            'invalid_parameter': 'One or more parameters are invalid.',
            'resource_not_found': 'The requested resource was not found.',
            'resource_conflict': 'Resource conflict. Please refresh and try again.'
        },
        
        # Admin context
        'admin': {
            'insufficient_permissions': 'Administrative privileges required.',
            'audit_log_error': 'Unable to retrieve audit information.',
            'user_management_error': 'User management operation failed.',
            'system_config_error': 'System configuration error occurred.'
        }
    }
    
    def __init__(self, debug_mode: Optional[bool] = None):
        """Initialize secure error handler"""
        self.debug_mode = self._determine_debug_mode(debug_mode)
        self.error_counter = {}
        
        if self.debug_mode:
            logger.warning(
                "DEBUG MODE ENABLED: Detailed errors will be shown. "
                "This should NEVER be used in production!"
            )
    
    def _determine_debug_mode(self, debug_mode: Optional[bool]) -> bool:
        """
        MEDIUM FIX: Enhanced debug mode detection with multiple safety checks
        """
        # Check environment-based indicators
        environment = getattr(settings, 'ENVIRONMENT', '').lower()
        
        # Production environment indicators
        production_indicators = [
            environment in ['production', 'prod'],
            os.getenv('NODE_ENV', '').lower() == 'production',
            os.getenv('ENVIRONMENT', '').lower() in ['production', 'prod'],
            os.getenv('DEBUG', '').lower() in ['false', '0', 'no'],
            not os.getenv('DEVELOPMENT', '').lower() in ['true', '1', 'yes']
        ]
        
        # Force disable debug in production
        if any(production_indicators):
            if debug_mode:
                logger.critical(
                    "SECURITY ALERT: Debug mode requested but overridden due to production environment. "
                    f"Environment: {environment}"
                )
            return False
        
        # Only allow debug in explicit development
        return debug_mode and environment == 'development'
    
    def sanitize_error_message(
        self,
        original_error: Union[str, Exception],
        context: str = 'unknown',
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        request: Optional[Request] = None
    ) -> Dict[str, Any]:
        """
        MEDIUM FIX: Comprehensive error message sanitization
        
        Args:
            original_error: The original error message or exception
            context: Context where error occurred (auth_login, billing, etc.)
            severity: Error severity level
            request: Optional request object for additional context
        
        Returns:
            Dict containing sanitized error response
        """
        # Generate unique error ID for tracking
        error_id = str(uuid.uuid4())
        
        # Convert exception to string if needed
        error_str = str(original_error)
        
        # Log the full error details server-side
        self._log_error_details(
            error_id=error_id,
            original_error=original_error,
            context=context,
            severity=severity,
            request=request
        )
        
        # Get sanitized message for user
        user_message = self._get_sanitized_message(error_str, context)
        
        # Determine HTTP status code
        status_code = self._determine_status_code(original_error, context)
        
        # Build response
        response_data = {
            "error_id": error_id,
            "message": user_message,
            "status_code": status_code,
            "timestamp": self._get_timestamp()
        }
        
        # MEDIUM FIX: Only include debug info in development mode
        if self.debug_mode:
            response_data["debug"] = {
                "original_error": error_str,
                "context": context,
                "severity": severity.value,
                "type": type(original_error).__name__
            }
            
            # Include traceback for exceptions in debug mode
            if isinstance(original_error, Exception):
                response_data["debug"]["traceback"] = traceback.format_exc()
        else:
            # Production mode - provide support guidance
            response_data["support"] = {
                "message": f"For assistance, please contact support with error ID: {error_id}",
                "error_id": error_id
            }
        
        # Track error frequency for monitoring
        self._track_error_frequency(context, error_str)
        
        return response_data
    
    def _get_sanitized_message(self, error_str: str, context: str) -> str:
        """
        MEDIUM FIX: Get sanitized error message based on context and patterns
        """
        # Check context-specific mappings first
        if context in self.CONTEXT_ERROR_MAPPINGS:
            context_mapping = self.CONTEXT_ERROR_MAPPINGS[context]
            
            # Look for specific error patterns in context
            error_lower = error_str.lower()
            for error_key, sanitized_msg in context_mapping.items():
                if error_key in error_lower:
                    return sanitized_msg
        
        # Apply pattern-based sanitization
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            if re.search(pattern, error_str, re.IGNORECASE | re.DOTALL):
                return replacement
        
        # Check for generic category matches
        error_lower = error_str.lower()
        
        if any(db_word in error_lower for db_word in ['database', 'sql', 'constraint', 'table']):
            return self.GENERIC_ERROR_MESSAGES.get('database')
        elif any(auth_word in error_lower for auth_word in ['authentication', 'login', 'password', 'token']):
            return self.GENERIC_ERROR_MESSAGES.get('authentication')
        elif any(net_word in error_lower for net_word in ['connection', 'network', 'timeout', 'dns']):
            return self.GENERIC_ERROR_MESSAGES.get('network')
        elif any(pay_word in error_lower for pay_word in ['stripe', 'payment', 'card', 'billing']):
            return self.GENERIC_ERROR_MESSAGES.get('payment')
        elif any(file_word in error_lower for file_word in ['file', 'upload', 'download', 'storage']):
            return self.GENERIC_ERROR_MESSAGES.get('file')
        elif 'rate limit' in error_lower or 'too many requests' in error_lower:
            return self.GENERIC_ERROR_MESSAGES.get('rate_limit')
        
        # Default to generic unknown error
        return self.GENERIC_ERROR_MESSAGES.get('unknown')
    
    def _determine_status_code(self, error: Union[str, Exception], context: str) -> int:
        """Determine appropriate HTTP status code"""
        if isinstance(error, HTTPException):
            return error.status_code
        
        error_str = str(error).lower()
        
        # Context-based status codes
        if context in ['auth_login', 'auth_register']:
            if any(word in error_str for word in ['invalid', 'incorrect', 'wrong']):
                return status.HTTP_401_UNAUTHORIZED
            elif 'exists' in error_str:
                return status.HTTP_409_CONFLICT
        elif context == 'billing':
            if any(word in error_str for word in ['declined', 'insufficient', 'expired']):
                return status.HTTP_402_PAYMENT_REQUIRED
        elif context == 'upload':
            if 'too large' in error_str or 'size' in error_str:
                return status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            elif 'type' in error_str or 'format' in error_str:
                return status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        
        # Pattern-based status codes
        if any(word in error_str for word in ['not found', 'does not exist']):
            return status.HTTP_404_NOT_FOUND
        elif any(word in error_str for word in ['forbidden', 'permission', 'denied', 'unauthorized']):
            return status.HTTP_403_FORBIDDEN
        elif any(word in error_str for word in ['invalid', 'malformed', 'bad request']):
            return status.HTTP_400_BAD_REQUEST
        elif any(word in error_str for word in ['conflict', 'duplicate', 'exists']):
            return status.HTTP_409_CONFLICT
        elif 'rate limit' in error_str or 'too many' in error_str:
            return status.HTTP_429_TOO_MANY_REQUESTS
        
        # Default to internal server error
        return status.HTTP_500_INTERNAL_SERVER_ERROR
    
    def _log_error_details(
        self,
        error_id: str,
        original_error: Union[str, Exception],
        context: str,
        severity: ErrorSeverity,
        request: Optional[Request]
    ):
        """Log detailed error information server-side"""
        # Build comprehensive error context
        error_context = {
            "error_id": error_id,
            "context": context,
            "severity": severity.value,
            "error_type": type(original_error).__name__,
            "error_message": str(original_error)
        }
        
        # Add request context if available
        if request:
            error_context.update({
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "unknown"),
                "user_id": getattr(request.state, 'user_id', None),
                "tenant_id": getattr(request.state, 'tenant_id', None)
            })
        
        # Add traceback for exceptions
        if isinstance(original_error, Exception):
            error_context["traceback"] = traceback.format_exc()
        
        # Log at appropriate level based on severity
        if severity == ErrorSeverity.CRITICAL:
            logger.critical(f"Critical error {error_id}", extra=error_context, exc_info=True)
        elif severity == ErrorSeverity.HIGH:
            logger.error(f"High severity error {error_id}", extra=error_context, exc_info=True)
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(f"Medium severity error {error_id}", extra=error_context)
        else:
            logger.info(f"Low severity error {error_id}", extra=error_context)
    
    def _track_error_frequency(self, context: str, error_message: str):
        """Track error frequency for monitoring"""
        key = f"{context}:{error_message[:100]}"  # Limit key length
        
        if key not in self.error_counter:
            self.error_counter[key] = {"count": 0, "first_seen": self._get_timestamp()}
        
        self.error_counter[key]["count"] += 1
        self.error_counter[key]["last_seen"] = self._get_timestamp()
        
        # Alert on high frequency errors
        if self.error_counter[key]["count"] % 100 == 0:  # Every 100 occurrences
            logger.warning(
                f"High frequency error detected: {key} - "
                f"Count: {self.error_counter[key]['count']}"
            )
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + "Z"
    
    def create_secure_http_exception(
        self,
        original_error: Union[str, Exception],
        context: str = 'unknown',
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        request: Optional[Request] = None
    ) -> HTTPException:
        """
        Create HTTPException with sanitized error message
        """
        error_response = self.sanitize_error_message(
            original_error, context, severity, request
        )
        
        return HTTPException(
            status_code=error_response["status_code"],
            detail=error_response["message"]
        )


# Global instance
_secure_error_handler = None


def get_secure_error_handler() -> SecureErrorMessageHandler:
    """Get global secure error handler instance"""
    global _secure_error_handler
    if _secure_error_handler is None:
        debug_mode = getattr(settings, 'DEBUG', False)
        _secure_error_handler = SecureErrorMessageHandler(debug_mode=debug_mode)
    return _secure_error_handler


# MEDIUM FIX: Convenience functions for different contexts
def create_auth_error(
    error: Union[str, Exception],
    request: Optional[Request] = None
) -> HTTPException:
    """Create authentication error with secure message"""
    handler = get_secure_error_handler()
    return handler.create_secure_http_exception(
        error, context='auth_login', severity=ErrorSeverity.MEDIUM, request=request
    )


def create_billing_error(
    error: Union[str, Exception],
    request: Optional[Request] = None
) -> HTTPException:
    """Create billing error with secure message"""
    handler = get_secure_error_handler()
    return handler.create_secure_http_exception(
        error, context='billing', severity=ErrorSeverity.HIGH, request=request
    )


def create_upload_error(
    error: Union[str, Exception],
    request: Optional[Request] = None
) -> HTTPException:
    """Create file upload error with secure message"""
    handler = get_secure_error_handler()
    return handler.create_secure_http_exception(
        error, context='upload', severity=ErrorSeverity.MEDIUM, request=request
    )


def create_api_error(
    error: Union[str, Exception],
    request: Optional[Request] = None
) -> HTTPException:
    """Create API error with secure message"""
    handler = get_secure_error_handler()
    return handler.create_secure_http_exception(
        error, context='api', severity=ErrorSeverity.MEDIUM, request=request
    )


def create_admin_error(
    error: Union[str, Exception],
    request: Optional[Request] = None
) -> HTTPException:
    """Create admin error with secure message"""
    handler = get_secure_error_handler()
    return handler.create_secure_http_exception(
        error, context='admin', severity=ErrorSeverity.HIGH, request=request
    )


def sanitize_error_for_logging(
    error: Union[str, Exception],
    context: str = 'unknown'
) -> Dict[str, Any]:
    """
    Sanitize error for logging purposes (keeps more detail than user messages)
    """
    handler = get_secure_error_handler()
    
    # For logging, we want more detail but still need to be careful
    error_str = str(error)
    
    # Remove only the most sensitive patterns
    sensitive_log_patterns = [
        (r'password[=:]\s*\S+', '[PASSWORD_REDACTED]'),
        (r'token[=:]\s*\S+', '[TOKEN_REDACTED]'),
        (r'key[=:]\s*\S+', '[KEY_REDACTED]'),
        (r'secret[=:]\s*\S+', '[SECRET_REDACTED]'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]'),
    ]
    
    sanitized_message = error_str
    for pattern, replacement in sensitive_log_patterns:
        sanitized_message = re.sub(pattern, replacement, sanitized_message, flags=re.IGNORECASE)
    
    return {
        "context": context,
        "sanitized_message": sanitized_message,
        "error_type": type(error).__name__,
        "timestamp": handler._get_timestamp()
    }