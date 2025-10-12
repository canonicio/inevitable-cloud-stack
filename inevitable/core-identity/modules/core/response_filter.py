"""
Response filtering to prevent sensitive data exposure
Fixes HIGH: Data exposure risks
"""
from typing import Any, Set, Dict, List, Union
from fastapi import Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import json
import re
import logging

logger = logging.getLogger(__name__)

class SensitiveFieldFilter:
    """Filter sensitive fields from API responses"""
    
    # Fields that should never be exposed
    BLOCKED_FIELDS = {
        'password', 'hashed_password', 'pwd', 'passwd',
        'secret', 'secret_key', 'api_key', 'private_key',
        'token', 'access_token', 'refresh_token',
        'mfa_secret', 'mfa_secret_encrypted', 'backup_codes',
        'backup_codes_encrypted', 'totp_secret',
        'ssn', 'social_security_number', 'tax_id',
        'credit_card', 'card_number', 'cvv', 'cvc',
        'bank_account', 'account_number', 'routing_number',
        'pin', 'security_code', 'verification_code'
    }
    
    # Patterns that suggest sensitive data
    SENSITIVE_PATTERNS = [
        re.compile(r'.*_secret(_.*)?$', re.IGNORECASE),
        re.compile(r'.*_password(_.*)?$', re.IGNORECASE),
        re.compile(r'.*_token(_.*)?$', re.IGNORECASE),
        re.compile(r'.*_key(_.*)?$', re.IGNORECASE),
        re.compile(r'.*_hash(_.*)?$', re.IGNORECASE),
        re.compile(r'.*_encrypted(_.*)?$', re.IGNORECASE),
        re.compile(r'^\$2[aby]\$\d+\$.*'),  # Bcrypt hash pattern
        re.compile(r'^pbkdf2:.*'),  # PBKDF2 hash pattern
        re.compile(r'^argon2.*'),  # Argon2 hash pattern
    ]
    
    @classmethod
    def is_sensitive_field(cls, field_name: str, field_value: Any = None) -> bool:
        """Check if a field should be filtered"""
        # Check exact matches
        if field_name.lower() in cls.BLOCKED_FIELDS:
            return True
        
        # Check patterns
        for pattern in cls.SENSITIVE_PATTERNS:
            if pattern.match(field_name):
                return True
        
        # Check value patterns if provided
        if field_value and isinstance(field_value, str):
            # Check for hash-like values
            if len(field_value) > 20 and all(c in '0123456789abcdef$' for c in field_value[:10]):
                return True
        
        return False
    
    @classmethod
    def filter_dict(cls, data: Dict[str, Any], max_depth: int = 10) -> Dict[str, Any]:
        """Recursively filter sensitive fields from dictionary"""
        return cls._filter_recursive(data, depth=0, max_depth=max_depth)
    
    @classmethod
    def _filter_recursive(
        cls,
        obj: Any,
        depth: int = 0,
        max_depth: int = 10,
        path: str = ""
    ) -> Any:
        """Recursively filter sensitive data"""
        if depth > max_depth:
            logger.warning(f"Max recursion depth reached at path: {path}")
            return "[MAX_DEPTH_EXCEEDED]"
        
        if isinstance(obj, dict):
            filtered = {}
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if field should be filtered
                if cls.is_sensitive_field(key, value):
                    filtered[key] = "[REDACTED]"
                    logger.debug(f"Filtered sensitive field: {current_path}")
                else:
                    filtered[key] = cls._filter_recursive(
                        value, depth + 1, max_depth, current_path
                    )
            return filtered
        
        elif isinstance(obj, list):
            return [
                cls._filter_recursive(item, depth + 1, max_depth, f"{path}[{i}]")
                for i, item in enumerate(obj)
            ]
        
        elif isinstance(obj, str):
            # Check for sensitive patterns in string values
            if cls._contains_sensitive_pattern(obj):
                return "[REDACTED]"
            return obj
        
        else:
            # Return other types as-is
            return obj
    
    @classmethod
    def _contains_sensitive_pattern(cls, value: str) -> bool:
        """Check if a string value contains sensitive patterns"""
        # Skip short strings
        if len(value) < 10:
            return False
        
        # Check for JWT pattern
        if value.count('.') == 2 and all(
            len(part) > 10 for part in value.split('.')
        ):
            return True
        
        # Check for base64 encoded secrets
        if len(value) > 40 and value.endswith('='):
            try:
                import base64
                decoded = base64.b64decode(value)
                if b'secret' in decoded.lower() or b'password' in decoded.lower():
                    return True
            except:
                pass
        
        return False

class ResponseFilterMiddleware(BaseHTTPMiddleware):
    """Middleware to filter sensitive data from all responses"""
    
    def __init__(self, app, exclude_paths: Set[str] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or {'/docs', '/openapi.json', '/health'}
    
    async def dispatch(self, request, call_next):
        # Skip filtering for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)
        
        # Process request
        response = await call_next(request)
        
        # Only filter JSON responses
        if response.headers.get('content-type', '').startswith('application/json'):
            # Read response body
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
            
            try:
                # Parse JSON
                data = json.loads(body.decode())
                
                # Filter sensitive fields
                filtered_data = SensitiveFieldFilter.filter_dict(data)
                
                # Create new response with filtered data
                return JSONResponse(
                    content=filtered_data,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
            except json.JSONDecodeError:
                # If not valid JSON, return original response
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type
                )
        
        return response

class SecureJSONResponse(JSONResponse):
    """Enhanced JSON response that automatically filters sensitive data"""
    
    def render(self, content: Any) -> bytes:
        # Filter sensitive data before rendering
        if isinstance(content, (dict, list)):
            content = SensitiveFieldFilter.filter_dict({"data": content})["data"]
        
        return super().render(content)

# Pydantic model helpers
from pydantic import BaseModel, Field, validator
from typing import Optional

class SecureBaseModel(BaseModel):
    """Base model that excludes sensitive fields by default"""
    
    class Config:
        # Exclude fields from response by default
        fields = {
            'hashed_password': {'exclude': True},
            'mfa_secret': {'exclude': True},
            'mfa_secret_encrypted': {'exclude': True},
            'backup_codes': {'exclude': True},
            'backup_codes_encrypted': {'exclude': True},
        }
    
    def dict(self, **kwargs):
        """Override dict to filter sensitive fields"""
        # Get base dict
        data = super().dict(**kwargs)
        
        # Apply sensitive field filter
        return SensitiveFieldFilter.filter_dict(data)

class UserResponseModel(SecureBaseModel):
    """Example secure user response model"""
    id: int
    username: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: str
    updated_at: str
    
    # These fields will be automatically excluded
    hashed_password: Optional[str] = Field(exclude=True)
    mfa_secret_encrypted: Optional[str] = Field(exclude=True)
    
    @field_validator('email')
    @classmethod
    def mask_email(cls, v):
        """Partially mask email for privacy"""
        if '@' in v:
            local, domain = v.split('@')
            if len(local) > 2:
                masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
            else:
                masked_local = '*' * len(local)
            return f"{masked_local}@{domain}"
        return v

def create_safe_error_response(
    status_code: int,
    message: str,
    details: Optional[Dict[str, Any]] = None
) -> JSONResponse:
    """Create error response with filtered details"""
    error_data = {
        "error": {
            "message": message,
            "status_code": status_code
        }
    }
    
    if details:
        # Filter sensitive data from error details
        error_data["error"]["details"] = SensitiveFieldFilter.filter_dict(details)
    
    return JSONResponse(
        status_code=status_code,
        content=error_data
    )

# Logging filter to prevent sensitive data in logs
class SensitiveDataLogFilter(logging.Filter):
    """Filter sensitive data from log records"""
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Filter message
        if hasattr(record, 'msg'):
            record.msg = self._filter_message(str(record.msg))
        
        # Filter args
        if hasattr(record, 'args') and record.args:
            record.args = tuple(
                self._filter_message(str(arg)) for arg in record.args
            )
        
        return True
    
    def _filter_message(self, message: str) -> str:
        """Filter sensitive patterns from log messages"""
        # Filter JWT tokens
        message = re.sub(
            r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
            'Bearer [JWT_REDACTED]',
            message
        )
        
        # Filter API keys
        message = re.sub(
            r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]+)["\']?',
            r'\1=[REDACTED]',
            message,
            flags=re.IGNORECASE
        )
        
        # Filter passwords
        message = re.sub(
            r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'\1=[REDACTED]',
            message,
            flags=re.IGNORECASE
        )
        
        return message

# Configure logging with sensitive data filter
def configure_secure_logging():
    """Configure logging to filter sensitive data"""
    # Add filter to all handlers
    log_filter = SensitiveDataLogFilter()
    
    # Get root logger
    root_logger = logging.getLogger()
    
    # Add filter to all handlers
    for handler in root_logger.handlers:
        handler.addFilter(log_filter)
    
    # Also add to specific loggers
    for logger_name in ['uvicorn', 'fastapi', 'sqlalchemy']:
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            handler.addFilter(log_filter)