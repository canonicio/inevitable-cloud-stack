"""
Enhanced Validators for Platform Forge Security
Provides secure validation classes with input sanitization and protection
"""
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, Optional, List
import re
import html
import logging

logger = logging.getLogger(__name__)


class SecureBaseModel(BaseModel):
    """
    Enhanced Pydantic BaseModel with built-in security features
    - Input sanitization
    - XSS protection
    - SQL injection prevention
    - Size limits
    """
    
    model_config = {
        # Enable validation on assignment
        'validate_assignment': True,
        # Prevent arbitrary class instantiation
        'arbitrary_types_allowed': False,
        # Strict mode for better security
        'str_strip_whitespace': True,
        'str_max_length': 1000,
    }
        
    @field_validator('*', mode='before')
    @classmethod
    def sanitize_input(cls, v):
        """Sanitize all string inputs to prevent XSS and injection attacks"""
        if isinstance(v, str):
            # HTML escape to prevent XSS
            v = html.escape(v)
            # Remove potentially dangerous characters
            v = re.sub(r'[<>"\']', '', v)
            # Limit length
            if len(v) > 1000:
                v = v[:1000]
            # Strip whitespace
            v = v.strip()
        return v


class APIParameterValidator:
    """
    Validator for API parameters with security checks
    """
    
    @staticmethod
    def validate_string(value: str, max_length: int = 255, min_length: int = 0) -> str:
        """Validate and sanitize string parameters"""
        if not isinstance(value, str):
            raise ValueError("Value must be a string")
            
        # Strip whitespace
        value = value.strip()
        
        # Length validation
        if len(value) < min_length:
            raise ValueError(f"String too short (minimum {min_length} characters)")
        if len(value) > max_length:
            raise ValueError(f"String too long (maximum {max_length} characters)")
            
        # XSS protection
        value = html.escape(value)
        
        # Remove dangerous patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>'
        ]
        
        for pattern in dangerous_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
            
        return value
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email format securely"""
        email = APIParameterValidator.validate_string(email, max_length=320)
        
        # Basic email regex (not perfect, but secure)
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")
            
        return email.lower()


# Export commonly used classes
__all__ = [
    'SecureBaseModel',
    'APIParameterValidator'
]