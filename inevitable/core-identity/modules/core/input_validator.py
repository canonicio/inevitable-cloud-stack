"""
Comprehensive Input Validation System
Addresses MEDIUM-AUTH-001: Insufficient Input Validation
"""
import re
import html
import json
from typing import Any, Optional, List, Dict, Union
from urllib.parse import urlparse, quote
from email_validator import validate_email, EmailNotValidError
import bleach
from pydantic import BaseModel, Field, field_validator, ConfigDict
import logging

logger = logging.getLogger(__name__)


class ValidationPatterns:
    """Common validation patterns"""
    
    # Security-focused patterns
    USERNAME = r'^[a-zA-Z0-9_-]{3,32}$'
    PASSWORD = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,128}$'
    PHONE = r'^\+?[1-9]\d{1,14}$'  # E.164 format
    UUID = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    
    # Stripe patterns
    STRIPE_CUSTOMER_ID = r'^cus_[A-Za-z0-9]{14,}$'
    STRIPE_PRICE_ID = r'^price_[A-Za-z0-9]{14,}$'
    STRIPE_SUBSCRIPTION_ID = r'^sub_[A-Za-z0-9]{14,}$'
    
    # File patterns
    SAFE_FILENAME = r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$'
    
    # SQL injection patterns to block
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)',
        r'(--|\#|\/\*|\*\/)',
        r'(\bOR\b\s*\d+\s*=\s*\d+)',
        r'(\bAND\b\s*\d+\s*=\s*\d+)',
        r'(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP))',
        r'(\bEXEC\b|\bEXECUTE\b)',
        r'(xp_cmdshell|sp_executesql)',
        r'(WAITFOR\s+DELAY)',
    ]
    
    # XSS patterns to block
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<embed[^>]*>',
        r'<object[^>]*>',
        r'eval\s*\(',
        r'expression\s*\(',
    ]
    
    # Path traversal patterns to block
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.[/\\]',
        r'\.\.%2[fF]',
        r'\.\.%5[cC]',
        r'%2[eE]%2[eE]',
        r'/etc/passwd',
        r'C:\\Windows',
        r'\\\\',
    ]


class InputValidator:
    """Comprehensive input validation utilities"""
    
    @staticmethod
    def sanitize_string(
        value: str,
        max_length: int = 1000,
        allow_html: bool = False,
        allowed_tags: Optional[List[str]] = None
    ) -> str:
        """
        Sanitize string input to prevent XSS and injection attacks
        """
        if not value:
            return ""
        
        # Truncate to max length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # HTML sanitization
        if allow_html:
            # Use bleach for safe HTML
            allowed_tags = allowed_tags or ['p', 'br', 'strong', 'em', 'u', 'a']
            allowed_attrs = {'a': ['href', 'title']}
            value = bleach.clean(
                value,
                tags=allowed_tags,
                attributes=allowed_attrs,
                strip=True
            )
        else:
            # Escape HTML entities
            value = html.escape(value)
        
        # Remove control characters except newlines and tabs
        value = ''.join(
            char for char in value 
            if char == '\n' or char == '\t' or 
            (ord(char) >= 32 and ord(char) != 127)
        )
        
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate and normalize email address"""
        try:
            # Use email-validator library
            validation = validate_email(email, check_deliverability=False)
            return validation.normalized
        except EmailNotValidError as e:
            raise ValueError(f"Invalid email: {str(e)}")
    
    @staticmethod
    def validate_url(
        url: str,
        allowed_schemes: Optional[List[str]] = None,
        require_tld: bool = True
    ) -> str:
        """Validate and sanitize URL"""
        if not url:
            raise ValueError("URL cannot be empty")
        
        allowed_schemes = allowed_schemes or ['http', 'https']
        
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in allowed_schemes:
                raise ValueError(f"Invalid URL scheme. Allowed: {allowed_schemes}")
            
            # Check for hostname
            if not parsed.netloc:
                raise ValueError("URL must have a valid hostname")
            
            # Check for TLD if required
            if require_tld and '.' not in parsed.netloc:
                raise ValueError("URL must have a valid domain")
            
            # Prevent localhost/private IPs in production
            if parsed.netloc in ['localhost', '127.0.0.1', '0.0.0.0']:
                raise ValueError("Local URLs not allowed")
            
            # Reconstruct clean URL
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            
            return clean_url
            
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    @staticmethod
    def validate_phone(phone: str) -> str:
        """Validate phone number (E.164 format)"""
        # Remove common formatting characters
        phone = re.sub(r'[\s\-\(\)]+', '', phone)
        
        # Ensure starts with + or digit
        if not phone.startswith('+'):
            phone = '+' + phone
        
        # Validate E.164 format
        if not re.match(ValidationPatterns.PHONE, phone):
            raise ValueError("Invalid phone number format")
        
        return phone
    
    @staticmethod
    def validate_username(username: str) -> str:
        """Validate username"""
        if not re.match(ValidationPatterns.USERNAME, username):
            raise ValueError(
                "Username must be 3-32 characters, alphanumeric, underscore, or hyphen"
            )
        return username
    
    @staticmethod
    def validate_password(password: str) -> str:
        """Validate password strength"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        if len(password) > 128:
            raise ValueError("Password must not exceed 128 characters")
        
        # Check complexity requirements
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '@$!%*?&' for c in password)
        
        if not (has_lower and has_upper and has_digit and has_special):
            raise ValueError(
                "Password must contain uppercase, lowercase, digit, and special character"
            )
        
        # Check for common passwords (simplified check)
        common_passwords = [
            'password', '12345678', 'qwerty', 'abc123', 'password123'
        ]
        if password.lower() in common_passwords:
            raise ValueError("Password is too common")
        
        return password
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """Validate UUID format"""
        if not re.match(ValidationPatterns.UUID, uuid_str.lower()):
            raise ValueError("Invalid UUID format")
        return uuid_str.lower()
    
    @staticmethod
    def validate_json(json_str: str, max_size: int = 1048576) -> Dict:
        """Validate and parse JSON safely"""
        if len(json_str) > max_size:
            raise ValueError(f"JSON exceeds maximum size of {max_size} bytes")
        
        try:
            data = json.loads(json_str)
            
            # Prevent deeply nested structures (JSON bomb attack)
            def check_depth(obj, depth=0, max_depth=10):
                if depth > max_depth:
                    raise ValueError("JSON nesting too deep")
                
                if isinstance(obj, dict):
                    for value in obj.values():
                        check_depth(value, depth + 1, max_depth)
                elif isinstance(obj, list):
                    for item in obj:
                        check_depth(item, depth + 1, max_depth)
            
            check_depth(data)
            return data
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
    
    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        """Detect potential SQL injection attempts"""
        if not value:
            return False
        
        value_upper = value.upper()
        
        for pattern in ValidationPatterns.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"Potential SQL injection detected: {value[:100]}")
                return True
        
        return False
    
    @staticmethod
    def detect_xss(value: str) -> bool:
        """Detect potential XSS attempts"""
        if not value:
            return False
        
        for pattern in ValidationPatterns.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential XSS detected: {value[:100]}")
                return True
        
        return False
    
    @staticmethod
    def detect_path_traversal(value: str) -> bool:
        """Detect path traversal attempts"""
        if not value:
            return False
        
        for pattern in ValidationPatterns.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential path traversal detected: {value[:100]}")
                return True
        
        return False
    
    @staticmethod
    def validate_safe_filename(filename: str) -> str:
        """Validate and sanitize filename"""
        if not filename:
            raise ValueError("Filename cannot be empty")
        
        # Remove path components
        filename = filename.replace('/', '').replace('\\', '')
        
        # Remove special characters
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:240] + ('.' + ext if ext else '')
        
        # Validate pattern
        if not re.match(ValidationPatterns.SAFE_FILENAME, filename):
            raise ValueError("Invalid filename format")
        
        # Check for dangerous extensions
        dangerous_extensions = [
            '.exe', '.dll', '.so', '.sh', '.bat', '.cmd', '.com',
            '.scr', '.vbs', '.js', '.jar', '.app', '.deb', '.rpm'
        ]
        
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            raise ValueError("Dangerous file extension not allowed")
        
        return filename
    
    @staticmethod
    def validate_stripe_id(stripe_id: str, id_type: str) -> str:
        """Validate Stripe ID format"""
        patterns = {
            'customer': ValidationPatterns.STRIPE_CUSTOMER_ID,
            'price': ValidationPatterns.STRIPE_PRICE_ID,
            'subscription': ValidationPatterns.STRIPE_SUBSCRIPTION_ID,
        }
        
        pattern = patterns.get(id_type)
        if not pattern:
            raise ValueError(f"Unknown Stripe ID type: {id_type}")
        
        if not re.match(pattern, stripe_id):
            raise ValueError(f"Invalid Stripe {id_type} ID format")
        
        return stripe_id


class SecureInputModel(BaseModel):
    """
    Base Pydantic model with built-in security validation
    All input models should inherit from this
    """
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_min_length=1,
        validate_assignment=True,
        arbitrary_types_allowed=False
    )
    
    @field_validator('*', mode='before')
    @classmethod
    def sanitize_all_strings(cls, v):
        """Automatically sanitize all string fields"""
        if isinstance(v, str):
            # Basic sanitization
            v = InputValidator.sanitize_string(v)
            
            # Check for injection attempts
            if InputValidator.detect_sql_injection(v):
                raise ValueError("Potential SQL injection detected")
            
            if InputValidator.detect_xss(v):
                raise ValueError("Potential XSS detected")
            
            if InputValidator.detect_path_traversal(v):
                raise ValueError("Potential path traversal detected")
        
        return v


# Example secure input models
class LoginRequest(SecureInputModel):
    """Secure login request model"""
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    mfa_code: Optional[str] = Field(None, pattern=r'^\d{6}$')
    
    @field_validator('email')
    @classmethod
    def validate_email_field(cls, v):
        return InputValidator.validate_email(v)
    
    @field_validator('password')
    @classmethod
    def validate_password_field(cls, v):
        # Don't validate password strength on login, just length
        return v


class RegisterRequest(SecureInputModel):
    """Secure registration request model"""
    username: str = Field(..., pattern=ValidationPatterns.USERNAME)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    phone: Optional[str] = None
    
    @field_validator('username')
    @classmethod
    def validate_username_field(cls, v):
        return InputValidator.validate_username(v)
    
    @field_validator('email')
    @classmethod
    def validate_email_field(cls, v):
        return InputValidator.validate_email(v)
    
    @field_validator('password')
    @classmethod
    def validate_password_field(cls, v):
        return InputValidator.validate_password(v)
    
    @field_validator('phone')
    @classmethod
    def validate_phone_field(cls, v):
        if v:
            return InputValidator.validate_phone(v)
        return v