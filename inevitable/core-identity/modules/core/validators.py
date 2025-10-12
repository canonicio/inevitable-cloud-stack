"""
Comprehensive input validation for Platform Forge
Addresses MEDIUM-001: Missing Input Validation
"""
import re
from typing import Optional, Annotated, List, Dict, Any
from pydantic import BaseModel, Field, field_validator, EmailStr, conint
from fastapi import HTTPException, status
from datetime import datetime
import ipaddress
import urllib.parse

# Security-focused regex patterns
class ValidationPatterns:
    """Common regex patterns for validation"""
    
    # Alphanumeric with limited special chars (safe for identifiers)
    SAFE_IDENTIFIER = r'^[a-zA-Z0-9_\-]+$'
    
    # Username: alphanumeric, underscore, dash, dot (3-32 chars)
    USERNAME = r'^[a-zA-Z0-9_\-\.]{3,32}$'
    
    # Safe string: no control characters or dangerous patterns
    SAFE_STRING = r'^[^\x00-\x1F\x7F<>&\'"`]*$'
    
    # Phone number (international format)
    PHONE = r'^\+?[1-9]\d{1,14}$'
    
    # URL safe slug
    URL_SLUG = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
    
    # File name (safe characters only)
    SAFE_FILENAME = r'^[a-zA-Z0-9_\-\.]+$'
    
    # MEDIUM FIX: Enhanced SQL injection patterns for edge cases
    SQL_INJECTION_PATTERNS = [
        r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|merge|with)\b)',
        r'(--|;|\/\*|\*\/|xp_|sp_|fn_)',
        r'(\b(or|and)\b\s*[\d\'\"]+\s*[=><]\s*[\d\'\"]+)',
        r'(\b(or|and)\b\s+[\d\'\"]+)',  # Boolean-based injection
        r'(char|chr|ascii|substring|concat|cast|convert|hex|unhex)\s*\(',
        r'(waitfor\s+delay|benchmark|sleep|pg_sleep)\s*\(',
        r'(load_file|into\s+outfile|into\s+dumpfile)',
        r'(\$\$|\@\@|#)',  # MySQL/PostgreSQL specific
        r'(information_schema|mysql\.|sys\.|pg_)',  # System schemas
    ]
    
    # MEDIUM FIX: Enhanced XSS patterns for edge cases  
    XSS_PATTERNS = [
        r'<\s*script',
        r'javascript\s*:',
        r'on\w+\s*=',
        r'<\s*(iframe|object|embed|applet|form|img|svg|math|details)',
        r'eval\s*\(',
        r'expression\s*\(',
        r'data\s*:\s*text/html',  # Data URI XSS
        r'vbscript\s*:',
        r'(document\.|window\.|alert\(|confirm\(|prompt\()',
        r'<\s*style[^>]*>.*?</\s*style\s*>',  # CSS injection
        r'@import\s*["\']',  # CSS import injection
        r'&\s*#\s*\d+\s*;',  # HTML entity encoding
        r'\\u[0-9a-fA-F]{4}',  # Unicode escape
    ]
    
    # MEDIUM FIX: Enhanced path traversal patterns for edge cases
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.[/\\]',
        r'\.\.%2[fF]',
        r'%2[eE]%2[eE]',
        r'\.\.\\',
        r'%c0%af',  # UTF-8 overlong encoding
        r'%c1%9c',  # UTF-8 overlong encoding
        r'\.{2,}[/\\]',  # Multiple dots
        r'[/\\]\.{2,}',
        r'file\s*:\s*/',  # File protocol
        r'\\\\[^\\]+\\',  # UNC paths
    ]
    
    # MEDIUM FIX: Additional dangerous patterns
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$(){}[\]<>]',  # Shell metacharacters
        r'(system|exec|shell_exec|passthru|eval|popen|proc_open)\s*\(',
        r'(wget|curl|nc|netcat|telnet|ssh)\s+',
        r'(/bin/|/usr/bin/|/sbin/|cmd\.exe|powershell)',
    ]
    
    LDAP_INJECTION_PATTERNS = [
        r'[()&|!*\\]',  # LDAP metacharacters
        r'(objectclass|cn=|uid=|ou=|dc=)',
    ]


class BaseValidator(BaseModel):
    """Base validator with common validation methods"""
    
    class Config:
        # Strip whitespace from strings
        str_strip_whitespace = True
        # Validate on assignment
        validate_assignment = True
        # Use enum values
        use_enum_values = True
    
    @staticmethod
    def validate_no_injection(value: str, field_name: str = "input") -> str:
        """
        MEDIUM FIX: Comprehensive injection validation covering all attack vectors
        Addresses MEDIUM-001: Input validation edge cases
        """
        if not value:
            return value
        
        # Check for SQL injection
        for pattern in ValidationPatterns.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains potentially dangerous SQL patterns")
        
        # Check for XSS
        for pattern in ValidationPatterns.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains potentially dangerous script patterns")
        
        # Check for path traversal
        for pattern in ValidationPatterns.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains path traversal patterns")
        
        # MEDIUM FIX: Check for command injection
        for pattern in ValidationPatterns.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains potentially dangerous command patterns")
        
        # MEDIUM FIX: Check for LDAP injection
        for pattern in ValidationPatterns.LDAP_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"{field_name} contains potentially dangerous LDAP patterns")
        
        # MEDIUM FIX: Check for null bytes and control characters
        if '\x00' in value or any(ord(c) < 32 and c not in '\t\n\r' for c in value):
            raise ValueError(f"{field_name} contains control characters or null bytes")
        
        # MEDIUM FIX: Check for excessive length to prevent DoS
        if len(value) > 10000:  # 10KB limit for most fields
            raise ValueError(f"{field_name} is too long (max 10000 characters)")
        
        # MEDIUM FIX: Check for suspicious repeating patterns (potential fuzzing)
        if len(set(value)) < len(value) / 10 and len(value) > 100:
            raise ValueError(f"{field_name} contains suspicious repeating patterns")
        
        return value
    
    @staticmethod
    def validate_safe_html(value: str, field_name: str = "input") -> str:
        """Validate HTML content with restricted tags"""
        if not value:
            return value
        
        # Only allow very basic HTML tags for rich text
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li']
        import html
        
        # First escape all HTML
        escaped = html.escape(value)
        
        # Then selectively unescape allowed tags
        for tag in allowed_tags:
            escaped = escaped.replace(f'&lt;{tag}&gt;', f'<{tag}>')
            escaped = escaped.replace(f'&lt;/{tag}&gt;', f'</{tag}>')
        
        return escaped


# Authentication validators
class LoginRequest(BaseValidator):
    """Validate login request"""
    username: Annotated[str, Field(min_length=1, max_length=255, strip_whitespace=True)]
    password: Annotated[str, Field(min_length=1, max_length=255)]
    mfa_token: Optional[Annotated[str, Field(pattern=r'^\d{6}$')]] = None
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        # Allow email or username format
        if '@' in v:
            # Validate as email
            try:
                EmailStr.validate(v)
            except:
                raise ValueError("Invalid email format")
        else:
            # Validate as username
            if not re.match(ValidationPatterns.USERNAME, v):
                raise ValueError("Username must be 3-32 characters, alphanumeric with underscore, dash, or dot")
        return v


class UserRegistration(BaseValidator):
    """Validate user registration"""
    username: Annotated[str, Field(pattern=ValidationPatterns.USERNAME, min_length=3, max_length=32)]
    email: EmailStr
    password: Annotated[str, Field(min_length=12, max_length=128)]
    first_name: Optional[Annotated[str, Field(max_length=50, pattern=ValidationPatterns.SAFE_STRING)]] = None
    last_name: Optional[Annotated[str, Field(max_length=50, pattern=ValidationPatterns.SAFE_STRING)]] = None
    tenant_id: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER, max_length=100)]] = None
    
    @field_validator('username')
    @classmethod
    def validate_username_not_reserved(cls, v):
        """Ensure username is not a reserved word"""
        reserved = {'admin', 'root', 'administrator', 'system', 'user', 'test', 'demo'}
        if v.lower() in reserved:
            raise ValueError("Username is reserved")
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        """Enforce password complexity requirements"""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        
        checks = [
            (r'[A-Z]', "uppercase letter"),
            (r'[a-z]', "lowercase letter"),
            (r'\d', "digit"),
            (r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?]', "special character")
        ]
        
        for pattern, requirement in checks:
            if not re.search(pattern, v):
                raise ValueError(f"Password must contain at least one {requirement}")
        
        return v


class PasswordReset(BaseValidator):
    """Validate password reset request"""
    email: EmailStr
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return BaseValidator.validate_no_injection(v, "email")


class PasswordResetConfirm(BaseValidator):
    """Validate password reset confirmation"""
    token: Annotated[str, Field(min_length=32, max_length=128, pattern=r'^[a-zA-Z0-9_-]+$')]
    new_password: Annotated[str, Field(min_length=8, max_length=128)]
    
    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        """Validate reset token format"""
        if not v or len(v) < 32:
            raise ValueError("Invalid token format")
        return BaseValidator.validate_no_injection(v, "token")
    
    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password strength"""
        if not v or len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Check for basic password complexity
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return BaseValidator.validate_no_injection(v, "password")


# Admin validators
class AuditLogQuery(BaseValidator):
    """Validate audit log query parameters"""
    user_id: Optional[Annotated[int, Field(gt=0)]] = None
    action: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER, max_length=100)]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: Annotated[int, Field(ge=1, le=1000)] = 100
    offset: Annotated[int, Field(ge=0)] = 0
    
    @field_validator('end_date')
    @classmethod
    def validate_date_range(cls, v, values):
        if v and 'start_date' in values and values['start_date']:
            if v < values['start_date']:
                raise ValueError("End date must be after start date")
        return v


# Billing validators
class CreateCheckoutSession(BaseValidator):
    """Validate checkout session creation"""
    package_id: Annotated[int, Field(gt=0)]
    success_url: str
    cancel_url: str
    
    @field_validator('success_url', 'cancel_url')
    @classmethod
    def validate_urls(cls, v):
        """Validate URLs are safe and properly formatted"""
        try:
            parsed = urllib.parse.urlparse(v)
            # Ensure URL has scheme and netloc
            if not all([parsed.scheme, parsed.netloc]):
                raise ValueError("Invalid URL format")
            # Only allow http/https
            if parsed.scheme not in ['http', 'https']:
                raise ValueError("Only HTTP/HTTPS URLs are allowed")
            # Prevent javascript: and data: URLs
            if parsed.scheme in ['javascript', 'data', 'vbscript']:
                raise ValueError("Dangerous URL scheme not allowed")
        except Exception:
            raise ValueError("Invalid URL format")
        return v


# General validators
class PaginationParams(BaseValidator):
    """Validate pagination parameters"""
    page: Annotated[int, Field(ge=1)] = 1
    per_page: Annotated[int, Field(ge=1, le=100)] = 20
    sort_by: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER)]] = None
    sort_order: Optional[Annotated[str, Field(pattern=r'^(asc|desc)$')]] = 'asc'


class SearchQuery(BaseValidator):
    """Validate search query"""
    q: Annotated[str, Field(min_length=1, max_length=255)]
    fields: Optional[List[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER)]]] = None
    
    @field_validator('q')
    @classmethod
    def validate_search_query(cls, v):
        """Sanitize search query"""
        # Remove potentially dangerous characters
        v = re.sub(r'[<>&\'"`]', '', v)
        # Limit consecutive spaces
        v = re.sub(r'\s+', ' ', v)
        return v.strip()


class FileUpload(BaseValidator):
    """Validate file upload parameters"""
    filename: Annotated[str, Field(pattern=ValidationPatterns.SAFE_FILENAME, max_length=255)]
    content_type: Annotated[str, Field(max_length=100)]
    size: Annotated[int, Field(gt=0, le=10*1024*1024)]  # Max 10MB
    
    @field_validator('content_type')
    @classmethod
    def validate_content_type(cls, v):
        """Validate allowed content types"""
        allowed_types = {
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'text/plain', 'text/csv',
            'application/json', 'application/xml'
        }
        if v not in allowed_types:
            raise ValueError(f"Content type {v} not allowed")
        return v
    
    @field_validator('filename')
    @classmethod
    def validate_filename_extension(cls, v, values):
        """Validate file extension matches content type"""
        extension_map = {
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/gif': ['.gif'],
            'image/webp': ['.webp'],
            'application/pdf': ['.pdf'],
            'text/plain': ['.txt'],
            'text/csv': ['.csv'],
            'application/json': ['.json'],
            'application/xml': ['.xml'],
        }
        
        if 'content_type' in values:
            content_type = values['content_type']
            allowed_extensions = extension_map.get(content_type, [])
            
            if allowed_extensions:
                if not any(v.lower().endswith(ext) for ext in allowed_extensions):
                    raise ValueError(f"File extension doesn't match content type {content_type}")
        
        return v


# Utility functions
def validate_ip_address(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_uuid(uuid_string: str) -> bool:
    """Validate UUID format"""
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid_string))


def sanitize_html(html: str) -> str:
    """Basic HTML sanitization (for display, not storage)"""
    # This is a basic implementation. For production, use a library like bleach
    # Remove script tags and their content
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove event handlers
    html = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
    # Remove javascript: URLs
    html = re.sub(r'javascript\s*:', '', html, flags=re.IGNORECASE)
    return html


def validate_json_schema(data: Dict[str, Any], max_depth: int = 10) -> bool:
    """Validate JSON doesn't have excessive nesting"""
    def check_depth(obj, current_depth=0):
        if current_depth > max_depth:
            return False
        
        if isinstance(obj, dict):
            return all(check_depth(v, current_depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            return all(check_depth(item, current_depth + 1) for item in obj)
        
        return True
    
    return check_depth(data)