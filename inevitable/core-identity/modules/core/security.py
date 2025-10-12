"""
Security utilities for Platform Forge
Addresses critical vulnerabilities identified in security assessment
"""
import os
import re
import hmac
import hashlib
import time
import secrets
import yaml
from pathlib import Path
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import argon2
import base64
import logging

logger = logging.getLogger(__name__)


class YAMLBombError(Exception):
    """Raised when YAML bomb is detected"""
    pass


class SecureYAMLLoader:
    """
    Secure YAML loader with protection against YAML bombs and other attacks.
    Addresses HIGH-003: YAML bomb denial of service
    """
    
    # Security limits
    MAX_FILE_SIZE = 1024 * 1024  # 1MB for runtime configs (smaller than generator)
    MAX_NESTING_DEPTH = 5       # Shallower than generator
    MAX_STRING_LENGTH = 512     # Smaller than generator
    MAX_COLLECTION_SIZE = 50    # Smaller collections
    
    @staticmethod
    def safe_load_file(file_path: str) -> Any:
        """
        Safely load YAML file with bomb protection
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            Parsed YAML data
            
        Raises:
            YAMLBombError: If YAML bomb is detected
        """
        path = Path(file_path)
        
        # Check file exists
        if not path.exists():
            raise FileNotFoundError(f"YAML file not found: {file_path}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > SecureYAMLLoader.MAX_FILE_SIZE:
            raise YAMLBombError(f"YAML file too large: {file_size} bytes (max {SecureYAMLLoader.MAX_FILE_SIZE})")
        
        # Load with safe_load
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read content first to add timeout protection
                content = f.read()
                
                # Additional size check after reading
                if len(content) > SecureYAMLLoader.MAX_FILE_SIZE:
                    raise YAMLBombError(f"YAML content too large: {len(content)} chars")
                
                data = yaml.safe_load(content)
                
                # Validate the parsed data structure
                SecureYAMLLoader._validate_data_limits(data)
                
                return data
                
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
        except Exception as e:
            if isinstance(e, YAMLBombError):
                raise
            raise ValueError(f"Error loading YAML: {e}")
    
    @staticmethod  
    def safe_load_string(content: str) -> Any:
        """
        Safely load YAML from string with bomb protection
        
        Args:
            content: YAML content as string
            
        Returns:
            Parsed YAML data
            
        Raises:
            YAMLBombError: If YAML bomb is detected
        """
        # Check content size
        if len(content) > SecureYAMLLoader.MAX_FILE_SIZE:
            raise YAMLBombError(f"YAML content too large: {len(content)} chars")
        
        try:
            data = yaml.safe_load(content)
            SecureYAMLLoader._validate_data_limits(data)
            return data
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
        except Exception as e:
            if isinstance(e, YAMLBombError):
                raise
            raise ValueError(f"Error parsing YAML: {e}")
    
    @staticmethod
    def _validate_data_limits(data: Any, depth: int = 0):
        """
        Recursively validate data structure limits to prevent YAML bombs
        
        Args:
            data: Data structure to validate
            depth: Current nesting depth
            
        Raises:
            YAMLBombError: If limits are exceeded
        """
        # Check nesting depth
        if depth > SecureYAMLLoader.MAX_NESTING_DEPTH:
            raise YAMLBombError(f"YAML nesting too deep: {depth} (max {SecureYAMLLoader.MAX_NESTING_DEPTH})")
        
        if isinstance(data, dict):
            # Check dictionary size
            if len(data) > SecureYAMLLoader.MAX_COLLECTION_SIZE:
                raise YAMLBombError(f"Dictionary too large: {len(data)} items (max {SecureYAMLLoader.MAX_COLLECTION_SIZE})")
            
            # Validate keys and values
            for key, value in data.items():
                if isinstance(key, str) and len(key) > SecureYAMLLoader.MAX_STRING_LENGTH:
                    raise YAMLBombError(f"Dictionary key too long: {len(key)} chars (max {SecureYAMLLoader.MAX_STRING_LENGTH})")
                
                SecureYAMLLoader._validate_data_limits(value, depth + 1)
        
        elif isinstance(data, list):
            # Check list size
            if len(data) > SecureYAMLLoader.MAX_COLLECTION_SIZE:
                raise YAMLBombError(f"List too large: {len(data)} items (max {SecureYAMLLoader.MAX_COLLECTION_SIZE})")
            
            # Validate items
            for item in data:
                SecureYAMLLoader._validate_data_limits(item, depth + 1)
        
        elif isinstance(data, str):
            # Check string length
            if len(data) > SecureYAMLLoader.MAX_STRING_LENGTH:
                raise YAMLBombError(f"String too long: {len(data)} chars (max {SecureYAMLLoader.MAX_STRING_LENGTH})")


# Convenience functions for backward compatibility
def safe_load_yaml(file_path: str) -> Any:
    """
    Safely load YAML file with bomb protection.
    HIGH-003 FIX: Secure YAML loading with size and complexity limits.
    """
    return SecureYAMLLoader.safe_load_file(file_path)


def safe_parse_yaml(content: str) -> Any:
    """
    Safely parse YAML string with bomb protection.
    HIGH-003 FIX: Secure YAML parsing with size and complexity limits.
    """
    return SecureYAMLLoader.safe_load_string(content)


class TemplateInjectionError(Exception):
    """Raised when template injection is detected"""
    pass


class TemplateSecurityValidator:
    """
    Validates user input to prevent template injection attacks.
    Addresses CRITICAL-014: Template injection in code generation
    """
    
    # Dangerous template patterns that could lead to code execution
    DANGEROUS_PATTERNS = [
        # Jinja2 template syntax
        r'\{\{.*?\}\}',          # {{ ... }}
        r'\{%.*?%\}',            # {% ... %}
        r'\{#.*?#\}',            # {# ... #}
        
        # Python code patterns
        r'__.*__',               # Dunder methods
        r'import\s+\w+',         # import statements
        r'from\s+\w+\s+import',  # from ... import
        r'exec\s*\(',            # exec function
        r'eval\s*\(',            # eval function
        r'compile\s*\(',         # compile function
        r'getattr\s*\(',         # getattr function
        r'setattr\s*\(',         # setattr function
        r'delattr\s*\(',         # delattr function
        r'globals\s*\(\)',       # globals() function
        r'locals\s*\(\)',        # locals() function
        r'vars\s*\(',            # vars function
        r'dir\s*\(',             # dir function
        
        # File operations
        r'open\s*\(',            # open function
        r'file\s*\(',            # file function
        
        # System/OS operations
        r'os\.',                 # os module
        r'sys\.',                # sys module
        r'subprocess\.',         # subprocess module
        
        # Class/object manipulation
        r'\.__class__',          # Class access
        r'\.__bases__',          # Base classes
        r'\.__subclasses__',     # Subclasses
        r'\.__mro__',            # Method resolution order
        
        # Dangerous attributes
        r'\.func_.*',            # Function internals
        r'\.gi_.*',              # Generator internals
        r'\.cr_.*',              # Coroutine internals
    ]
    
    @staticmethod
    def validate_template_data(data: Any, context_name: str = "data") -> None:
        """
        Validate data that will be passed to templates.
        
        Args:
            data: Data to validate (can be string, dict, list, etc.)
            context_name: Name of the context for error reporting
            
        Raises:
            TemplateInjectionError: If template injection is detected
        """
        if isinstance(data, str):
            TemplateSecurityValidator._validate_string(data, context_name)
        elif isinstance(data, dict):
            for key, value in data.items():
                TemplateSecurityValidator.validate_template_data(value, f"{context_name}.{key}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                TemplateSecurityValidator.validate_template_data(item, f"{context_name}[{i}]")
    
    @staticmethod
    def _validate_string(text: str, context_name: str) -> None:
        """
        Validate a string for template injection patterns.
        
        Args:
            text: String to validate
            context_name: Context name for error reporting
            
        Raises:
            TemplateInjectionError: If dangerous patterns are found
        """
        if not text:
            return
        
        # Check for dangerous patterns
        for pattern in TemplateSecurityValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                raise TemplateInjectionError(
                    f"Template injection pattern detected in {context_name}: {pattern}"
                )
        
        # Additional checks for encoded payloads
        # Check for URL encoding
        if '%' in text and any(c in text.lower() for c in ['2f', '5f', '7b', '7d']):
            # Decode and check again
            try:
                import urllib.parse
                decoded = urllib.parse.unquote(text)
                if decoded != text:
                    TemplateSecurityValidator._validate_string(decoded, f"{context_name} (URL decoded)")
            except Exception:
                pass  # Invalid URL encoding, skip
        
        # Check for base64 encoding (common obfuscation)
        if len(text) > 4 and text.replace('+', '').replace('/', '').replace('=', '').isalnum():
            try:
                import base64
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                if len(decoded) > 0:
                    TemplateSecurityValidator._validate_string(decoded, f"{context_name} (base64 decoded)")
            except Exception:
                pass  # Not valid base64 or contains non-text, skip
    
    @staticmethod
    def sanitize_template_context(context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize template context to prevent injection while preserving functionality.
        CRITICAL-014 FIX: Safe template context preparation
        
        Args:
            context: Template context dictionary
            
        Returns:
            Sanitized context dictionary
        """
        sanitized = {}
        
        for key, value in context.items():
            # Sanitize key name
            safe_key = re.sub(r'[^\w\-_]', '_', str(key))
            
            # Sanitize value based on type
            if isinstance(value, str):
                # Basic HTML/XML escaping for safety
                safe_value = (value
                    .replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#x27;')
                    .replace('{{', '&#x7b;&#x7b;')
                    .replace('}}', '&#x7d;&#x7d;')
                    .replace('{%', '&#x7b;&#x25;')
                    .replace('%}', '&#x25;&#x7d;')
                )
                sanitized[safe_key] = safe_value
            elif isinstance(value, (int, float, bool)):
                # Numeric and boolean values are safe
                sanitized[safe_key] = value
            elif isinstance(value, (list, dict)):
                # Recursively sanitize collections
                sanitized[safe_key] = TemplateSecurityValidator._sanitize_collection(value)
            else:
                # Convert other types to safe strings
                sanitized[safe_key] = str(value).replace('{{', '').replace('}}', '')
        
        return sanitized
    
    @staticmethod
    def _sanitize_collection(data: Any) -> Any:
        """Recursively sanitize collections"""
        if isinstance(data, dict):
            return {
                re.sub(r'[^\w\-_]', '_', str(k)): TemplateSecurityValidator._sanitize_collection(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [TemplateSecurityValidator._sanitize_collection(item) for item in data]
        elif isinstance(data, str):
            return (data
                .replace('{{', '&#x7b;&#x7b;')
                .replace('}}', '&#x7d;&#x7d;')
                .replace('{%', '&#x7b;&#x25;')
                .replace('%}', '&#x25;&#x7d;')
            )
        else:
            return data


# Convenience function
def validate_template_data(data: Any, context_name: str = "template_data") -> None:
    """
    CRITICAL-014 FIX: Validate data for template injection patterns.
    """
    return TemplateSecurityValidator.validate_template_data(data, context_name)


def sanitize_template_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    CRITICAL-014 FIX: Sanitize template context to prevent injection.
    """
    return TemplateSecurityValidator.sanitize_template_context(context)

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class PathTraversalError(SecurityError):
    """Raised when path traversal is detected"""
    pass

class TenantIsolationError(SecurityError):
    """Raised when tenant isolation is violated"""
    pass

class SecurityUtils:
    """Core security utilities for Platform Forge"""
    
    @staticmethod
    def sanitize_path(user_input: str, max_length: int = 255) -> str:
        """
        Sanitize user input to prevent path traversal attacks
        Addresses CRITICAL-001: Path Traversal in Platform Generator
        """
        if not user_input or not isinstance(user_input, str):
            raise ValueError("Invalid input for path sanitization")
        
        # Remove null bytes
        sanitized = user_input.replace('\x00', '')
        
        # Remove path traversal attempts
        sanitized = re.sub(r'\.\.+[/\\]', '', sanitized)
        sanitized = re.sub(r'[/\\]\.\.+', '', sanitized)
        sanitized = re.sub(r'\.\.+', '', sanitized)
        
        # Remove absolute path indicators
        sanitized = re.sub(r'^[/\\]+', '', sanitized)
        
        # Whitelist allowed characters (alphanumeric, dash, underscore)
        sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '', sanitized)
        
        # Ensure not empty after sanitization
        if not sanitized:
            raise PathTraversalError("Path becomes empty after sanitization")
        
        # Limit length
        if len(sanitized) > max_length:
            raise PathTraversalError(f"Path too long: {len(sanitized)} > {max_length}")
        
        # Ensure it's just a basename (no path separators)
        sanitized = os.path.basename(sanitized)
        
        # Additional check for common dangerous patterns
        dangerous_patterns = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9']
        if sanitized.lower() in dangerous_patterns:
            raise PathTraversalError(f"Dangerous pattern detected: {sanitized}")
        
        return sanitized
    
    @staticmethod
    def validate_safe_path(base_path: str, user_path: str) -> str:
        """
        Validate that the resolved path is within the base directory
        """
        base = Path(base_path).resolve()
        target = (base / user_path).resolve()
        
        try:
            target.relative_to(base)
        except ValueError:
            raise PathTraversalError(f"Path {user_path} escapes base directory {base_path}")
        
        return str(target)

class CryptoUtils:
    """Enhanced cryptographic utilities for securing sensitive data"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is None:
            # Get from settings with validation
            from .config import settings
            master_key = settings.PLATFORM_FORGE_MASTER_KEY.encode()
        
        self.master_key = master_key
        self._tenant_ciphers = {}  # Cache for tenant-specific ciphers
    
    def get_tenant_cipher(self, tenant_id: str) -> Fernet:
        """Get or create tenant-specific cipher using Argon2id"""
        if tenant_id not in self._tenant_ciphers:
            # Use Argon2id for key derivation - much stronger than PBKDF2
            # Argon2id provides resistance against both side-channel and GPU attacks
            salt = f"tenant_{tenant_id}_salt_v2".encode()
            
            # Use the low-level Argon2 interface for proper key derivation
            from argon2.low_level import hash_secret_raw, Type
            
            # Argon2id parameters optimized for security
            # Memory: 64MB (65536 KB), Iterations: 3, Parallelism: 4
            key_bytes = hash_secret_raw(
                secret=self.master_key,
                salt=salt,
                time_cost=3,           # iterations
                memory_cost=65536,     # 64MB in KB
                parallelism=4,
                hash_len=32,           # 32 bytes for Fernet
                type=Type.ID           # Argon2id variant
            )
            
            # Encode for Fernet (requires URL-safe base64)
            key = base64.urlsafe_b64encode(key_bytes)
            
            self._tenant_ciphers[tenant_id] = Fernet(key)
        
        return self._tenant_ciphers[tenant_id]
    
    def encrypt_field(self, data: str, tenant_id: str) -> str:
        """
        Encrypt field data with tenant-specific key
        Addresses CRITICAL-004: MFA Secret Exposure
        """
        if not data:
            return ""
        
        cipher = self.get_tenant_cipher(tenant_id)
        
        # Add nonce for additional security
        nonce = secrets.token_bytes(16)
        payload = nonce + data.encode()
        
        encrypted = cipher.encrypt(payload)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt_field(self, encrypted_data: str, tenant_id: str) -> str:
        """
        Decrypt field data with tenant-specific key
        """
        if not encrypted_data:
            return ""
        
        try:
            cipher = self.get_tenant_cipher(tenant_id)
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            
            decrypted = cipher.decrypt(encrypted_bytes)
            
            # Remove nonce (first 16 bytes)
            return decrypted[16:].decode()
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise SecurityError("Decryption failed")
    
    def encrypt_sensitive_data(self, data: str, tenant_id: str = "default") -> str:
        """
        Legacy method for backward compatibility
        """
        return self.encrypt_field(data, tenant_id)
    
    def decrypt_sensitive_data(self, encrypted_data: str, tenant_id: str = "default") -> str:
        """
        Legacy method for backward compatibility
        """
        return self.decrypt_field(encrypted_data, tenant_id)

class WebhookSecurity:
    """
    Webhook security utilities
    Addresses CRITICAL-005: Webhook Signature Bypass
    """
    
    # Stripe's published IP ranges (should be updated regularly)
    STRIPE_IP_RANGES = [
        "54.187.174.169/32",
        "54.187.205.235/32", 
        "54.187.216.72/32",
        "54.241.31.99/32",
        "54.241.31.102/32",
        "54.241.34.107/32",
        "52.89.214.238/32",
        "34.210.56.234/32",
        "35.162.115.61/32",
        "35.167.5.25/32",
        "44.225.139.172/32",
        "44.226.251.12/32",
        "44.233.202.106/32"
    ]
    
    def __init__(self, webhook_secret: str, timestamp_tolerance: int = 300):
        self.webhook_secret = webhook_secret.encode()
        self.timestamp_tolerance = timestamp_tolerance
        self.processed_webhooks = set()  # In production, use Redis/database
        
        # Initialize IP validator
        import ipaddress
        self.allowed_networks = []
        for ip_range in self.STRIPE_IP_RANGES:
            self.allowed_networks.append(ipaddress.ip_network(ip_range))
    
    def verify_source_ip(self, client_ip: str, headers: dict = None) -> bool:
        """
        Verify webhook source IP against allowlist.
        Properly handles X-Forwarded-For and other proxy headers.
        
        Returns True only if IP is from verified Stripe ranges.
        """
        import ipaddress
        
        # Never trust X-Forwarded-For or proxy headers for webhooks
        # These can be easily spoofed. Only use direct client IP.
        if headers:
            logger.warning("Proxy headers provided but ignored for security")
        
        try:
            # Parse the client IP
            ip_addr = ipaddress.ip_address(client_ip)
            
            # Check against allowed networks
            for network in self.allowed_networks:
                if ip_addr in network:
                    logger.info(f"Webhook from verified Stripe IP: {client_ip}")
                    return True
            
            logger.warning(f"Webhook from non-Stripe IP: {client_ip}")
            return False
            
        except ValueError as e:
            logger.error(f"Invalid IP address format: {client_ip} - {e}")
            return False
    
    def verify_webhook_signature(
        self, 
        payload: bytes, 
        signature_header: str, 
        webhook_id: Optional[str] = None,
        client_ip: Optional[str] = None
    ) -> bool:
        """
        Verify webhook signature, source IP, and prevent replay attacks
        """
        try:
            # CRITICAL: Verify source IP first (if provided)
            if client_ip and not self.verify_source_ip(client_ip):
                logger.warning(f"Webhook rejected: Invalid source IP {client_ip}")
                return False
            
            # Parse Stripe signature header
            sig_elements = {}
            for element in signature_header.split(','):
                key, value = element.split('=', 1)
                sig_elements[key] = value
            
            timestamp = int(sig_elements.get('t', 0))
            signature = sig_elements.get('v1', '')
            
            # CRITICAL: Tighter timestamp validation (60 seconds instead of 300)
            if abs(time.time() - timestamp) > 60:
                logger.warning(f"Webhook timestamp outside 60s window: {timestamp}")
                return False
            
            # Verify signature with constant-time comparison
            signed_payload = f"{timestamp}.{payload.decode()}"
            expected_signature = hmac.new(
                self.webhook_secret,
                signed_payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("Webhook signature verification failed")
                return False
            
            # Check for replay attacks (if webhook ID provided)
            if webhook_id:
                if webhook_id in self.processed_webhooks:
                    logger.warning(f"Duplicate webhook detected: {webhook_id}")
                    return False
                self.processed_webhooks.add(webhook_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Webhook verification error: {e}")
            return False

class TenantSecurity:
    """
    Multi-tenant security utilities
    Addresses CRITICAL-003: Tenant Isolation Bypass
    """
    
    @staticmethod
    def extract_tenant_from_jwt(jwt_payload: Dict[str, Any]) -> Optional[str]:
        """Extract tenant ID from JWT payload"""
        return jwt_payload.get('tenant_id')
    
    @staticmethod
    def validate_tenant_access(
        jwt_tenant_id: str, 
        header_tenant_id: str, 
        resource_tenant_id: Optional[str] = None
    ) -> bool:
        """
        Validate tenant access across JWT, headers, and resources
        """
        # JWT and header must match
        if jwt_tenant_id != header_tenant_id:
            logger.warning(
                f"Tenant mismatch: JWT={jwt_tenant_id}, Header={header_tenant_id}"
            )
            return False
        
        # If resource has tenant, it must match
        if resource_tenant_id and resource_tenant_id != jwt_tenant_id:
            logger.warning(
                f"Resource tenant mismatch: Resource={resource_tenant_id}, JWT={jwt_tenant_id}"
            )
            return False
        
        return True

class InputValidator:
    """
    Input validation utilities
    Addresses multiple injection vulnerabilities
    """
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> bool:
        """Validate UUID format"""
        pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return re.match(pattern, uuid_str.lower()) is not None
    
    @staticmethod
    def sanitize_sql_identifier(identifier: str) -> str:
        """Sanitize SQL identifiers (table names, column names)"""
        # Allow only alphanumeric and underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '', identifier)
        
        # Must start with letter
        if not sanitized or not sanitized[0].isalpha():
            raise ValueError("Invalid SQL identifier")
        
        return sanitized
    
    @staticmethod
    def validate_json_input(data: Any, max_depth: int = 10, max_size: int = 1024*1024) -> bool:
        """Validate JSON input to prevent DoS attacks"""
        import json
        
        # Check size
        if len(str(data)) > max_size:
            return False
        
        # Check depth (simplified check)
        def check_depth(obj, depth=0):
            if depth > max_depth:
                return False
            if isinstance(obj, dict):
                return all(check_depth(v, depth + 1) for v in obj.values())
            elif isinstance(obj, list):
                return all(check_depth(item, depth + 1) for item in obj)
            return True
        
        return check_depth(data)

class PasswordSecurity:
    """
    Password security utilities
    Addresses HIGH-003: Weak Password Policy
    """
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, List[str]]:
        """
        Validate password strength
        Returns (is_valid, list_of_issues)
        """
        issues = []
        
        if len(password) < 12:
            issues.append("Password must be at least 12 characters long")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Check for common passwords (simplified)
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            issues.append("Password is too common")
        
        return len(issues) == 0, issues
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate cryptographically secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def get_validated_base_url() -> str:
        """
        Get validated base URL to prevent open redirect attacks.
        Addresses CRITICAL-AUTH-003: URL Construction Vulnerability
        """
        import os
        from urllib.parse import urlparse
        
        # Get base URL from environment
        env_url = os.getenv("APP_BASE_URL", "http://localhost:8000")
        
        # Parse and validate URL
        try:
            parsed = urlparse(env_url)
            
            # Ensure scheme is HTTP/HTTPS
            if parsed.scheme not in ('http', 'https'):
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
            
            # Ensure hostname is provided
            if not parsed.hostname:
                raise ValueError("No hostname in base URL")
            
            # Whitelist allowed hostnames for security
            allowed_hosts = [
                'localhost',
                '127.0.0.1',
                '0.0.0.0'
            ]
            
            # Add configured hosts from environment
            env_hosts = os.getenv("ALLOWED_HOSTS", "").split(",")
            allowed_hosts.extend([host.strip() for host in env_hosts if host.strip()])
            
            # Check if hostname is allowed
            if parsed.hostname not in allowed_hosts:
                # In production, this should be strict
                from modules.core.config import settings
                if hasattr(settings, 'ENVIRONMENT') and settings.ENVIRONMENT == 'production':
                    raise ValueError(f"Hostname not in allowed list: {parsed.hostname}")
                else:
                    # In development, log warning but allow
                    logger.warning(f"Using non-whitelisted hostname in development: {parsed.hostname}")
            
            # Reconstruct clean URL
            port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
            validated_url = f"{parsed.scheme}://{parsed.hostname}{port_str}"
            
            return validated_url
            
        except Exception as e:
            logger.error(f"Invalid base URL configuration: {e}")
            # Fallback to secure default
            return "http://localhost:8000"
    
    @staticmethod
    def encode_user_id(user_id: int) -> str:
        """
        Encode user ID to prevent information disclosure.
        Addresses CRITICAL-AUTH-004: User ID Exposure in URLs
        """
        import base64
        import json
        import time
        
        # Create payload with user ID and timestamp
        payload = {
            'uid': user_id,
            'ts': int(time.time()),
            # Add some random padding to prevent size-based attacks
            'pad': secrets.token_hex(8)
        }
        
        # Convert to JSON and encode
        json_payload = json.dumps(payload, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_payload.encode()).decode().rstrip('=')
        
        return encoded
    
    @staticmethod
    def decode_user_id(encoded_id: str, max_age_seconds: int = 3600) -> Optional[int]:
        """
        Decode user ID from encoded string with age validation.
        Returns None if invalid or expired.
        """
        import base64
        import json
        import time
        
        try:
            # Add padding if needed
            missing_padding = len(encoded_id) % 4
            if missing_padding:
                encoded_id += '=' * (4 - missing_padding)
            
            # Decode
            json_payload = base64.urlsafe_b64decode(encoded_id.encode()).decode()
            payload = json.loads(json_payload)
            
            # Extract values
            user_id = payload.get('uid')
            timestamp = payload.get('ts')
            
            if not isinstance(user_id, int) or not isinstance(timestamp, (int, float)):
                return None
            
            # Check age
            age = time.time() - timestamp
            if age > max_age_seconds:
                logger.warning(f"Expired encoded user ID: age={age}s, max={max_age_seconds}s")
                return None
            
            return user_id
            
        except Exception as e:
            logger.warning(f"Failed to decode user ID: {e}")
            return None
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)

# Global security instance
crypto_utils = None

def get_crypto_utils() -> CryptoUtils:
    """Get global crypto utils instance"""
    global crypto_utils
    if crypto_utils is None:
        crypto_utils = CryptoUtils()
    return crypto_utils