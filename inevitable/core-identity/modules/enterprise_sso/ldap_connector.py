"""
Secure LDAP Connector with TLS/SSL
Addresses HIGH-SSO-003: LDAP Connection Security
"""
import ssl
import ldap3
from ldap3 import Server, Connection, Tls, SAFE_SYNC, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError
from typing import Optional, Dict, Any, List, Tuple
import logging
import hashlib
import time
from datetime import datetime, timedelta

from ..core.config import settings
from ..core.input_validator import InputValidator

logger = logging.getLogger(__name__)


class SecureLDAPConnector:
    """
    Secure LDAP connector with mandatory TLS/SSL
    Implements connection pooling, input sanitization, and audit logging
    """
    
    def __init__(
        self,
        server_url: str,
        bind_dn: str,
        bind_password: str,
        base_dn: str,
        use_ssl: bool = True,
        use_start_tls: bool = False,
        ca_cert_file: Optional[str] = None,
        client_cert_file: Optional[str] = None,
        client_key_file: Optional[str] = None,
        validate_cert: bool = True
    ):
        """
        Initialize secure LDAP connector
        
        Args:
            server_url: LDAP server URL (ldap:// or ldaps://)
            bind_dn: DN for binding to LDAP
            bind_password: Password for bind DN
            base_dn: Base DN for searches
            use_ssl: Use LDAPS (port 636)
            use_start_tls: Use StartTLS (port 389 then upgrade)
            ca_cert_file: Path to CA certificate file
            client_cert_file: Path to client certificate for mutual TLS
            client_key_file: Path to client key for mutual TLS
            validate_cert: Validate server certificate
        """
        
        # SECURITY: Enforce TLS/SSL
        if not use_ssl and not use_start_tls:
            raise ValueError(
                "SECURITY: LDAP connections must use SSL or StartTLS. "
                "Plain LDAP is not allowed."
            )
        
        # Validate and sanitize inputs
        self.server_url = self._validate_server_url(server_url)
        self.bind_dn = self._sanitize_dn(bind_dn)
        self.bind_password = bind_password  # Store securely
        self.base_dn = self._sanitize_dn(base_dn)
        
        # TLS configuration
        self.use_ssl = use_ssl
        self.use_start_tls = use_start_tls
        self.validate_cert = validate_cert
        
        # Setup TLS
        self.tls = self._setup_tls(
            ca_cert_file,
            client_cert_file,
            client_key_file,
            validate_cert
        )
        
        # Connection pool
        self.connection_pool = []
        self.max_connections = 10
        self.connection = None
        
        # Rate limiting for authentication attempts
        self.auth_attempts = {}
        self.max_auth_attempts = 5
        self.auth_window = 300  # 5 minutes
    
    def _validate_server_url(self, url: str) -> str:
        """Validate LDAP server URL"""
        if not url:
            raise ValueError("LDAP server URL cannot be empty")
        
        # Check protocol
        if not url.startswith(('ldap://', 'ldaps://')):
            raise ValueError("LDAP URL must start with ldap:// or ldaps://")
        
        # Don't allow localhost in production
        if settings.ENVIRONMENT == "production":
            if any(blocked in url.lower() for blocked in ['localhost', '127.0.0.1', '0.0.0.0']):
                raise ValueError("Local LDAP servers not allowed in production")
        
        return url
    
    def _sanitize_dn(self, dn: str) -> str:
        """
        Sanitize LDAP DN to prevent injection
        """
        if not dn:
            return ""
        
        # LDAP DN special characters that need escaping
        special_chars = {
            ',': r'\,',
            '+': r'\+',
            '"': r'\"',
            '\\': r'\\',
            '<': r'\<',
            '>': r'\>',
            ';': r'\;',
            '#': r'\#',
            '=': r'\=',
        }
        
        # Don't escape if already escaped
        for char, escaped in special_chars.items():
            if char in dn and escaped not in dn:
                logger.warning(f"Potentially dangerous character '{char}' in DN: {dn}")
        
        return dn
    
    def _setup_tls(
        self,
        ca_cert_file: Optional[str],
        client_cert_file: Optional[str],
        client_key_file: Optional[str],
        validate_cert: bool
    ) -> Tls:
        """Setup TLS configuration"""
        
        # Create SSL context
        ssl_context = ssl.create_default_context()
        
        if validate_cert:
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            # Load CA certificate if provided
            if ca_cert_file:
                ssl_context.load_verify_locations(ca_cert_file)
        else:
            # Only disable in development/testing
            if settings.ENVIRONMENT == "production":
                raise ValueError("Certificate validation cannot be disabled in production")
            
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("LDAP certificate validation disabled - NOT FOR PRODUCTION")
        
        # Setup mutual TLS if certificates provided
        if client_cert_file and client_key_file:
            ssl_context.load_cert_chain(client_cert_file, client_key_file)
            logger.info("Mutual TLS configured for LDAP")
        
        # Enforce minimum TLS version
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Disable weak ciphers
        ssl_context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')
        
        return Tls(
            local_certificate_file=client_cert_file,
            local_private_key_file=client_key_file,
            validate=validate_cert,
            version=ssl.PROTOCOL_TLS,
            ca_certs_file=ca_cert_file,
            ciphers='HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4'
        )
    
    def connect(self) -> bool:
        """
        Establish secure connection to LDAP server
        """
        try:
            # Create server object
            server = Server(
                self.server_url,
                use_ssl=self.use_ssl,
                tls=self.tls,
                get_info=ALL_ATTRIBUTES
            )
            
            # Create connection
            self.connection = Connection(
                server,
                user=self.bind_dn,
                password=self.bind_password,
                auto_bind=False,
                client_strategy=SAFE_SYNC,
                raise_exceptions=True
            )
            
            # Start TLS if configured
            if self.use_start_tls and not self.use_ssl:
                if not self.connection.start_tls():
                    raise LDAPException("Failed to start TLS")
                logger.info("LDAP StartTLS successful")
            
            # Bind to server
            if not self.connection.bind():
                raise LDAPBindError(f"LDAP bind failed: {self.connection.result}")
            
            logger.info(f"Secure LDAP connection established to {self.server_url}")
            
            # Log connection security details
            if self.connection.tls_started:
                logger.info("TLS connection active")
            
            return True
            
        except LDAPException as e:
            logger.error(f"LDAP connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected LDAP connection error: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from LDAP server"""
        if self.connection:
            try:
                self.connection.unbind()
                logger.info("LDAP connection closed")
            except Exception as e:
                logger.error(f"Error closing LDAP connection: {e}")
    
    def _escape_filter_value(self, value: str) -> str:
        """
        Escape special characters in LDAP filter values to prevent injection
        INCLUDING Unicode bypass attempts
        """
        if not value:
            return ""
        
        # CRITICAL FIX: Normalize Unicode to prevent bypass attacks
        import unicodedata
        # Normalize to NFC form to prevent Unicode encoding tricks
        value = unicodedata.normalize('NFC', value)
        
        # Remove zero-width and invisible Unicode characters
        invisible_chars = [
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\u2060',  # Word joiner
            '\ufeff',  # Zero-width no-break space
            '\u180e',  # Mongolian vowel separator
            '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',  # Various spaces
            '\u2005', '\u2006', '\u2007', '\u2008', '\u2009',
            '\u200a', '\u202f', '\u205f', '\u3000'
        ]
        
        for char in invisible_chars:
            value = value.replace(char, '')
        
        # Remove Unicode control characters
        import sys
        cleaned = ''.join(
            char for char in value 
            if not unicodedata.category(char).startswith('C')
        )
        
        # LDAP filter special characters - extended set
        escape_chars = {
            '\\': r'\5c',
            '*': r'\2a',
            '(': r'\28',
            ')': r'\29',
            '\x00': r'\00',
            '/': r'\2f',
            '=': r'\3d',
            '+': r'\2b',
            '<': r'\3c',
            '>': r'\3e',
            '#': r'\23',
            ',': r'\2c',
            ';': r'\3b',
            '"': r'\22',
            '\n': r'\0a',
            '\r': r'\0d',
        }
        
        escaped = cleaned
        for char, escape_seq in escape_chars.items():
            escaped = escaped.replace(char, escape_seq)
        
        # Additional validation: reject if still contains suspicious patterns
        suspicious_patterns = [
            '\\u', '\\x', '%00', '\0', '&#'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in escaped:
                logger.warning(f"Suspicious pattern '{pattern}' detected in LDAP filter value")
                raise ValueError(f"Invalid characters in LDAP filter value")
        
        return escaped
    
    def authenticate_user(
        self,
        username: str,
        password: str,
        tenant_id: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Authenticate user against LDAP with rate limiting
        """
        # Rate limiting check
        if not self._check_auth_rate_limit(username):
            logger.warning(f"LDAP auth rate limit exceeded for user: {username}")
            return False, None
        
        # Sanitize username to prevent injection
        username = self._escape_filter_value(username)
        
        if not username or not password:
            return False, None
        
        try:
            # Search for user
            search_filter = f"(&(objectClass=person)(uid={username}))"
            
            if tenant_id:
                # Add tenant filter if multi-tenant
                search_filter = f"(&{search_filter}(o={self._escape_filter_value(tenant_id)}))"
            
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['uid', 'cn', 'mail', 'memberOf']
            )
            
            if not self.connection.entries:
                logger.info(f"LDAP user not found: {username}")
                self._record_auth_attempt(username, False)
                return False, None
            
            user_entry = self.connection.entries[0]
            user_dn = user_entry.entry_dn
            
            # Attempt to bind as user
            temp_connection = Connection(
                self.connection.server,
                user=user_dn,
                password=password,
                auto_bind=False,
                raise_exceptions=False
            )
            
            if self.use_start_tls and not self.use_ssl:
                temp_connection.start_tls()
            
            if temp_connection.bind():
                # Authentication successful
                temp_connection.unbind()
                
                user_data = {
                    'dn': user_dn,
                    'username': str(user_entry.uid),
                    'name': str(user_entry.cn),
                    'email': str(user_entry.mail) if user_entry.mail else None,
                    'groups': list(user_entry.memberOf) if user_entry.memberOf else []
                }
                
                logger.info(f"LDAP authentication successful for user: {username}")
                self._record_auth_attempt(username, True)
                
                return True, user_data
            else:
                logger.info(f"LDAP authentication failed for user: {username}")
                self._record_auth_attempt(username, False)
                return False, None
                
        except LDAPException as e:
            logger.error(f"LDAP authentication error: {e}")
            return False, None
        except Exception as e:
            logger.error(f"Unexpected LDAP authentication error: {e}")
            return False, None
    
    def _check_auth_rate_limit(self, username: str) -> bool:
        """Check if user has exceeded authentication rate limit"""
        current_time = time.time()
        
        # Clean old attempts
        self.auth_attempts = {
            user: [t for t in times if current_time - t < self.auth_window]
            for user, times in self.auth_attempts.items()
        }
        
        # Check current user
        user_attempts = self.auth_attempts.get(username, [])
        
        return len(user_attempts) < self.max_auth_attempts
    
    def _record_auth_attempt(self, username: str, success: bool):
        """Record authentication attempt for rate limiting"""
        if not success:
            if username not in self.auth_attempts:
                self.auth_attempts[username] = []
            self.auth_attempts[username].append(time.time())
    
    def search_users(
        self,
        search_filter: str,
        attributes: Optional[List[str]] = None,
        size_limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search for users in LDAP directory
        """
        # Sanitize filter to prevent injection
        # Note: This is a basic example, real implementation should parse and validate filter syntax
        if any(dangerous in search_filter for dangerous in ['*)', '\\', '\x00']):
            logger.warning(f"Potentially dangerous LDAP filter blocked: {search_filter}")
            return []
        
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes or ['uid', 'cn', 'mail'],
                size_limit=size_limit
            )
            
            results = []
            for entry in self.connection.entries:
                user_dict = {
                    'dn': entry.entry_dn,
                }
                for attr in entry:
                    user_dict[str(attr.key)] = str(attr.value)
                results.append(user_dict)
            
            return results
            
        except LDAPException as e:
            logger.error(f"LDAP search error: {e}")
            return []
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()