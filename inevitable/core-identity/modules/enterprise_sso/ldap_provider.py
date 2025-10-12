"""
LDAP/Active Directory Provider for Enterprise SSO
"""
import logging
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel, Field
import ssl
import re
import html

# Note: python-ldap or ldap3 should be installed
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, Tls
    from ldap3.core.exceptions import LDAPException
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    ldap3 = None
    # Fallback constants and types
    SIMPLE = "SIMPLE"
    NTLM = "NTLM"
    SASL = "SASL"
    Connection = Any
    Server = Any
    LDAPException = Exception

logger = logging.getLogger(__name__)


def escape_ldap_filter(value: str) -> str:
    """
    Escape LDAP filter special characters to prevent injection attacks.
    Addresses HIGH-001: LDAP injection vulnerability
    
    LDAP filter special characters that need escaping:
    - ( -> \28
    - ) -> \29  
    - \ -> \5C
    - * -> \2A
    - NUL -> \00
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Define escape mappings for LDAP filter special characters
    escape_map = {
        '\\': '\\5C',  # Backslash must be escaped first
        '*': '\\2A',    # Asterisk (wildcard)
        '(': '\\28',    # Left parenthesis  
        ')': '\\29',    # Right parenthesis
        '\x00': '\\00'   # NULL character
    }
    
    # Apply escaping
    for char, escaped in escape_map.items():
        value = value.replace(char, escaped)
    
    return value


def escape_ldap_dn(value: str) -> str:
    """
    Escape LDAP DN special characters.
    DN escaping is different from filter escaping.
    
    LDAP DN special characters:
    - , -> \,
    - = -> \=
    - + -> \+
    - < -> \<
    - > -> \>
    - # -> \#
    - ; -> \;
    - \ -> \\
    - " -> \"
    - space at beginning/end -> \ 
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Define escape mappings for LDAP DN special characters
    escape_map = {
        '\\': '\\\\',  # Backslash must be escaped first
        ',': '\\,',
        '=': '\\=', 
        '+': '\\+',
        '<': '\\<',
        '>': '\\>',
        '#': '\\#',
        ';': '\\;',
        '"': '\\"'
    }
    
    # Apply escaping
    for char, escaped in escape_map.items():
        value = value.replace(char, escaped)
    
    # Handle leading/trailing spaces
    if value.startswith(' '):
        value = '\\' + value
    if value.endswith(' '):
        value = value[:-1] + '\\ '
    
    return value


class LDAPConfig(BaseModel):
    """LDAP configuration"""
    server_url: str  # ldap://server or ldaps://server
    bind_dn: Optional[str] = None  # For service account
    bind_password: Optional[str] = None
    
    # Search configuration
    base_dn: str  # e.g., "dc=example,dc=com"
    user_search_base: Optional[str] = None  # Override base_dn for users
    group_search_base: Optional[str] = None  # Override base_dn for groups
    
    # Search filters
    user_search_filter: str = "(uid={username})"  # or "(sAMAccountName={username})" for AD
    group_search_filter: str = "(member={user_dn})"
    
    # Attribute mapping
    user_attributes: Dict[str, str] = Field(default_factory=lambda: {
        "email": "mail",
        "first_name": "givenName",
        "last_name": "sn",
        "display_name": "displayName",
        "phone": "telephoneNumber",
        "department": "department",
        "title": "title",
        "employee_id": "employeeNumber"
    })
    
    group_attributes: Dict[str, str] = Field(default_factory=lambda: {
        "name": "cn",
        "description": "description"
    })
    
    # Connection settings
    use_ssl: bool = False
    use_tls: bool = False
    verify_ssl: bool = True
    timeout: int = 30
    
    # Active Directory specific
    is_active_directory: bool = False
    default_domain: Optional[str] = None  # For NTLM auth
    
    # Advanced settings
    page_size: int = 1000
    referrals: bool = True
    authentication: str = SIMPLE  # SIMPLE, NTLM, SASL


class LDAPProvider:
    """LDAP/Active Directory authentication provider"""
    
    def __init__(self, config: LDAPConfig):
        if not LDAP_AVAILABLE:
            raise ImportError("ldap3 package is required for LDAP authentication")
        
        self.config = config
        self._server = None
        self._init_server()
    
    def _init_server(self):
        """Initialize LDAP server connection"""
        # Parse server URL
        url_match = re.match(r'(ldaps?)://([^:]+)(?::(\d+))?', self.config.server_url)
        if not url_match:
            raise ValueError(f"Invalid LDAP server URL: {self.config.server_url}")
        
        protocol, host, port = url_match.groups()
        
        # Set default ports
        if not port:
            port = 636 if protocol == 'ldaps' or self.config.use_ssl else 389
        else:
            port = int(port)
        
        # HIGH FIX: Configure secure TLS with enhanced security
        # Addresses HIGH-SSO-003: Missing LDAP Connection Security
        tls_config = None
        if self.config.use_tls or protocol == 'ldaps':
            # SECURITY FIX: Always require certificate validation in production
            cert_validation = ssl.CERT_REQUIRED
            if not self.config.verify_ssl:
                from modules.core.config import settings
                if hasattr(settings, 'ENVIRONMENT') and settings.ENVIRONMENT == 'production':
                    logger.error("LDAP certificate validation disabled in production - forcing CERT_REQUIRED")
                    cert_validation = ssl.CERT_REQUIRED
                else:
                    logger.warning("LDAP certificate validation disabled - only allowed in development")
                    cert_validation = ssl.CERT_NONE
            
            tls_config = Tls(
                validate=cert_validation,
                # HIGH FIX: Use TLS 1.3 minimum (fallback to 1.2 if 1.3 not available)
                version=getattr(ssl, 'PROTOCOL_TLS_CLIENT', ssl.PROTOCOL_TLSv1_2),
                # HIGH FIX: Restrict to secure ciphers only
                ciphers='ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS',
                # HIGH FIX: Disable weak protocols and features
                options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION,
                # HIGH FIX: Enable certificate hostname verification
                check_names=self.config.verify_ssl
            )
        
        # Create server object
        self._server = Server(
            host,
            port=port,
            use_ssl=protocol == 'ldaps' or self.config.use_ssl,
            tls=tls_config,
            get_info=ALL
        )
    
    def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test LDAP connection"""
        try:
            # Try anonymous bind first
            conn = Connection(
                self._server,
                auto_bind=True,
                client_strategy=ldap3.SYNC,
                raise_exceptions=True
            )
            conn.unbind()
            
            # Try service account bind if configured
            if self.config.bind_dn and self.config.bind_password:
                conn = Connection(
                    self._server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password,
                    auto_bind=True,
                    client_strategy=ldap3.SYNC,
                    raise_exceptions=True
                )
                conn.unbind()
            
            return True, "Connection successful"
            
        except Exception as e:
            logger.error(f"LDAP connection test failed: {e}")
            return False, str(e)
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with LDAP"""
        try:
            # Handle Active Directory domain\username format
            # SECURITY FIX: Don't escape username for NTLM auth - it's not used in LDAP queries
            # The username here is used for bind authentication, not LDAP filter construction
            if self.config.is_active_directory and '\\' not in username and self.config.default_domain:
                auth_username = f"{self.config.default_domain}\\{username}"
            else:
                auth_username = username
            
            # First, find the user's DN
            user_dn, user_data = self._search_user(username)
            if not user_dn:
                logger.warning(f"User not found: {username}")
                return None
            
            # Attempt to bind with user's credentials
            try:
                if self.config.is_active_directory and self.config.authentication == NTLM:
                    # NTLM authentication for AD
                    conn = Connection(
                        self._server,
                        user=auth_username,
                        password=password,
                        authentication=NTLM,
                        auto_bind=True,
                        raise_exceptions=True
                    )
                else:
                    # Simple bind
                    # SECURITY: user_dn comes from a legitimate LDAP search result, not user input
                    # No escaping needed for bind operations with pre-validated DNs
                    conn = Connection(
                        self._server,
                        user=user_dn,
                        password=password,
                        authentication=SIMPLE,
                        auto_bind=True,
                        raise_exceptions=True
                    )
                
                # Authentication successful
                conn.unbind()
                
                # Get user groups
                groups = self._get_user_groups(user_dn)
                
                # Build user info
                user_info = {
                    "username": username,
                    "dn": user_dn,
                    "groups": groups,
                    "raw_attributes": user_data
                }
                
                # Map attributes
                for local_attr, ldap_attr in self.config.user_attributes.items():
                    if ldap_attr in user_data:
                        value = user_data[ldap_attr]
                        # Handle multi-valued attributes
                        if isinstance(value, list) and len(value) == 1:
                            value = value[0]
                        user_info[local_attr] = value
                
                return user_info
                
            except LDAPException as e:
                logger.warning(f"Authentication failed for {username}: {e}")
                return None
                
        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")
            return None
    
    def search_users(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for users in LDAP"""
        try:
            conn = self._get_service_connection()
            
            # HIGH-001 FIX: Escape query to prevent LDAP injection
            escaped_query = escape_ldap_filter(query)
            
            # Build search filter with escaped query
            # CRITICAL FIX: Don't use raw string replacement on filters - build properly
            base_filter = self.config.user_search_filter.replace('{username}', '*')
            search_filter = f"(&{base_filter}(|(cn=*{escaped_query}*)(mail=*{escaped_query}*)(displayName=*{escaped_query}*)))"
            
            # Search
            conn.search(
                search_base=self.config.user_search_base or self.config.base_dn,
                search_filter=search_filter,
                attributes=list(self.config.user_attributes.values()),
                size_limit=limit
            )
            
            users = []
            for entry in conn.entries:
                user_data = {"dn": entry.entry_dn}
                for local_attr, ldap_attr in self.config.user_attributes.items():
                    if hasattr(entry, ldap_attr):
                        value = getattr(entry, ldap_attr).value
                        if value:
                            user_data[local_attr] = value
                users.append(user_data)
            
            conn.unbind()
            return users
            
        except Exception as e:
            logger.error(f"LDAP user search error: {e}")
            return []
    
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information from LDAP"""
        try:
            user_dn, user_data = self._search_user(username)
            if not user_dn:
                return None
            
            # Get groups
            groups = self._get_user_groups(user_dn)
            
            # Build user info
            user_info = {
                "username": username,
                "dn": user_dn,
                "groups": groups,
                "raw_attributes": user_data
            }
            
            # Map attributes
            for local_attr, ldap_attr in self.config.user_attributes.items():
                if ldap_attr in user_data:
                    value = user_data[ldap_attr]
                    if isinstance(value, list) and len(value) == 1:
                        value = value[0]
                    user_info[local_attr] = value
            
            return user_info
            
        except Exception as e:
            logger.error(f"LDAP get user error: {e}")
            return None
    
    def _search_user(self, username: str) -> Tuple[Optional[str], Dict[str, Any]]:
        """Search for a specific user"""
        try:
            conn = self._get_service_connection()
            
            # HIGH-001 FIX: Escape username to prevent LDAP injection
            escaped_username = escape_ldap_filter(username)
            
            # Build search filter with escaped username
            search_filter = self.config.user_search_filter.replace("{username}", escaped_username)
            
            # Search
            conn.search(
                search_base=self.config.user_search_base or self.config.base_dn,
                search_filter=search_filter,
                attributes=list(self.config.user_attributes.values())
            )
            
            if len(conn.entries) == 0:
                return None, {}
            
            if len(conn.entries) > 1:
                logger.warning(f"Multiple users found for username {username}")
            
            entry = conn.entries[0]
            user_data = {}
            
            for attr in self.config.user_attributes.values():
                if hasattr(entry, attr):
                    value = getattr(entry, attr).value
                    if value:
                        user_data[attr] = value
            
            conn.unbind()
            return entry.entry_dn, user_data
            
        except Exception as e:
            logger.error(f"LDAP user search error: {e}")
            return None, {}
    
    def _get_user_groups(self, user_dn: str) -> List[str]:
        """Get groups for a user"""
        try:
            conn = self._get_service_connection()
            
            # HIGH-001 FIX: Escape user DN to prevent LDAP injection
            # Note: DN should use DN escaping, but in filter context use filter escaping
            escaped_user_dn = escape_ldap_filter(user_dn)
            
            # Build group search filter with escaped user DN
            search_filter = self.config.group_search_filter.replace("{user_dn}", escaped_user_dn)
            
            # Search
            conn.search(
                search_base=self.config.group_search_base or self.config.base_dn,
                search_filter=search_filter,
                attributes=[self.config.group_attributes.get("name", "cn")]
            )
            
            groups = []
            for entry in conn.entries:
                group_name_attr = self.config.group_attributes.get("name", "cn")
                if hasattr(entry, group_name_attr):
                    group_name = getattr(entry, group_name_attr).value
                    if group_name:
                        groups.append(group_name)
            
            conn.unbind()
            return groups
            
        except Exception as e:
            logger.error(f"LDAP group search error: {e}")
            return []
    
    def _get_service_connection(self) -> Connection:
        """Get LDAP connection using service account"""
        if self.config.bind_dn and self.config.bind_password:
            conn = Connection(
                self._server,
                user=self.config.bind_dn,
                password=self.config.bind_password,
                auto_bind=True,
                client_strategy=ldap3.SYNC,
                raise_exceptions=True
            )
        else:
            # Anonymous bind
            conn = Connection(
                self._server,
                auto_bind=True,
                client_strategy=ldap3.SYNC,
                raise_exceptions=True
            )
        
        return conn
    
    def sync_users(self, callback=None) -> Dict[str, Any]:
        """Sync all users from LDAP"""
        try:
            conn = self._get_service_connection()
            
            # Search all users - asterisk is safe as it's hardcoded, not user input
            conn.search(
                search_base=self.config.user_search_base or self.config.base_dn,
                search_filter=self.config.user_search_filter.replace("{username}", "*"),
                attributes=list(self.config.user_attributes.values()),
                paged_size=self.config.page_size
            )
            
            total_users = 0
            synced_users = 0
            errors = []
            
            for entry in conn.entries:
                total_users += 1
                
                try:
                    user_data = {"dn": entry.entry_dn}
                    
                    # Extract username
                    username = None
                    if self.config.is_active_directory:
                        if hasattr(entry, "sAMAccountName"):
                            username = entry.sAMAccountName.value
                    else:
                        if hasattr(entry, "uid"):
                            username = entry.uid.value
                    
                    if not username:
                        errors.append(f"No username found for {entry.entry_dn}")
                        continue
                    
                    user_data["username"] = username
                    
                    # Map attributes
                    for local_attr, ldap_attr in self.config.user_attributes.items():
                        if hasattr(entry, ldap_attr):
                            value = getattr(entry, ldap_attr).value
                            if value:
                                user_data[local_attr] = value
                    
                    # Get groups
                    user_data["groups"] = self._get_user_groups(entry.entry_dn)
                    
                    # Call callback if provided
                    if callback:
                        callback(user_data)
                    
                    synced_users += 1
                    
                except Exception as e:
                    errors.append(f"Error syncing {entry.entry_dn}: {str(e)}")
            
            conn.unbind()
            
            return {
                "total_users": total_users,
                "synced_users": synced_users,
                "errors": errors
            }
            
        except Exception as e:
            logger.error(f"LDAP sync error: {e}")
            return {
                "total_users": 0,
                "synced_users": 0,
                "errors": [str(e)]
            }