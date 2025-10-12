"""
OAuth 2.0 / OpenID Connect Provider for Enterprise SSO
"""
import os
import logging
import secrets
import hashlib
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote
import httpx
import jwt
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OAuthConfig(BaseModel):
    """OAuth/OIDC configuration"""
    provider_name: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: Optional[str] = None
    jwks_url: Optional[str] = None
    
    # OIDC specific
    issuer: Optional[str] = None
    discovery_url: Optional[str] = None
    
    # Scopes
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    
    # Attribute mapping
    attribute_mapping: Dict[str, str] = Field(default_factory=dict)
    
    # Advanced settings
    response_type: str = "code"
    response_mode: Optional[str] = None
    grant_type: str = "authorization_code"
    use_pkce: bool = True
    use_nonce: bool = True


class OAuthProvider:
    """OAuth 2.0 / OpenID Connect provider implementation"""
    
    # Well-known provider configurations
    WELL_KNOWN_PROVIDERS = {
        "google": {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
            "issuer": "https://accounts.google.com",
            "scopes": ["openid", "profile", "email"]
        },
        "microsoft": {
            "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "userinfo_url": "https://graph.microsoft.com/v1.0/me",
            "jwks_url": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            "issuer": "https://login.microsoftonline.com/common/v2.0",
            "scopes": ["openid", "profile", "email", "User.Read"]
        },
        "okta": {
            "discovery_url": "https://{domain}/.well-known/openid-configuration",
            "scopes": ["openid", "profile", "email"]
        },
        "auth0": {
            "discovery_url": "https://{domain}/.well-known/openid-configuration",
            "scopes": ["openid", "profile", "email"]
        }
    }
    
    def __init__(self, config: OAuthConfig):
        self.config = config
        self.client = httpx.AsyncClient()
        self._discovery_data = None
        self._jwks_cache = None
    
    async def initialize(self):
        """Initialize provider with discovery if available"""
        if self.config.discovery_url:
            await self._load_discovery()
    
    async def _load_discovery(self):
        """Load OpenID Connect discovery document"""
        try:
            response = await self.client.get(self.config.discovery_url)
            response.raise_for_status()
            self._discovery_data = response.json()
            
            # Update URLs from discovery
            self.config.authorize_url = self._discovery_data.get("authorization_endpoint", self.config.authorize_url)
            self.config.token_url = self._discovery_data.get("token_endpoint", self.config.token_url)
            self.config.userinfo_url = self._discovery_data.get("userinfo_endpoint", self.config.userinfo_url)
            self.config.jwks_url = self._discovery_data.get("jwks_uri", self.config.jwks_url)
            self.config.issuer = self._discovery_data.get("issuer", self.config.issuer)
            
        except Exception as e:
            logger.error(f"Failed to load discovery document: {e}")
    
    def create_authorization_url(self, redirect_uri: str, state: str) -> Dict[str, Any]:
        """Create OAuth authorization URL"""
        params = {
            "client_id": self.config.client_id,
            "response_type": self.config.response_type,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state
        }
        
        # Add response mode if specified
        if self.config.response_mode:
            params["response_mode"] = self.config.response_mode
        
        # Add nonce for OIDC
        nonce = None
        if self.config.use_nonce and "openid" in self.config.scopes:
            nonce = secrets.token_urlsafe(32)
            params["nonce"] = nonce
        
        # Add PKCE challenge if enabled
        code_verifier = None
        if self.config.use_pkce:
            code_verifier = self._generate_code_verifier()
            code_challenge = self._generate_code_challenge(code_verifier)
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        
        # Add provider-specific parameters
        if self.config.provider_name == "google":
            params["access_type"] = "offline"
            params["prompt"] = "consent"
        elif self.config.provider_name == "microsoft":
            params["response_mode"] = "query"
        
        url = f"{self.config.authorize_url}?{urlencode(params)}"
        
        return {
            "url": url,
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier
        }
    
    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens"""
        data = {
            "grant_type": self.config.grant_type,
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret
        }
        
        # Add PKCE verifier if used
        if code_verifier:
            data["code_verifier"] = code_verifier
        
        try:
            response = await self.client.post(
                self.config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            tokens = response.json()
            return tokens
            
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise ValueError(f"Failed to exchange code for tokens: {str(e)}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from provider"""
        if not self.config.userinfo_url:
            raise ValueError("User info endpoint not configured")
        
        try:
            response = await self.client.get(
                self.config.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            # Map attributes
            mapped_info = {}
            for local_attr, provider_attr in self.config.attribute_mapping.items():
                if provider_attr in user_info:
                    mapped_info[local_attr] = user_info[provider_attr]
            
            # Add standard attributes
            mapped_info["sub"] = user_info.get("sub", user_info.get("id"))
            mapped_info["email"] = user_info.get("email", user_info.get("mail"))
            mapped_info["name"] = user_info.get("name", user_info.get("displayName"))
            mapped_info["given_name"] = user_info.get("given_name", user_info.get("givenName"))
            mapped_info["family_name"] = user_info.get("family_name", user_info.get("surname"))
            mapped_info["picture"] = user_info.get("picture", user_info.get("photo"))
            mapped_info["raw_attributes"] = user_info
            
            return mapped_info
            
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            raise ValueError(f"Failed to get user information: {str(e)}")
    
    async def validate_id_token(self, id_token: str, nonce: Optional[str] = None) -> Dict[str, Any]:
        """Validate OpenID Connect ID token"""
        try:
            # Decode header to get key ID
            header = jwt.get_unverified_header(id_token)
            kid = header.get("kid")
            
            # Get public key
            public_key = await self._get_public_key(kid)
            
            # Decode and validate token
            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.config.client_id,
                issuer=self.config.issuer
            )
            
            # Validate nonce if provided
            if nonce and claims.get("nonce") != nonce:
                raise ValueError("Nonce mismatch")
            
            return claims
            
        except Exception as e:
            logger.error(f"ID token validation failed: {e}")
            raise ValueError(f"Invalid ID token: {str(e)}")
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token"""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret
        }
        
        try:
            response = await self.client.post(
                self.config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise ValueError(f"Failed to refresh token: {str(e)}")
    
    async def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """Revoke a token"""
        if not hasattr(self._discovery_data, "revocation_endpoint"):
            logger.warning("Token revocation endpoint not available")
            return False
        
        data = {
            "token": token,
            "token_type_hint": token_type,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret
        }
        
        try:
            response = await self.client.post(
                self._discovery_data["revocation_endpoint"],
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def _get_public_key(self, kid: str) -> str:
        """Get public key from JWKS endpoint"""
        if not self.config.jwks_url:
            raise ValueError("JWKS URL not configured")
        
        # Load JWKS if not cached
        if not self._jwks_cache:
            response = await self.client.get(self.config.jwks_url)
            response.raise_for_status()
            self._jwks_cache = response.json()
        
        # Find key by kid
        for key in self._jwks_cache.get("keys", []):
            if key.get("kid") == kid:
                # Convert JWK to PEM format
                # This is simplified - use python-jose or jwcrypto in production
                return key
        
        raise ValueError(f"Key with kid '{kid}' not found")
    
    def _generate_code_verifier(self) -> str:
        """Generate PKCE code verifier"""
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    
    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate PKCE code challenge"""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    @classmethod
    def create_provider(cls, provider_name: str, client_id: str, client_secret: str, **kwargs) -> 'OAuthProvider':
        """Create provider instance for well-known providers"""
        if provider_name not in cls.WELL_KNOWN_PROVIDERS:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        provider_config = cls.WELL_KNOWN_PROVIDERS[provider_name].copy()
        
        # Handle domain-based providers
        if "domain" in kwargs:
            for key, value in provider_config.items():
                if isinstance(value, str) and "{domain}" in value:
                    provider_config[key] = value.format(domain=kwargs["domain"])
        
        # Merge with custom config
        provider_config.update(kwargs)
        
        config = OAuthConfig(
            provider_name=provider_name,
            client_id=client_id,
            client_secret=client_secret,
            **provider_config
        )
        
        return cls(config)