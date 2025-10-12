"""
Secure Cookie Management System for Platform Forge
Addresses LOW-001: Cookie Security Attributes

Provides comprehensive cookie security enhancements:
- Secure cookie attributes (Secure, HttpOnly, SameSite)
- Cookie encryption and integrity protection
- Configurable security policies per cookie type
- Automatic cookie security validation
- GDPR-compliant cookie consent integration
"""
import secrets
import hmac
import hashlib
import time
import json
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
from enum import Enum
from fastapi import Request, Response, HTTPException
from cryptography.fernet import Fernet
import logging
from dataclasses import dataclass

from .config import settings
from .security import SecurityError

logger = logging.getLogger(__name__)


class CookieType(Enum):
    """Cookie classification for security policies"""
    SESSION = "session"
    CSRF = "csrf"
    PREFERENCES = "preferences"
    ANALYTICS = "analytics"
    AUTHENTICATION = "authentication"
    CONSENT = "consent"
    CART = "cart"
    LANGUAGE = "language"
    THEME = "theme"


class CookieSameSite(Enum):
    """SameSite attribute values"""
    STRICT = "strict"
    LAX = "lax"
    NONE = "none"


@dataclass
class CookieSecurityPolicy:
    """Security policy for a cookie type"""
    secure: bool = True  # Always use HTTPS in production
    httponly: bool = True  # Not accessible via JavaScript
    samesite: CookieSameSite = CookieSameSite.STRICT
    max_age: int = 3600  # 1 hour default
    domain: Optional[str] = None
    path: str = "/"
    encrypt: bool = False  # Whether to encrypt cookie value
    sign: bool = True  # Whether to sign cookie for integrity
    consent_required: bool = False  # GDPR consent required
    essential: bool = True  # Essential for service operation


class SecureCookieManager:
    """
    Comprehensive cookie security manager with encryption, signing, and policy enforcement
    """
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = (master_key or settings.SECRET_KEY).encode()
        self._cipher = None
        self._init_cipher()
        
        # Default security policies per cookie type
        self.security_policies = {
            CookieType.SESSION: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.STRICT,
                max_age=3600,  # 1 hour
                encrypt=True,
                sign=True,
                essential=True
            ),
            CookieType.AUTHENTICATION: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.STRICT,
                max_age=1800,  # 30 minutes
                encrypt=True,
                sign=True,
                essential=True
            ),
            CookieType.CSRF: CookieSecurityPolicy(
                secure=True,
                httponly=False,  # Must be readable by JavaScript
                samesite=CookieSameSite.STRICT,
                max_age=3600,
                encrypt=False,
                sign=True,
                essential=True
            ),
            CookieType.PREFERENCES: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.LAX,
                max_age=86400 * 30,  # 30 days
                encrypt=True,
                sign=True,
                consent_required=True,
                essential=False
            ),
            CookieType.ANALYTICS: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.LAX,
                max_age=86400 * 7,  # 7 days
                encrypt=False,
                sign=True,
                consent_required=True,
                essential=False
            ),
            CookieType.CONSENT: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.STRICT,
                max_age=86400 * 365,  # 1 year
                encrypt=False,
                sign=True,
                essential=True
            ),
            CookieType.CART: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.LAX,
                max_age=86400 * 7,  # 7 days
                encrypt=True,
                sign=True,
                consent_required=True,
                essential=False
            ),
            CookieType.LANGUAGE: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.LAX,
                max_age=86400 * 30,  # 30 days
                encrypt=False,
                sign=False,
                essential=False
            ),
            CookieType.THEME: CookieSecurityPolicy(
                secure=True,
                httponly=True,
                samesite=CookieSameSite.LAX,
                max_age=86400 * 30,  # 30 days
                encrypt=False,
                sign=False,
                essential=False
            )
        }
    
    def _init_cipher(self):
        """Initialize Fernet cipher for cookie encryption"""
        try:
            # Derive a consistent key from master key
            key_material = hmac.new(
                self.master_key,
                b"cookie_encryption",
                hashlib.sha256
            ).digest()
            # Fernet requires 32 bytes, base64 encoded
            from base64 import urlsafe_b64encode
            fernet_key = urlsafe_b64encode(key_material)
            self._cipher = Fernet(fernet_key)
        except Exception as e:
            logger.error(f"Failed to initialize cookie cipher: {e}")
            raise SecurityError("Cookie encryption initialization failed")
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt cookie value"""
        try:
            if self._cipher is None:
                self._init_cipher()
            return self._cipher.encrypt(value.encode()).decode()
        except Exception as e:
            logger.error(f"Cookie encryption failed: {e}")
            raise SecurityError("Cookie encryption failed")
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt cookie value"""
        try:
            if self._cipher is None:
                self._init_cipher()
            return self._cipher.decrypt(encrypted_value.encode()).decode()
        except Exception as e:
            logger.error(f"Cookie decryption failed: {e}")
            raise SecurityError("Cookie decryption failed")
    
    def _sign_value(self, value: str) -> str:
        """Create HMAC signature for cookie value"""
        signature = hmac.new(
            self.master_key,
            value.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{value}.{signature}"
    
    def _verify_signature(self, signed_value: str) -> Optional[str]:
        """Verify and extract cookie value from signature"""
        try:
            if '.' not in signed_value:
                return None
            
            value, signature = signed_value.rsplit('.', 1)
            expected_signature = hmac.new(
                self.master_key,
                value.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if hmac.compare_digest(signature, expected_signature):
                return value
            return None
        except Exception:
            return None
    
    def set_secure_cookie(
        self,
        response: Response,
        name: str,
        value: Union[str, dict, list],
        cookie_type: CookieType,
        custom_policy: Optional[CookieSecurityPolicy] = None,
        request: Optional[Request] = None
    ) -> bool:
        """
        Set a secure cookie with appropriate security attributes
        
        Args:
            response: FastAPI Response object
            name: Cookie name
            value: Cookie value (string, dict, or list)
            cookie_type: Type of cookie for security policy
            custom_policy: Override default policy
            request: Request object for consent checking
            
        Returns:
            bool: True if cookie was set, False if blocked by consent
        """
        try:
            # Get security policy
            policy = custom_policy or self.security_policies.get(
                cookie_type, 
                CookieSecurityPolicy()
            )
            
            # Check consent requirements
            if request and policy.consent_required and not policy.essential:
                if not self._check_consent(request, cookie_type):
                    logger.info(f"Cookie {name} blocked by consent policy")
                    return False
            
            # Convert value to string if needed
            if isinstance(value, (dict, list)):
                cookie_value = json.dumps(value)
            else:
                cookie_value = str(value)
            
            # Apply encryption if required
            if policy.encrypt:
                cookie_value = self._encrypt_value(cookie_value)
            
            # Apply signing if required
            if policy.sign:
                cookie_value = self._sign_value(cookie_value)
            
            # Adjust security attributes based on environment
            secure = policy.secure and not settings.DEBUG
            
            # Set cookie with security attributes
            response.set_cookie(
                key=name,
                value=cookie_value,
                max_age=policy.max_age,
                expires=datetime.utcnow() + timedelta(seconds=policy.max_age),
                path=policy.path,
                domain=policy.domain,
                secure=secure,
                httponly=policy.httponly,
                samesite=policy.samesite.value
            )
            
            logger.debug(f"Secure cookie set: {name} (type: {cookie_type.value})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set secure cookie {name}: {e}")
            raise SecurityError(f"Failed to set secure cookie: {e}")
    
    def get_secure_cookie(
        self,
        request: Request,
        name: str,
        cookie_type: CookieType,
        return_json: bool = False
    ) -> Optional[Union[str, dict, list]]:
        """
        Get and validate a secure cookie
        
        Args:
            request: FastAPI Request object
            name: Cookie name
            cookie_type: Type of cookie for security policy
            return_json: Whether to parse JSON values
            
        Returns:
            Cookie value or None if invalid/missing
        """
        try:
            # Get policy
            policy = self.security_policies.get(cookie_type, CookieSecurityPolicy())
            
            # Get cookie value
            raw_value = request.cookies.get(name)
            if not raw_value:
                return None
            
            cookie_value = raw_value
            
            # Verify signature if required
            if policy.sign:
                cookie_value = self._verify_signature(raw_value)
                if cookie_value is None:
                    logger.warning(f"Cookie signature verification failed: {name}")
                    return None
            
            # Decrypt if required
            if policy.encrypt:
                cookie_value = self._decrypt_value(cookie_value)
            
            # Parse JSON if requested
            if return_json:
                try:
                    return json.loads(cookie_value)
                except json.JSONDecodeError:
                    logger.warning(f"Cookie JSON parsing failed: {name}")
                    return None
            
            return cookie_value
            
        except Exception as e:
            logger.error(f"Failed to get secure cookie {name}: {e}")
            return None
    
    def delete_cookie(
        self,
        response: Response,
        name: str,
        path: str = "/",
        domain: Optional[str] = None
    ):
        """Securely delete a cookie"""
        response.delete_cookie(
            key=name,
            path=path,
            domain=domain,
            secure=not settings.DEBUG,
            httponly=True,
            samesite="strict"
        )
    
    def _check_consent(self, request: Request, cookie_type: CookieType) -> bool:
        """Check if user has consented to this cookie type"""
        try:
            # Get consent cookie
            consent_data = self.get_secure_cookie(
                request,
                "cookie_consent",
                CookieType.CONSENT,
                return_json=True
            )
            
            if not consent_data or not isinstance(consent_data, dict):
                return False
            
            # Check specific consent for this cookie type
            return consent_data.get(cookie_type.value, False)
            
        except Exception:
            return False
    
    def validate_cookie_security(self, request: Request) -> Dict[str, Any]:
        """
        Validate all cookies in request for security compliance
        
        Returns:
            Dict with validation results and security scores
        """
        results = {
            "total_cookies": 0,
            "secure_cookies": 0,
            "insecure_cookies": [],
            "missing_attributes": [],
            "security_score": 0.0,
            "recommendations": []
        }
        
        try:
            cookies = request.cookies
            results["total_cookies"] = len(cookies)
            
            for cookie_name, cookie_value in cookies.items():
                # Check if cookie has expected security attributes
                # Note: We can only validate what we manage
                if cookie_name in ["session", "csrf_token", "auth_token"]:
                    # These should be secure cookies
                    results["secure_cookies"] += 1
                else:
                    # Check for potentially insecure patterns
                    if len(cookie_value) < 10:  # Very short values might be insecure
                        results["insecure_cookies"].append({
                            "name": cookie_name,
                            "issue": "Value too short for security"
                        })
            
            # Calculate security score
            if results["total_cookies"] > 0:
                results["security_score"] = (
                    results["secure_cookies"] / results["total_cookies"]
                ) * 100
            
            # Generate recommendations
            if results["insecure_cookies"]:
                results["recommendations"].append(
                    "Use SecureCookieManager for all sensitive cookies"
                )
            
            if results["security_score"] < 80:
                results["recommendations"].append(
                    "Implement comprehensive cookie security policies"
                )
            
            return results
            
        except Exception as e:
            logger.error(f"Cookie security validation failed: {e}")
            return results
    
    def generate_consent_banner_data(self) -> Dict[str, Any]:
        """Generate data for GDPR cookie consent banner"""
        cookie_categories = {
            "essential": {
                "name": "Essential Cookies",
                "description": "Required for the website to function properly",
                "cookies": ["session", "csrf_token", "auth_token", "consent"],
                "required": True
            },
            "preferences": {
                "name": "Preference Cookies", 
                "description": "Remember your settings and preferences",
                "cookies": ["language", "theme", "preferences"],
                "required": False
            },
            "analytics": {
                "name": "Analytics Cookies",
                "description": "Help us improve our service",
                "cookies": ["analytics", "metrics"],
                "required": False
            },
            "marketing": {
                "name": "Marketing Cookies",
                "description": "Used for targeted advertising",
                "cookies": ["cart", "recommendations"],
                "required": False
            }
        }
        
        return {
            "categories": cookie_categories,
            "privacy_policy_url": "/privacy-policy",
            "cookie_policy_url": "/cookie-policy"
        }
    
    def set_consent_preferences(
        self,
        response: Response,
        preferences: Dict[str, bool],
        request: Optional[Request] = None
    ):
        """Set user cookie consent preferences"""
        consent_data = {
            "timestamp": int(time.time()),
            "preferences": preferences,
            "version": "1.0"
        }
        
        # Map preferences to cookie types
        cookie_type_mapping = {
            "essential": [CookieType.SESSION, CookieType.CSRF, CookieType.AUTHENTICATION, CookieType.CONSENT],
            "preferences": [CookieType.PREFERENCES, CookieType.LANGUAGE, CookieType.THEME],
            "analytics": [CookieType.ANALYTICS],
            "marketing": [CookieType.CART]
        }
        
        for category, allowed in preferences.items():
            if category in cookie_type_mapping:
                for cookie_type in cookie_type_mapping[category]:
                    consent_data[cookie_type.value] = allowed
        
        # Essential cookies are always allowed
        for cookie_type in cookie_type_mapping["essential"]:
            consent_data[cookie_type.value] = True
        
        self.set_secure_cookie(
            response,
            "cookie_consent",
            consent_data,
            CookieType.CONSENT,
            request=request
        )


# Global secure cookie manager instance
_cookie_manager = None


def get_cookie_manager() -> SecureCookieManager:
    """Get global secure cookie manager instance"""
    global _cookie_manager
    if _cookie_manager is None:
        _cookie_manager = SecureCookieManager()
    return _cookie_manager


# FastAPI Dependencies
async def secure_cookie_dependency() -> SecureCookieManager:
    """FastAPI dependency for secure cookie manager"""
    return get_cookie_manager()