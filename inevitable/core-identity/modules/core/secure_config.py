"""
Enhanced configuration with security validations
Fixes CRITICAL: Default JWT Secret vulnerability
"""
import os
import secrets
import warnings
from typing import Optional, List
from pydantic import validator
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings
import logging

logger = logging.getLogger(__name__)

# List of known weak/default secrets
WEAK_SECRETS = {
    "your-secret-key-here-change-in-production",
    "secret", "password", "changeme", "default",
    "admin", "123456", "qwerty", "letmein",
    "development", "test", "demo", "example"
}

class SecureSettings(BaseSettings):
    """Enhanced settings with security validations"""
    
    # Application settings
    APP_NAME: str = "Platform Forge"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./platform_forge.db")
    
    # JWT Security Settings
    _SECRET_KEY: Optional[str] = os.getenv("SECRET_KEY")
    _PLATFORM_FORGE_MASTER_KEY: Optional[str] = os.getenv("PLATFORM_FORGE_MASTER_KEY")
    
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Stripe
    STRIPE_API_KEY: Optional[str] = os.getenv("STRIPE_API_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET")
    STRIPE_PUBLISHABLE_KEY: Optional[str] = os.getenv("STRIPE_PUBLISHABLE_KEY")
    
    # Redis (for caching/sessions)
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Email
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    EMAILS_FROM_EMAIL: Optional[str] = os.getenv("EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: str = os.getenv("EMAILS_FROM_NAME", APP_NAME)
    
    # Multi-tenancy
    ENABLE_MULTI_TENANCY: bool = os.getenv("ENABLE_MULTI_TENANCY", "true").lower() == "true"
    
    # Observability
    ENABLE_METRICS: bool = os.getenv("ENABLE_METRICS", "true").lower() == "true"
    METRICS_PORT: int = int(os.getenv("METRICS_PORT", "9090"))
    
    # Privacy/GDPR
    ENABLE_PRIVACY_MODULE: bool = os.getenv("ENABLE_PRIVACY_MODULE", "true").lower() == "true"
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", "365"))
    
    # Security Settings
    SECURE_COOKIES: bool = ENVIRONMENT != "development"
    SAMESITE_COOKIES: str = "strict"
    CORS_ALLOW_CREDENTIALS: bool = False
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000
    
    # Password Policy
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_HISTORY_COUNT: int = 5
    
    # Session Security
    SESSION_LIFETIME_MINUTES: int = 60
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = 12
    
    model_config = {"case_sensitive": True, "env_file": ".env", "extra": "allow"}
    
    @property
    def SECRET_KEY(self) -> str:
        """Validated SECRET_KEY with security checks"""
        key = self._SECRET_KEY
        
        if not key:
            if self.ENVIRONMENT == "development":
                # Generate random key for development
                key = secrets.token_urlsafe(64)
                warnings.warn(
                    f"Using generated SECRET_KEY for development: {key[:8]}...\n"
                    "Set SECRET_KEY environment variable for production!",
                    RuntimeWarning,
                    stacklevel=2
                )
                self._SECRET_KEY = key
            else:
                raise ValueError(
                    "SECURITY ERROR: SECRET_KEY must be set in production environment.\n"
                    "Generate a secure key with:\n"
                    "  python -c 'import secrets; print(secrets.token_urlsafe(64))'"
                )
        
        # Validate key strength
        if key.strip().lower() in WEAK_SECRETS:
            raise ValueError(
                f"SECURITY ERROR: SECRET_KEY is using a known weak/default value.\n"
                f"Current value appears to be: '{key[:20]}...'\n"
                f"Generate a secure key with:\n"
                f"  python -c 'import secrets; print(secrets.token_urlsafe(64))'"
            )
        
        if len(key) < 32:
            raise ValueError(
                f"SECURITY ERROR: SECRET_KEY is too short ({len(key)} chars).\n"
                f"Minimum length is 32 characters. Current: '{key[:20]}...'\n"
                f"Generate a secure key with:\n"
                f"  python -c 'import secrets; print(secrets.token_urlsafe(64))'"
            )
        
        # Check for low entropy
        if len(set(key)) < 10:
            raise ValueError(
                "SECURITY ERROR: SECRET_KEY has low entropy (not enough unique characters).\n"
                "Generate a secure key with:\n"
                "  python -c 'import secrets; print(secrets.token_urlsafe(64))'"
            )
        
        return key
    
    @property
    def PLATFORM_FORGE_MASTER_KEY(self) -> str:
        """Master key for tenant encryption"""
        key = self._PLATFORM_FORGE_MASTER_KEY
        
        if not key:
            if self.ENVIRONMENT == "development":
                key = secrets.token_urlsafe(64)
                warnings.warn(
                    f"Using generated master key for development: {key[:8]}...",
                    RuntimeWarning,
                    stacklevel=2
                )
                self._PLATFORM_FORGE_MASTER_KEY = key
            else:
                raise ValueError(
                    "SECURITY ERROR: PLATFORM_FORGE_MASTER_KEY must be set in production.\n"
                    "Generate with:\n"
                    "  python -c 'import secrets; print(secrets.token_urlsafe(64))'"
                )
        
        # Same validation as SECRET_KEY
        if key.strip().lower() in WEAK_SECRETS:
            raise ValueError("SECURITY ERROR: PLATFORM_FORGE_MASTER_KEY is using a weak value")
        
        if len(key) < 32:
            raise ValueError("SECURITY ERROR: PLATFORM_FORGE_MASTER_KEY must be at least 32 characters")
        
        return key
    
    def validate_production_config(self):
        """Validate configuration for production deployment"""
        errors = []
        warnings = []
        
        if self.ENVIRONMENT == "production":
            # Critical checks
            if self.DEBUG:
                errors.append("DEBUG must be False in production")
            
            if "sqlite" in self.DATABASE_URL:
                errors.append("SQLite should not be used in production")
            
            if not self.STRIPE_API_KEY:
                warnings.append("STRIPE_API_KEY not set - billing will be disabled")
            
            if not self.REDIS_URL:
                warnings.append("REDIS_URL not set - using in-memory caching")
            
            # Security headers
            if not self.SECURE_COOKIES:
                errors.append("SECURE_COOKIES must be True in production")
            
            # Log configuration status
            logger.info(f"Production configuration validation:")
            logger.info(f"  - Environment: {self.ENVIRONMENT}")
            logger.info(f"  - Debug: {self.DEBUG}")
            logger.info(f"  - Database: {self.DATABASE_URL.split('@')[0]}...")
            logger.info(f"  - Multi-tenancy: {self.ENABLE_MULTI_TENANCY}")
            logger.info(f"  - Metrics: {self.ENABLE_METRICS}")
            
            if errors:
                error_msg = "Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
                raise ValueError(error_msg)
            
            if warnings:
                for warning in warnings:
                    logger.warning(f"Production configuration warning: {warning}")
        
        return True


class KeyRotationManager:
    """Manage JWT key rotation for zero-downtime key updates"""
    
    def __init__(self, settings: SecureSettings):
        self.settings = settings
        self.current_key = settings.SECRET_KEY
        self.previous_keys = self._load_previous_keys()
    
    def _load_previous_keys(self) -> List[str]:
        """Load previous keys for rotation support"""
        keys = []
        for i in range(3):  # Support up to 3 previous keys
            key = os.getenv(f"PREVIOUS_SECRET_KEY_{i}")
            if key and key not in WEAK_SECRETS and len(key) >= 32:
                keys.append(key)
        return keys
    
    def verify_token_with_rotation(self, token: str) -> Optional[dict]:
        """Verify token with current and previous keys"""
        from jose import jwt, JWTError
        
        # Try current key first
        try:
            payload = jwt.decode(
                token, 
                self.current_key, 
                algorithms=[self.settings.ALGORITHM]
            )
            return payload
        except JWTError:
            pass
        
        # Try previous keys
        for idx, key in enumerate(self.previous_keys):
            try:
                payload = jwt.decode(
                    token, 
                    key, 
                    algorithms=[self.settings.ALGORITHM]
                )
                # Log that old key was used
                logger.info(f"Token verified with previous key {idx}")
                return payload
            except JWTError:
                continue
        
        return None
    
    def should_refresh_token(self, payload: dict) -> bool:
        """Check if token should be refreshed with new key"""
        # Refresh if token was issued with an old key
        # Implementation depends on storing key version in JWT
        return False  # Placeholder


# Create global settings instance with validation
try:
    settings = SecureSettings()
    
    # Validate on startup
    if settings.ENVIRONMENT == "production":
        settings.validate_production_config()
        logger.info("Production configuration validated successfully")
    
except ValueError as e:
    logger.error(f"Configuration error: {str(e)}")
    raise

# Export key rotation manager
key_rotation = KeyRotationManager(settings)