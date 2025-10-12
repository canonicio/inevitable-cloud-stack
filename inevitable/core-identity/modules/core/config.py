"""
Configuration settings for Platform Forge
"""
import os
import secrets
import warnings
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "Platform Forge"
    VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./platform_forge.db")
    
    # Security - Enhanced with validation
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    @property
    def SECRET_KEY(self) -> str:
        """Get SECRET_KEY with security validation"""
        key = os.getenv("SECRET_KEY", "").strip()
        
        # Check for default/weak keys
        weak_keys = [
            "your-secret-key-here-change-in-production",
            "secret", "password", "changeme", "default", "test", "dev"
        ]
        
        if not key or key.lower() in weak_keys:
            if self.DEBUG:
                # Generate secure random key for development
                key = secrets.token_urlsafe(64)
                warnings.warn(
                    "⚠️  Using generated SECRET_KEY for development. "
                    "Set SECRET_KEY environment variable for production!\n"
                    f"Generated key: {key}",
                    RuntimeWarning
                )
            else:
                raise ValueError(
                    "🚨 SECURITY ERROR: SECRET_KEY must be set in production!\n"
                    "Generate a secure key with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
                )
        
        # Validate key strength
        if len(key) < 32:
            raise ValueError(
                f"🚨 SECURITY ERROR: SECRET_KEY must be at least 32 characters long (got {len(key)})"
            )
        
        return key
    
    @property
    def PLATFORM_FORGE_MASTER_KEY(self) -> str:
        """Get master key for tenant encryption"""
        key = os.getenv("PLATFORM_FORGE_MASTER_KEY", "").strip()
        
        if not key:
            if self.DEBUG:
                key = secrets.token_urlsafe(64)
                warnings.warn(
                    "⚠️  Using generated PLATFORM_FORGE_MASTER_KEY for development",
                    RuntimeWarning
                )
            else:
                raise ValueError(
                    "🚨 SECURITY ERROR: PLATFORM_FORGE_MASTER_KEY must be set in production!"
                )
        
        if len(key) < 32:
            raise ValueError(
                f"🚨 SECURITY ERROR: PLATFORM_FORGE_MASTER_KEY must be at least 32 characters long (got {len(key)})"
            )
        
        return key
    
    # Stripe
    STRIPE_API_KEY: Optional[str] = os.getenv("STRIPE_API_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET")
    STRIPE_PUBLISHABLE_KEY: Optional[str] = os.getenv("STRIPE_PUBLISHABLE_KEY")
    
    # Redis (for caching/sessions)
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")
    
    # CORS
    BACKEND_CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:8000"]
    
    # Email
    SMTP_HOST: Optional[str] = os.getenv("SMTP_HOST")
    SMTP_PORT: Optional[int] = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    EMAILS_FROM_EMAIL: Optional[str] = os.getenv("EMAILS_FROM_EMAIL")
    EMAILS_FROM_NAME: Optional[str] = os.getenv("EMAILS_FROM_NAME", APP_NAME)
    
    # Multi-tenancy
    ENABLE_MULTI_TENANCY: bool = os.getenv("ENABLE_MULTI_TENANCY", "true").lower() == "true"
    
    # Observability
    ENABLE_METRICS: bool = os.getenv("ENABLE_METRICS", "true").lower() == "true"
    METRICS_PORT: int = int(os.getenv("METRICS_PORT", "9090"))
    
    # Privacy/GDPR
    ENABLE_PRIVACY_MODULE: bool = os.getenv("ENABLE_PRIVACY_MODULE", "true").lower() == "true"
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", "365"))
    
    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"  # Ignore extra environment variables


# Create global settings instance
settings = Settings()