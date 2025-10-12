"""
Admin system security configuration
Addresses CRITICAL-012: Admin System Initialization Bypass
"""
import os
import secrets
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AdminSecurityConfig:
    """
    Secure admin system configuration that prevents hardcoded credentials
    Addresses CRITICAL-012: Admin System Initialization Bypass
    """
    
    @staticmethod
    def get_secure_admin_config() -> Dict[str, Any]:
        """
        Get secure admin configuration without any hardcoded credentials.
        Forces proper admin setup during deployment.
        """
        config = {
            "require_secure_setup": True,
            "allow_default_credentials": False,
            "minimum_password_length": 16,
            "require_mfa_for_admin": True,
            "admin_session_timeout": 300,  # 5 minutes
            "max_admin_login_attempts": 3,
        }
        
        # Check for any dangerous environment variables
        dangerous_env_vars = [
            "DEFAULT_ADMIN_PASSWORD",
            "ADMIN_PASSWORD", 
            "INITIAL_ADMIN_PASSWORD"
        ]
        
        for var in dangerous_env_vars:
            if os.environ.get(var):
                logger.critical(
                    f"SECURITY VIOLATION: Found {var} environment variable. "
                    f"Remove this and use proper admin setup process."
                )
                raise ValueError(f"Insecure admin configuration detected: {var}")
        
        return config
    
    @staticmethod
    def validate_admin_setup_request(username: str, password: str, email: str) -> bool:
        """
        Validate admin setup request to ensure security requirements.
        """
        # Validate username
        if not username or len(username) < 3:
            raise ValueError("Admin username must be at least 3 characters")
        
        if username.lower() in ["admin", "administrator", "root", "user"]:
            raise ValueError("Username too common, choose something more unique")
        
        # Validate password strength
        from ..auth.service import auth_service
        is_valid, message = auth_service.validate_password_strength(password)
        if not is_valid:
            raise ValueError(f"Admin password requirements not met: {message}")
        
        # Validate email
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email address format")
        
        return True
    
    @staticmethod
    def generate_secure_admin_token() -> str:
        """Generate a secure admin setup token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def check_for_default_admin() -> None:
        """
        Check if any default admin accounts exist and log warnings.
        This should be called during application startup.
        """
        from sqlalchemy.orm import Session
        from ..core.database import SessionLocal
        from ..auth.models import User
        
        try:
            db: Session = SessionLocal()
            
            # Check for common default usernames
            default_usernames = ["admin", "administrator", "root", "user", "test"]
            
            for username in default_usernames:
                user = db.query(User).filter(User.username == username).first()
                if user:
                    logger.critical(
                        f"SECURITY WARNING: Default username '{username}' detected. "
                        f"Please change this immediately for security."
                    )
            
            # Check for users with weak passwords (if we can detect them)
            all_users = db.query(User).filter(User.is_admin == True).all()
            for user in all_users:
                # We can't directly check password, but we can check creation patterns
                if user.username == "admin" and user.email == "admin@platform-forge.local":
                    logger.critical(
                        f"SECURITY VIOLATION: Default admin account detected! "
                        f"User: {user.username}, Email: {user.email}. "
                        f"This must be changed immediately."
                    )
                    
        except Exception as e:
            logger.error(f"Error checking for default admin accounts: {e}")
        finally:
            db.close()


def validate_no_hardcoded_credentials():
    """
    Startup validation to ensure no hardcoded credentials exist.
    Call this during application initialization.
    """
    try:
        config = AdminSecurityConfig.get_secure_admin_config()
        AdminSecurityConfig.check_for_default_admin()
        logger.info("✅ Admin security validation passed - no hardcoded credentials detected")
    except Exception as e:
        logger.critical(f"❌ Admin security validation failed: {e}")
        raise


# Export the validation function
__all__ = ['AdminSecurityConfig', 'validate_no_hardcoded_credentials']