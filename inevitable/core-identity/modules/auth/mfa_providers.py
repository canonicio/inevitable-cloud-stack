"""
MFA Providers for different authentication methods
"""
import secrets
import string
import logging
import hmac
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from sqlalchemy.orm import Session
import redis

from modules.core.config import settings
from modules.core.crypto import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)


class MFAProvider(ABC):
    """Abstract base class for MFA providers"""
    
    @abstractmethod
    def generate_code(self, user_id: int, **kwargs) -> str:
        """Generate an MFA code"""
        pass
    
    @abstractmethod
    def verify_code(self, user_id: int, code: str, **kwargs) -> bool:
        """Verify an MFA code"""
        pass
    
    @abstractmethod
    def send_code(self, user_id: int, code: str, **kwargs) -> bool:
        """Send the MFA code to the user"""
        pass


class EmailMFAProvider(MFAProvider):
    """Email-based MFA provider with rate limiting and database fallback"""
    
    def __init__(self, db: Session, redis_client: Optional[redis.Redis] = None):
        self.db = db
        try:
            self.redis_client = redis_client or redis.Redis.from_url(
                settings.REDIS_URL or "redis://localhost:6379"
            )
            # Test Redis connection
            self.redis_client.ping()
            self.redis_available = True
        except Exception as e:
            logger.warning(f"Redis not available for MFA, using database fallback: {e}")
            self.redis_client = None
            self.redis_available = False
        self.code_length = 6
        self.code_ttl = 300  # 5 minutes
        
        # MEDIUM-002 FIX: Add rate limiting configuration
        self.rate_limit = {
            'requests': 5,  # Maximum 5 email codes
            'window': 3600  # Per hour
        }
    
    def _check_rate_limit_db(self, user_id: int) -> bool:
        """Database fallback for rate limiting when Redis unavailable"""
        from sqlalchemy import text
        
        # Use raw SQL for better performance
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.rate_limit['window'])
        
        # Check attempts in the last window using database
        result = self.db.execute(text("""
            SELECT COUNT(*) as attempt_count
            FROM mfa_attempts 
            WHERE user_id = :user_id 
            AND created_at > :cutoff_time
            AND method_type = 'email'
        """), {"user_id": user_id, "cutoff_time": cutoff_time})
        
        attempt_count = result.scalar() or 0
        
        # Record this attempt
        self.db.execute(text("""
            INSERT INTO mfa_attempts (user_id, created_at, method_type) 
            VALUES (:user_id, :now, 'email')
        """), {"user_id": user_id, "now": datetime.utcnow()})
        
        return attempt_count < self.rate_limit['requests']
    
    def _store_code_db(self, user_id: int, code: str) -> None:
        """Database fallback for code storage when Redis unavailable"""
        from sqlalchemy import text
        
        # Clear any existing codes for this user
        self.db.execute(text("""
            DELETE FROM mfa_codes 
            WHERE user_id = :user_id AND method_type = 'email'
        """), {"user_id": user_id})
        
        # Store new code with expiration
        expires_at = datetime.utcnow() + timedelta(seconds=self.code_ttl)
        self.db.execute(text("""
            INSERT INTO mfa_codes (user_id, code, expires_at, created_at, method_type)
            VALUES (:user_id, :code, :expires_at, :now, 'email')
        """), {
            "user_id": user_id, 
            "code": code, 
            "expires_at": expires_at, 
            "now": datetime.utcnow()
        })
        self.db.commit()
    
    def _verify_code_db(self, user_id: int, code: str) -> bool:
        """Database fallback for code verification when Redis unavailable"""
        from sqlalchemy import text
        
        # Get and delete code atomically (as much as possible with DB)
        result = self.db.execute(text("""
            SELECT code FROM mfa_codes 
            WHERE user_id = :user_id 
            AND expires_at > :now
            AND method_type = 'email'
            FOR UPDATE
        """), {"user_id": user_id, "now": datetime.utcnow()})
        
        stored_code = result.scalar()
        
        if stored_code:
            # Delete the code (one-time use)
            self.db.execute(text("""
                DELETE FROM mfa_codes 
                WHERE user_id = :user_id AND method_type = 'email'
            """), {"user_id": user_id})
            self.db.commit()
            
            # Use timing-safe comparison
            return hmac.compare_digest(str(stored_code), str(code))
        
        return False
    
    def _check_rate_limit(self, user_id: int) -> bool:
        """
        Check and update rate limit for MFA code generation.
        Addresses MEDIUM-002: Missing Rate Limiting on MFA Code Generation
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            return self._check_rate_limit_db(user_id)
        
        key = f"mfa_rate:email:{user_id}"
        
        try:
            # Use Redis pipeline for atomic operation
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.rate_limit['window'])
            results = pipe.execute()
            
            current_count = results[0]
            
            if current_count > self.rate_limit['requests']:
                # Log potential abuse
                logger.warning(
                    f"MFA email rate limit exceeded for user {user_id}: {current_count} attempts"
                )
                return False
            
            return True
        except Exception as e:
            logger.warning(f"Redis error in rate limiting, falling back to database: {e}")
            # Fallback to database if Redis fails
            return self._check_rate_limit_db(user_id)
    
    def generate_code(self, user_id: int, **kwargs) -> str:
        """
        Generate a 6-digit code for email MFA using cryptographically secure random with rate limiting.
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # MEDIUM-002 FIX: Check rate limit before generating code
        if not self._check_rate_limit(user_id):
            raise ValueError(f"Too many email codes requested. Maximum {self.rate_limit['requests']} per hour. Try again later.")
        
        code = ''.join(secrets.choice(string.digits) for _ in range(self.code_length))
        
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            self._store_code_db(user_id, code)
        else:
            try:
                # Store in Redis with TTL
                key = f"mfa:email:{user_id}"
                self.redis_client.setex(key, self.code_ttl, code)
            except Exception as e:
                logger.warning(f"Redis error storing MFA code, using database fallback: {e}")
                self._store_code_db(user_id, code)
        
        return code
    
    def verify_code(self, user_id: int, code: str, **kwargs) -> bool:
        """
        Verify the email MFA code with timing attack protection and race condition prevention.
        CRITICAL FIX: Uses hmac.compare_digest to prevent timing attacks
        MEDIUM FIX: Uses atomic Redis operation to prevent race conditions
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            return self._verify_code_db(user_id, code)
        
        key = f"mfa:email:{user_id}"
        
        try:
            # MEDIUM FIX: Use Redis atomic operation to prevent race conditions
            # GETDEL atomically gets and deletes the key in one operation
            try:
                # Try Redis GETDEL if available (Redis 6.2+)
                stored_code = self.redis_client.getdel(key)
            except AttributeError:
                # Fallback to Lua script for atomic get-and-delete on older Redis
                lua_script = """
                local value = redis.call('GET', KEYS[1])
                if value then
                    redis.call('DEL', KEYS[1])
                    return value
                else
                    return nil
                end
                """
                stored_code = self.redis_client.eval(lua_script, 1, key)
            
            if not stored_code:
                return False
            
            # Convert bytes to string if needed
            if isinstance(stored_code, bytes):
                stored_code = stored_code.decode()
            
            # CRITICAL FIX: Use hmac.compare_digest for constant-time comparison
            # This prevents attackers from using timing differences to determine correct digits
            return hmac.compare_digest(stored_code, code)
        except Exception as e:
            logger.warning(f"Redis error verifying MFA code, using database fallback: {e}")
            return self._verify_code_db(user_id, code)
    
    def send_code(self, user_id: int, code: str, **kwargs) -> bool:
        """Send MFA code via email"""
        from modules.auth.models import User
        
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Your Platform Forge Security Code'
            msg['From'] = settings.SMTP_FROM_EMAIL
            msg['To'] = user.email
            
            # Create the body of the message
            text = f"""
Your Platform Forge security code is: {code}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email and ensure your account is secure.
"""
            
            html = f"""
<html>
  <body>
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Your Platform Forge Security Code</h2>
      <div style="background-color: #f0f0f0; padding: 20px; text-align: center; margin: 20px 0;">
        <h1 style="font-size: 36px; letter-spacing: 8px; margin: 0;">{code}</h1>
      </div>
      <p>This code will expire in 5 minutes.</p>
      <p style="color: #666;">If you didn't request this code, please ignore this email and ensure your account is secure.</p>
    </div>
  </body>
</html>
"""
            
            # Record the MIME types of both parts
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Use the new email service
            from modules.core.email_service import email_service
            import asyncio
            
            # Run async email send
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(email_service.send_mfa_code_email(user, code))
            loop.close()
            
            return result
            
        except Exception as e:
            # Log the error
            import logging
            logging.error(f"Failed to send email MFA code: {str(e)}")
            return False


class SMSMFAProvider(MFAProvider):
    """SMS-based MFA provider using Twilio with rate limiting"""
    
    def __init__(self, db: Session, redis_client: Optional[redis.Redis] = None):
        self.db = db
        try:
            self.redis_client = redis_client or redis.Redis.from_url(
                settings.REDIS_URL or "redis://localhost:6379"
            )
            # Test Redis connection
            self.redis_client.ping()
            self.redis_available = True
        except Exception as e:
            logger.warning(f"Redis not available for SMS MFA, using database fallback: {e}")
            self.redis_client = None
            self.redis_available = False
        self.code_length = 6
        self.code_ttl = 300  # 5 minutes
        
        # Initialize Twilio client
        self.twilio_client = Client(
            settings.TWILIO_ACCOUNT_SID,
            settings.TWILIO_AUTH_TOKEN
        ) if settings.TWILIO_ACCOUNT_SID else None
        
        # MEDIUM-002 FIX: Add rate limiting configuration for SMS (more restrictive due to cost)
        self.rate_limit = {
            'requests': 3,   # Maximum 3 SMS codes (SMS costs money)
            'window': 3600   # Per hour
        }
    
    def _check_rate_limit_db(self, user_id: int) -> bool:
        """Database fallback for rate limiting when Redis unavailable"""
        from sqlalchemy import text
        
        # Use raw SQL for better performance
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.rate_limit['window'])
        
        # Check attempts in the last window using database
        result = self.db.execute(text("""
            SELECT COUNT(*) as attempt_count
            FROM mfa_attempts 
            WHERE user_id = :user_id 
            AND created_at > :cutoff_time
            AND method_type = 'sms'
        """), {"user_id": user_id, "cutoff_time": cutoff_time})
        
        attempt_count = result.scalar() or 0
        
        # Record this attempt
        self.db.execute(text("""
            INSERT INTO mfa_attempts (user_id, created_at, method_type) 
            VALUES (:user_id, :now, 'sms')
        """), {"user_id": user_id, "now": datetime.utcnow()})
        
        return attempt_count < self.rate_limit['requests']
    
    def _store_code_db(self, user_id: int, code: str) -> None:
        """Database fallback for code storage when Redis unavailable"""
        from sqlalchemy import text
        
        # Clear any existing codes for this user
        self.db.execute(text("""
            DELETE FROM mfa_codes 
            WHERE user_id = :user_id AND method_type = 'sms'
        """), {"user_id": user_id})
        
        # Store new code with expiration
        expires_at = datetime.utcnow() + timedelta(seconds=self.code_ttl)
        self.db.execute(text("""
            INSERT INTO mfa_codes (user_id, code, expires_at, created_at, method_type)
            VALUES (:user_id, :code, :expires_at, :now, 'sms')
        """), {
            "user_id": user_id, 
            "code": code, 
            "expires_at": expires_at, 
            "now": datetime.utcnow()
        })
        self.db.commit()
    
    def _verify_code_db(self, user_id: int, code: str) -> bool:
        """Database fallback for code verification when Redis unavailable"""
        from sqlalchemy import text
        
        # Get and delete code atomically (as much as possible with DB)
        result = self.db.execute(text("""
            SELECT code FROM mfa_codes 
            WHERE user_id = :user_id 
            AND expires_at > :now
            AND method_type = 'sms'
            FOR UPDATE
        """), {"user_id": user_id, "now": datetime.utcnow()})
        
        stored_code = result.scalar()
        
        if stored_code:
            # Delete the code (one-time use)
            self.db.execute(text("""
                DELETE FROM mfa_codes 
                WHERE user_id = :user_id AND method_type = 'sms'
            """), {"user_id": user_id})
            self.db.commit()
            
            # Use timing-safe comparison
            return hmac.compare_digest(str(stored_code), str(code))
        
        return False
    
    def _check_rate_limit(self, user_id: int) -> bool:
        """
        Check and update rate limit for SMS MFA code generation.
        Addresses MEDIUM-002: Missing Rate Limiting on MFA Code Generation
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            return self._check_rate_limit_db(user_id)
        
        key = f"mfa_rate:sms:{user_id}"
        
        try:
            # Use Redis pipeline for atomic operation
            pipe = self.redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.rate_limit['window'])
            results = pipe.execute()
            
            current_count = results[0]
            
            if current_count > self.rate_limit['requests']:
                # Log potential abuse - important for SMS due to cost
                logger.warning(
                    f"MFA SMS rate limit exceeded for user {user_id}: {current_count} attempts - potential cost impact"
                )
                return False
            
            return True
        except Exception as e:
            logger.warning(f"Redis error in SMS rate limiting, falling back to database: {e}")
            # Fallback to database if Redis fails
            return self._check_rate_limit_db(user_id)
    
    def generate_code(self, user_id: int, **kwargs) -> str:
        """
        Generate a 6-digit code for SMS MFA using cryptographically secure random with rate limiting.
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # MEDIUM-002 FIX: Check rate limit before generating code (critical for SMS cost control)
        if not self._check_rate_limit(user_id):
            raise ValueError(f"Too many SMS codes requested. Maximum {self.rate_limit['requests']} per hour. Try again later.")
        
        code = ''.join(secrets.choice(string.digits) for _ in range(self.code_length))
        
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            self._store_code_db(user_id, code)
        else:
            try:
                # Store in Redis with TTL
                key = f"mfa:sms:{user_id}"
                self.redis_client.setex(key, self.code_ttl, code)
            except Exception as e:
                logger.warning(f"Redis error storing SMS MFA code, using database fallback: {e}")
                self._store_code_db(user_id, code)
        
        return code
    
    def verify_code(self, user_id: int, code: str, **kwargs) -> bool:
        """
        Verify the SMS MFA code with timing attack protection and race condition prevention.
        CRITICAL FIX: Uses hmac.compare_digest to prevent timing attacks
        MEDIUM FIX: Uses atomic Redis operation to prevent race conditions
        HIGH FIX: Added database fallback when Redis unavailable
        """
        # HIGH FIX: Use database fallback if Redis not available
        if not self.redis_available:
            return self._verify_code_db(user_id, code)
        
        key = f"mfa:sms:{user_id}"
        
        try:
            # MEDIUM FIX: Use Redis atomic operation to prevent race conditions
            # GETDEL atomically gets and deletes the key in one operation
            try:
                # Try Redis GETDEL if available (Redis 6.2+)
                stored_code = self.redis_client.getdel(key)
            except AttributeError:
                # Fallback to Lua script for atomic get-and-delete on older Redis
                lua_script = """
                local value = redis.call('GET', KEYS[1])
                if value then
                    redis.call('DEL', KEYS[1])
                    return value
                else
                    return nil
                end
                """
                stored_code = self.redis_client.eval(lua_script, 1, key)
            
            if not stored_code:
                return False
            
            # Convert bytes to string if needed
            if isinstance(stored_code, bytes):
                stored_code = stored_code.decode()
            
            # CRITICAL FIX: Use hmac.compare_digest for constant-time comparison
            # This prevents attackers from using timing differences to determine correct digits
            return hmac.compare_digest(stored_code, code)
        except Exception as e:
            logger.warning(f"Redis error verifying SMS MFA code, using database fallback: {e}")
            return self._verify_code_db(user_id, code)
    
    def send_code(self, user_id: int, code: str, **kwargs) -> bool:
        """Send MFA code via SMS"""
        if not self.twilio_client:
            print("Twilio client not configured")
            return False
        
        phone_number = kwargs.get('phone_number')
        if not phone_number:
            # Get phone number from user profile
            from modules.auth.models import User
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user or not hasattr(user, 'phone_number'):
                return False
            phone_number = user.phone_number
        
        if not phone_number:
            return False
        
        try:
            message = self.twilio_client.messages.create(
                body=f"Your Platform Forge security code is: {code}. This code will expire in 5 minutes.",
                from_=settings.TWILIO_FROM_NUMBER,
                to=phone_number
            )
            
            return message.sid is not None
            
        except Exception as e:
            # Log the error
            print(f"Failed to send SMS MFA code: {str(e)}")
            return False


class MFAProviderFactory:
    """Factory for creating MFA providers"""
    
    _providers = {
        'email': EmailMFAProvider,
        'sms': SMSMFAProvider,
    }
    
    @classmethod
    def create(cls, provider_type: str, db: Session, **kwargs) -> Optional[MFAProvider]:
        """Create an MFA provider instance"""
        provider_class = cls._providers.get(provider_type)
        if not provider_class:
            return None
        
        return provider_class(db, **kwargs)
    
    @classmethod
    def register_provider(cls, provider_type: str, provider_class: type):
        """Register a new MFA provider"""
        cls._providers[provider_type] = provider_class