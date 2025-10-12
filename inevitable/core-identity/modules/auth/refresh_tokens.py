"""
JWT Refresh Token Implementation
Addresses HIGH-002: Missing JWT Refresh Token Implementation
"""
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from sqlalchemy.orm import Session
import redis

from modules.core.config import settings
from modules.auth.models import User

logger = logging.getLogger(__name__)


class RefreshTokenService:
    """
    Secure refresh token implementation with proper revocation support.
    Addresses HIGH-002: Missing JWT Refresh Token Implementation
    """
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire_minutes = 15  # Short-lived access tokens
        self.refresh_token_expire_days = 30  # Long-lived refresh tokens
        
        # Redis for token revocation tracking
        self.redis_client = redis_client or redis.Redis.from_url(
            settings.REDIS_URL or "redis://localhost:6379",
            decode_responses=True
        )
    
    def create_token_pair(self, user_data: dict) -> dict:
        """
        Create secure access/refresh token pair.
        
        Args:
            user_data: Dictionary containing user information (sub, tenant_id, etc.)
            
        Returns:
            Dictionary with access_token, refresh_token, token_type, and expires_in
        """
        # Create short-lived access token (15 minutes)
        access_token = self._create_access_token(
            user_data, 
            expires_delta=timedelta(minutes=self.access_token_expire_minutes)
        )
        
        # Create long-lived refresh token (30 days)
        refresh_jti = secrets.token_urlsafe(32)
        refresh_token = self._create_refresh_token(user_data, jti=refresh_jti)
        
        # Store refresh token metadata for revocation
        self._store_refresh_token(refresh_jti, user_data['sub'])
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60  # in seconds
        }
    
    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Securely refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Dictionary with new access_token and expires_in
            
        Raises:
            ValueError: If refresh token is invalid or revoked
        """
        try:
            # Verify refresh token
            payload = self._verify_refresh_token(refresh_token)
            
            # Check if refresh token is revoked
            if self._is_token_revoked(payload['jti']):
                raise ValueError("Refresh token has been revoked")
            
            # Issue new access token
            access_token = self._create_access_token({
                'sub': payload['sub'],
                'tenant_id': payload.get('tenant_id'),
                'email': payload.get('email'),
                'username': payload.get('username')
            })
            
            # Update last used timestamp for refresh token
            self._update_refresh_token_usage(payload['jti'])
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": self.access_token_expire_minutes * 60
            }
            
        except (JWTError, KeyError, ValueError) as e:
            logger.warning(f"Refresh token validation failed: {e}")
            raise ValueError("Invalid or expired refresh token")
    
    def revoke_refresh_token(self, token: str) -> bool:
        """
        Revoke a refresh token.
        
        Args:
            token: Refresh token to revoke
            
        Returns:
            True if successfully revoked, False otherwise
        """
        try:
            payload = self._verify_refresh_token(token)
            return self._revoke_token(payload['jti'])
        except Exception as e:
            logger.error(f"Failed to revoke refresh token: {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all refresh tokens for a user.
        
        Args:
            user_id: User ID whose tokens should be revoked
            
        Returns:
            Number of tokens revoked
        """
        pattern = f"refresh_token:*:user:{user_id}"
        revoked = 0
        
        for key in self.redis_client.scan_iter(match=pattern):
            if self.redis_client.delete(key):
                revoked += 1
        
        logger.info(f"Revoked {revoked} refresh tokens for user {user_id}")
        return revoked
    
    def _create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create short-lived access token"""
        to_encode = data.copy()
        
        now = datetime.utcnow()
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": now,
            "typ": "access",
            "jti": secrets.token_urlsafe(16)
        })
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def _create_refresh_token(self, data: dict, jti: str) -> str:
        """Create long-lived refresh token"""
        to_encode = data.copy()
        
        now = datetime.utcnow()
        expire = now + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({
            "exp": expire,
            "iat": now,
            "typ": "refresh",
            "jti": jti,
            "sub": data['sub']
        })
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def _verify_refresh_token(self, token: str) -> dict:
        """Verify refresh token and return payload"""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "sub", "jti", "typ"]
                }
            )
            
            # Verify token type
            if payload.get('typ') != 'refresh':
                raise ValueError("Invalid token type")
            
            return payload
            
        except JWTError as e:
            logger.debug(f"Refresh token verification failed: {e}")
            raise ValueError("Invalid refresh token")
    
    def _store_refresh_token(self, jti: str, user_id: str):
        """Store refresh token metadata in Redis"""
        key = f"refresh_token:{jti}:user:{user_id}"
        value = {
            "created_at": datetime.utcnow().isoformat(),
            "last_used": datetime.utcnow().isoformat(),
            "user_id": user_id
        }
        
        # Store with expiration matching token lifetime
        self.redis_client.hset(key, mapping=value)
        self.redis_client.expire(key, self.refresh_token_expire_days * 86400)
    
    def _update_refresh_token_usage(self, jti: str):
        """Update last used timestamp for refresh token"""
        # Find the key (we need to scan since we don't know the user_id)
        for key in self.redis_client.scan_iter(match=f"refresh_token:{jti}:user:*"):
            self.redis_client.hset(key, "last_used", datetime.utcnow().isoformat())
            break
    
    def _is_token_revoked(self, jti: str) -> bool:
        """Check if refresh token is revoked"""
        # Token is valid if it exists in Redis
        for key in self.redis_client.scan_iter(match=f"refresh_token:{jti}:user:*"):
            return False  # Token exists, not revoked
        return True  # Token doesn't exist, considered revoked
    
    def _revoke_token(self, jti: str) -> bool:
        """Revoke a refresh token by JTI"""
        for key in self.redis_client.scan_iter(match=f"refresh_token:{jti}:user:*"):
            return bool(self.redis_client.delete(key))
        return False


# Global instance
_refresh_token_service = None

def get_refresh_token_service() -> RefreshTokenService:
    """Get or create the global refresh token service instance"""
    global _refresh_token_service
    if _refresh_token_service is None:
        _refresh_token_service = RefreshTokenService()
    return _refresh_token_service