"""
Authentication dependencies for FastAPI
"""
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from jose import jwt, JWTError
import logging
import redis

from ..core.database import get_db
from ..core.config import settings
from .models import User

logger = logging.getLogger(__name__)

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get the current authenticated user from the JWT token.
    CRITICAL FIX: Use enhanced JWT service with revocation checks
    """
    token = credentials.credentials
    
    try:
        # CRITICAL FIX: Use enhanced JWT service instead of direct decode
        from .jwt_security import get_jwt_service
        jwt_service = get_jwt_service()
        
        try:
            # Verify token with enhanced security (includes revocation check)
            payload = jwt_service.verify_token(token)
        except AttributeError as e:
            # Handle missing algorithm or secret key configuration
            logger.error(f"JWT configuration error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication service configuration error"
            )
        # Get user_id from token - it's stored as string
        user_id_str = payload.get("sub")
        tenant_id: Optional[str] = payload.get("tenant_id")
        
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Convert to int with proper validation
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # CRITICAL FIX: Always filter by tenant_id to prevent cross-tenant access
    # This addresses the CVSS 9.8 Tenant Isolation Bypass vulnerability
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant ID required in token"
        )
    
    # Get user from database WITH MANDATORY tenant filtering
    user = db.query(User).filter(
        User.id == user_id,
        User.tenant_id == tenant_id  # CRITICAL: Always filter by tenant
    ).first()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Additional validation: Ensure token tenant matches user tenant
    if user.tenant_id != tenant_id:
        logger.warning(f"Tenant mismatch: Token claims tenant {tenant_id} but user belongs to {user.tenant_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: tenant mismatch"
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get the current active user.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get the current user if they are a superuser.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user


def get_tenant_id(current_user: User = Depends(get_current_user)) -> Optional[str]:
    """
    Get the tenant ID from the current user.
    """
    return current_user.tenant_id


async def require_tenant(
    current_user: User = Depends(get_current_user)
) -> str:
    """
    Require that the current user has a tenant_id.
    Returns the tenant_id for use in queries.
    """
    if not current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant access required"
        )
    return current_user.tenant_id


def require_mfa(func):
    """
    Decorator to require MFA verification for a function.
    Addresses CRITICAL-009: MFA Decorator Placeholder Implementation
    """
    from functools import wraps
    from fastapi import Request, HTTPException, status
    import time
    
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract request and current_user from function arguments
        request = None
        current_user = None
        
        # Find request and user in args/kwargs
        for arg in args:
            if hasattr(arg, 'method') and hasattr(arg, 'headers'):  # Request object
                request = arg
            elif hasattr(arg, 'id') and hasattr(arg, 'is_active'):  # User object
                current_user = arg
        
        for key, value in kwargs.items():
            if key == 'request' or (hasattr(value, 'method') and hasattr(value, 'headers')):
                request = value
            elif key == 'current_user' or (hasattr(value, 'id') and hasattr(value, 'is_active')):
                current_user = value
        
        if not request or not current_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA decorator requires request and current_user parameters"
            )
        
        # Check for MFA token in headers
        mfa_token = request.headers.get("X-MFA-Token")
        if not mfa_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification required",
                headers={"WWW-Authenticate": "MFA"}
            )
        
        # Validate MFA token format and freshness
        try:
            # MFA token should be in format: {timestamp}:{token}:{hmac}
            parts = mfa_token.split(':')
            if len(parts) != 3:
                raise ValueError("Invalid MFA token format")
            
            timestamp_str, token, hmac_signature = parts
            timestamp = int(timestamp_str)
            
            # Check if token is not too old (5 minutes max)
            current_time = int(time.time())
            if current_time - timestamp > 300:  # 5 minutes
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="MFA token expired"
                )
            
            # Verify HMAC signature to prevent tampering
            import hmac
            import hashlib
            from ..core.config import settings
            
            expected_hmac = hmac.new(
                settings.SECRET_KEY.encode(),
                f"{timestamp}:{token}:{current_user.id}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(hmac_signature, expected_hmac):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid MFA token signature"
                )
            
            # Validate the actual MFA code
            from .mfa_providers import get_mfa_provider
            
            # Get user's active MFA method (TOTP, email, or SMS)
            mfa_provider = get_mfa_provider(current_user.mfa_method or "email")
            
            if not mfa_provider.verify_code(current_user.id, token, current_user.tenant_id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid MFA code"
                )
            
            # MFA verification successful - proceed with original function
            return await func(*args, **kwargs)
            
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid MFA token format: {e}"
            )
        except Exception as e:
            # Log error but don't expose details
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"MFA verification error: {e}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA verification failed"
            )
    
    return wrapper


security_optional = HTTPBearer(auto_error=False)

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get the current user if authenticated, otherwise return None.
    This is useful for endpoints that work for both authenticated and anonymous users.
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


async def get_secure_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Get the current authenticated user with comprehensive session hijacking protection.
    Addresses RISK-M001: Session Hijacking protection
    
    This dependency:
    1. Validates JWT token
    2. Performs session security analysis
    3. Detects potential hijacking attempts
    4. Applies appropriate security measures
    """
    # First, get the basic authenticated user
    user = await get_current_user(credentials, db)
    
    # Extract session ID from JWT
    token = credentials.credentials
    
    try:
        from .jwt_security import get_jwt_service
        jwt_service = get_jwt_service()
        payload = jwt_service.verify_token(token)
        session_id = payload.get("sid")  # Session ID
        
        if not session_id:
            # Fallback to JTI if no explicit session ID
            session_id = payload.get("jti", "")
        
        if session_id:
            # Apply session hijacking protection
            from .session_hijacking_protection import session_security_middleware
            
            # Get Redis client
            redis_client = None
            try:
                redis_client = redis.Redis.from_url(settings.REDIS_URL or "redis://localhost:6379")
            except Exception as e:
                logger.warning(f"Redis connection failed for session security: {e}")
                # Continue without Redis - protection will use database fallback
            
            # Validate session security (may raise HTTPException)
            session_security_middleware(session_id, str(user.id), request, redis_client, db)
        
    except Exception as e:
        # Log error but don't expose details
        logger.error(f"Session security validation error: {e}")
        # For security reasons, treat any validation error as suspicious
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session validation failed"
        )
    
    return user


async def get_secure_active_user(
    user: User = Depends(get_secure_user)
) -> User:
    """
    Get the current active user with session security validation.
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return user


async def get_secure_superuser(
    user: User = Depends(get_secure_user)
) -> User:
    """
    Get the current user with session security if they are a superuser.
    """
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return user