"""
Authentication service for Platform Forge
CRITICAL-003 FIX: Enhanced with secure key management and cryptographically secure tokens
"""
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from passlib.context import CryptContext
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.security import SecurityUtils
from .models import User
from .jwt_security import get_jwt_service

logger = logging.getLogger(__name__)


class AuthService:
    """Service for handling authentication operations."""
    
    def __init__(self):
        # Use argon2 as primary with bcrypt as fallback for backward compatibility
        self.pwd_context = CryptContext(
            schemes=["argon2", "bcrypt"],
            default="argon2",
            deprecated="auto"
        )
        # CRITICAL-003 FIX: Use enhanced JWT service with secure key management
        self.jwt_service = get_jwt_service()
        # Keep legacy fields for backward compatibility
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash."""
        return self.pwd_context.hash(password)
    
    def authenticate_user(self, db: Session, username_or_email: str, password: str, tenant_id: str) -> Optional[User]:
        """
        Authenticate a user by username or email and password.
        CRITICAL FIX: tenant_id is now MANDATORY to prevent cross-tenant authentication bypass
        """
        import time
        from datetime import datetime, timedelta
        import pytz
        
        # CRITICAL FIX: tenant_id is now mandatory 
        if not tenant_id:
            raise ValueError("tenant_id is required for authentication")
        
        # Find user by username or email WITH MANDATORY tenant filtering
        query = db.query(User).filter(
            (User.username == username_or_email) | (User.email == username_or_email),
            User.tenant_id == tenant_id  # CRITICAL: Always filter by tenant
        )
        
        user = query.first()
        
        if not user:
            # Prevent timing attacks by simulating password verification
            self._simulate_password_verification()
            return None
        
        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.now(pytz.UTC):
            return None
        
        # Verify password
        if not self.verify_password(password, user.hashed_password):
            # Increment failed attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now(pytz.UTC)
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(pytz.UTC) + timedelta(minutes=15)
            
            db.commit()
            return None
        
        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_failed_login = None
        user.locked_until = None
        db.commit()
        
        return user
    
    def _simulate_password_verification(self):
        """Simulate password verification to prevent timing attacks."""
        # Use a dummy hash to simulate real bcrypt timing
        # This ensures the timing is consistent with actual password verification
        dummy_password = "dummy_password_for_timing"
        dummy_hash = "$2b$12$PEmxrth.vjPDazPWQcLs6u9GRFLJvneUkcf/vcXn8L.bzaBUKeX4W"  # Pre-computed bcrypt hash
        
        # This will take approximately the same time as a real password verification
        try:
            self.pwd_context.verify(dummy_password, dummy_hash)
        except:
            # In case of any error, just continue
            pass
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None, regenerate_session: bool = False) -> str:
        """
        CRITICAL-003 FIX: Create cryptographically secure JWT access token
        
        Uses enhanced JWT service with:
        - Secure key rotation management
        - Enhanced entropy in random components
        - Session fingerprinting for security
        - Comprehensive claim validation
        """
        try:
            # Extract user information from data
            user_id = data.get('sub', '')
            tenant_id = data.get('tenant_id', '')
            permissions = data.get('permissions', [])
            roles = data.get('roles', [])
            
            # Determine authentication level
            auth_level = 2 if regenerate_session else 1  # 2 for full auth, 1 for initial
            
            # Use enhanced JWT service for secure token creation
            token, jti = self.jwt_service.create_access_token(
                user_id=user_id,
                tenant_id=tenant_id,
                expires_delta=expires_delta,
                auth_level=auth_level,
                permissions=permissions,
                roles=roles,
                additional_claims={
                    k: v for k, v in data.items() 
                    if k not in ['sub', 'tenant_id', 'permissions', 'roles']
                }
            )
            
            logger.info(
                "Access token created with enhanced security",
                extra={
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "auth_level": auth_level,
                    "jti": jti[:8] + "..."
                }
            )
            
            return token
            
        except Exception as e:
            # CRITICAL SECURITY FIX: Never fall back to insecure token creation
            logger.error(f"Failed to create secure access token: {e}")
            raise Exception("Secure token creation failed - cannot proceed with insecure fallback")
    
    def _create_legacy_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None, regenerate_session: bool = False) -> str:
        """Legacy token creation for emergency fallback only"""
        to_encode = data.copy()
        
        # Add issued at time
        now = datetime.utcnow()
        to_encode.update({"iat": now})
        
        # Add expiration
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        
        # Generate secure identifiers even in legacy mode
        import secrets
        import hashlib
        
        session_data = f"{data.get('sub', '')}{data.get('tenant_id', '')}{now.timestamp()}"
        session_fingerprint = hashlib.sha256(session_data.encode()).hexdigest()[:16]
        
        jti = secrets.token_urlsafe(20)
        session_id = f"sess_{secrets.token_urlsafe(24)}"
        
        to_encode.update({
            "jti": jti,
            "sid": session_id,
            "sfp": session_fingerprint,
            "auth_level": "full" if regenerate_session else "initial",
            "typ": "access",
            "legacy": True  # Mark as legacy token
        })
        
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str, expected_tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        CRITICAL-003 FIX: Verify JWT token with enhanced security
        
        Uses enhanced JWT service with:
        - Multi-key support for graceful key rotation
        - Comprehensive claim validation  
        - Timing attack protection
        - Session fingerprint validation
        """
        try:
            # Try enhanced JWT service first
            payload = self.jwt_service.verify_token(
                token=token,
                expected_tenant_id=expected_tenant_id
            )
            
            # Check if token is revoked
            jti = payload.get('jti', '')
            if jti and self.jwt_service.is_token_revoked(jti):
                logger.warning(f"Attempted use of revoked token: {jti[:8]}...")
                return None
            
            return payload
            
        except JWTError as e:
            # CRITICAL SECURITY FIX: Never fall back to insecure verification
            # This prevents bypassing revocation checks and MFA requirements
            logger.error(f"JWT verification failed - NO FALLBACK: {str(e)}")
            return None  # Fail securely - no fallback to legacy mode
            
        except Exception as e:
            logger.error(f"JWT verification error: {str(e)}")
            return None
    
    def _verify_legacy_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Legacy token verification for backward compatibility"""
        try:
            # SECURITY: Only allow our specific algorithm
            if self.algorithm != "HS256":
                logger.error(f"Invalid JWT algorithm configuration: {self.algorithm}")
                return None
            
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "require": ["exp", "iat", "sub"]
                }
            )
            
            # Validate required claims
            required_claims = ["sub", "jti", "sid", "sfp", "typ"]
            for claim in required_claims:
                if claim not in payload:
                    logger.warning(f"Missing required claim {claim} in JWT")
                    return None
            
            # Validate token type
            if payload.get("typ") != "access":
                logger.warning(f"Invalid token type: {payload.get('typ')}")
                return None
            
            # Validate session fingerprint format
            sfp = payload.get("sfp")
            if not sfp or len(sfp) != 16 or not all(c in '0123456789abcdef' for c in sfp):
                logger.warning("Invalid session fingerprint format")
                return None
            
            # Mark as legacy for monitoring
            payload['_legacy_verification'] = True
            
            return payload
            
        except JWTError as e:
            logger.debug(f"Legacy JWT verification failed: {e}")
            return None
    
    def create_refresh_session(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new session after successful authentication.
        This forces session regeneration to prevent fixation attacks.
        """
        # Always regenerate session for post-auth tokens
        return self.create_access_token(user_data, regenerate_session=True)
    
    def create_user(
        self,
        db: Session,
        username: str,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
        is_active: bool = True,
        is_superuser: bool = False
    ) -> User:
        """Create a new user."""
        hashed_password = self.get_password_hash(password)
        
        user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            tenant_id=tenant_id,
            is_active=is_active,
            is_superuser=is_superuser
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    def update_password(self, db: Session, user: User, new_password: str) -> User:
        """Update user password."""
        user.hashed_password = self.get_password_hash(new_password)
        db.commit()
        db.refresh(user)
        return user
    
    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """
        Enhanced password strength validation addressing MEDIUM-003.
        Protects against passwords from leaked databases and common attacks.
        """
        import re
        import hashlib
        
        issues = []
        
        # Length requirements (increased from 8 to 12)
        if len(password) < 12:
            issues.append("Password must be at least 12 characters long")
        
        if len(password) > 128:
            issues.append("Password cannot exceed 128 characters")
        
        # Character diversity requirements
        if not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one digit")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`" for c in password):
            issues.append("Password must contain at least one special character")
        
        # Comprehensive common password database (from major breaches)
        common_passwords = {
            # Top 100 most common passwords from major breaches
            'password', '123456', '123456789', 'qwerty', 'abc123', '111111',
            'password1', 'admin', 'welcome', 'monkey', 'letmein', '1234567890',
            'dragon', 'master', 'princess', 'login', 'welcome123', 'solo',
            'passw0rd', 'starwars', 'hello', 'freedom', 'whatever', 'qwerty123',
            'trustno1', 'jordan23', 'harley', 'robert', 'matthew', 'jordan',
            'asshole', 'daniel', 'andrew', 'joshua', 'samsung', 'hunter',
            'charlie', 'thomas', 'hockey', 'tigger', 'shadow', 'michael',
            'jennifer', 'computer', 'michelle', 'maggie', 'sophia', 'ginger',
            'purple', 'secret', 'baseball', 'butthead', 'time', 'orange',
            'lakers', 'michelle1', 'yellow', 'internet', 'basketball', 'player',
            'sunshine', 'morgan', 'starwars1', 'tiger', 'enter', 'mercedes',
            'martin', 'george', 'diamond', 'trouble', 'bianca', 'alex',
            'super', 'thomas1', 'prince', 'family', 'flower', 'royal',
            'anthony', 'monica', 'lucky', 'dolphins', 'golden', 'chelsea',
            'black', 'ashley', 'chris', 'green', 'test', 'superman',
            'steelers', 'maverick', 'coffee', 'lol123', 'access', 'flower1',
            'thunder', 'taylor', 'buster', 'scooter', 'blue', 'gregory',
            'mountain', 'TEST', 'cooper', 'jordan1', 'miller', 'johnathan',
            'gizmodo', 'arthur', 'security', '1234', '12345', '12345678'
        }
        
        # Check against common passwords (case insensitive)
        if password.lower() in common_passwords:
            issues.append("Password found in common password database")
        
        # Check for simple patterns
        if re.match(r'^(.)\1+$', password):  # All same character
            issues.append("Password cannot be all the same character")
        
        if re.match(r'^(012|123|234|345|456|567|678|789|890)+', password.lower()):
            issues.append("Password cannot contain sequential numbers")
        
        if re.match(r'^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+', password.lower()):
            issues.append("Password cannot contain sequential letters")
        
        # Check keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'qwertyuiop', 'asdfghjkl', 
            'zxcvbnm', '!@#$%^&*()', 'qwer', 'asdf', 'zxcv'
        ]
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                issues.append("Password cannot contain keyboard patterns")
                break
        
        # Check for repetitive patterns
        if re.search(r'(.{2,})\1{2,}', password):  # Repeating substrings
            issues.append("Password cannot contain repetitive patterns")
        
        # Dictionary word detection (basic)
        common_words = {
            'love', 'hate', 'baby', 'cool', 'work', 'home', 'life', 'good', 'time',
            'year', 'people', 'make', 'just', 'know', 'take', 'person', 'into',
            'your', 'what', 'have', 'from', 'they', 'want', 'been', 'more'
        }
        
        # Remove numbers and special chars, check if remaining is common word
        word_part = re.sub(r'[^a-zA-Z]', '', password.lower())
        if len(word_part) > 6 and word_part in common_words:
            issues.append("Password cannot be based on common dictionary words")
        
        # Check for personal information patterns (basic heuristics)
        # Dates (YYYY, MM/DD/YYYY, DD/MM/YYYY patterns)
        if re.search(r'(19|20)\d{2}', password) or re.search(r'\d{1,2}/\d{1,2}/\d{2,4}', password):
            issues.append("Password should not contain dates")
        
        # Phone number patterns
        if re.search(r'\d{10}|\(\d{3}\)\s*\d{3}-?\d{4}', password):
            issues.append("Password should not contain phone numbers")
        
        # Check password entropy (approximate)
        unique_chars = len(set(password))
        entropy = unique_chars * len(password) * 0.5  # Rough entropy calculation
        if entropy < 50:
            issues.append("Password lacks sufficient entropy/randomness")
        
        # Check for password in hash against known breaches (simplified)
        # In production, you'd use APIs like HaveIBeenPwned
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        # Some well-known breach hashes (first 5 chars of SHA1)
        known_breach_prefixes = {
            'B1B37', 'C2543', '482C8', '65E8B', 'F25A2', 'E38AD', '5BAA6',
            '7C6A1', '0D107', '1E4C9', '5994A', '21BD1', '7B522', 'A4F67'
        }
        
        if password_hash[:5] in known_breach_prefixes:
            issues.append("Password appears in known data breaches")
        
        # Rate the overall password strength
        strength_score = 0
        if len(password) >= 12: strength_score += 1
        if len(password) >= 16: strength_score += 1
        if any(c.isupper() for c in password): strength_score += 1
        if any(c.islower() for c in password): strength_score += 1
        if any(c.isdigit() for c in password): strength_score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~`" for c in password): strength_score += 1
        if unique_chars > len(password) * 0.5: strength_score += 1
        
        if strength_score < 5:
            issues.append("Password strength is insufficient")
        
        if issues:
            return False, "; ".join(issues[:3])  # Limit to first 3 issues for usability
        
        return True, "Password meets security requirements"


# Create a singleton instance
auth_service = AuthService()