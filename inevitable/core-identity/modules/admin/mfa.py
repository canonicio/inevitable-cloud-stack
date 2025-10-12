"""
Secure Multi-Factor Authentication module
Addresses CRITICAL-004: MFA Secret Exposure
"""
import pyotp
import qrcode
import io
import base64
import hmac
from typing import Optional, List
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from modules.core.database import get_db
from modules.core.security import CryptoUtils, SecurityError
from modules.auth.models import User
import secrets
import string
import logging

logger = logging.getLogger(__name__)

class SecureMFAService:
    """Secure service for handling Multi-Factor Authentication"""
    
    def __init__(self):
        self.crypto = CryptoUtils()
    
    def generate_secret(self) -> str:
        """
        Generate a new MFA secret key with cryptographically secure randomness.
        MEDIUM FIX: Uses secrets module instead of PyOTP default for guaranteed secure randomness
        """
        import secrets
        import base64
        
        # Generate 160 bits (20 bytes) of cryptographically secure random data
        # This provides sufficient entropy for TOTP secrets
        random_bytes = secrets.token_bytes(20)
        
        # Convert to base32 encoding (required for TOTP)
        return base64.b32encode(random_bytes).decode('utf-8')
    
    def encrypt_secret(self, secret: str) -> str:
        """Encrypt MFA secret for storage"""
        return self.crypto.encrypt_sensitive_data(secret)
    
    def decrypt_secret(self, encrypted_secret: str) -> str:
        """Decrypt MFA secret for use"""
        return self.crypto.decrypt_sensitive_data(encrypted_secret)
    
    def generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate backup codes for MFA recovery"""
        codes = []
        for _ in range(count):
            # Generate cryptographically secure backup codes
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    def encrypt_backup_codes(self, codes: List[str]) -> str:
        """Encrypt backup codes for storage"""
        codes_str = ','.join(codes)
        return self.crypto.encrypt_sensitive_data(codes_str)
    
    def decrypt_backup_codes(self, encrypted_codes: str) -> List[str]:
        """Decrypt backup codes for use"""
        if not encrypted_codes:
            return []
        codes_str = self.crypto.decrypt_sensitive_data(encrypted_codes)
        return codes_str.split(',') if codes_str else []
    
    def generate_qr_code(self, user_email: str, secret: str, issuer: str = "Platform Forge") -> str:
        """Generate QR code for MFA setup"""
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for web display
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.read()).decode()
        
        return f"data:image/png;base64,{img_base64}"
    
    def verify_token(self, secret: str, token: str) -> bool:
        """
        Verify TOTP token with timing attack protection.
        CRITICAL-007 FIX: Custom constant-time TOTP verification
        """
        if not secret or not token:
            return False
        
        try:
            totp = pyotp.TOTP(secret)
            
            # CRITICAL FIX: Manual constant-time TOTP verification
            # PyOTP's internal verify() may not use constant-time comparison,
            # so we implement our own with hmac.compare_digest()
            import time
            
            current_time = int(time.time())
            valid_window = 2  # Allow 2 time steps before and after (90-second tolerance)
            
            # Check current time and surrounding windows using constant-time comparison
            for offset in range(-valid_window, valid_window + 1):
                expected_token = totp.at(current_time + (offset * 30))  # 30-second intervals
                if hmac.compare_digest(expected_token, token):
                    return True
            
            return False
            
        except Exception as e:
            logger.warning(f"MFA token verification failed: {e}")
            return False
    
    def verify_backup_code(self, user: User, code: str, db: Session) -> bool:
        """
        Verify backup code and mark as used with timing attack protection.
        CRITICAL-007 FIX: Uses constant-time comparison to prevent timing attacks
        """
        if not user.backup_codes or not code:
            return False
        
        try:
            # Get backup codes - automatically decrypted by hybrid property
            codes_str = user.backup_codes
            backup_codes = codes_str.split(',') if codes_str else []
            
            # CRITICAL FIX: Use constant-time comparison for backup codes
            # This prevents timing attacks on backup code verification
            valid_code_found = False
            valid_code_index = -1
            
            # Check each backup code using constant-time comparison
            for i, backup_code in enumerate(backup_codes):
                if hmac.compare_digest(backup_code.strip(), code.strip()):
                    valid_code_found = True
                    valid_code_index = i
                    break
            
            if valid_code_found:
                # Remove used code
                backup_codes.pop(valid_code_index)
                
                # Save updated codes - will be automatically encrypted
                user.backup_codes = ','.join(backup_codes) if backup_codes else None
                db.commit()
                
                logger.info(f"Backup code used for user {user.id}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Backup code verification failed: {e}")
            return False

# Global MFA service instance
_mfa_service = None

def get_mfa_service() -> SecureMFAService:
    """Get global MFA service instance"""
    global _mfa_service
    if _mfa_service is None:
        _mfa_service = SecureMFAService()
    return _mfa_service

async def setup_mfa(
    user_id: int,
    db: Session = Depends(get_db)
) -> dict:
    """Initialize MFA setup for a user"""
    mfa_service = get_mfa_service()
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    
    try:
        # Generate new secret
        secret = mfa_service.generate_secret()
        
        # Store secret - it will be automatically encrypted by the hybrid property
        user.mfa_secret = secret
        db.commit()
        
        # Generate QR code (using plaintext secret)
        qr_code = mfa_service.generate_qr_code(user.email, secret)
        
        logger.info(f"MFA setup initiated for user {user_id}")
        
        # IMPORTANT: Never return the secret in production
        # Only return QR code and setup instructions
        return {
            "qr_code": qr_code,
            "message": "Scan the QR code with your authenticator app and verify with a token",
            "setup_complete": False
        }
        
    except Exception as e:
        logger.error(f"MFA setup failed for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="MFA setup failed")

async def enable_mfa(
    user_id: int,
    token: str,
    db: Session = Depends(get_db)
) -> dict:
    """Enable MFA for a user after verifying setup token"""
    mfa_service = get_mfa_service()
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not initialized")
    
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")
    
    try:
        # Get secret - it will be automatically decrypted by the hybrid property
        secret = user.mfa_secret
        
        # Verify setup token
        if not mfa_service.verify_token(secret, token):
            raise HTTPException(status_code=400, detail="Invalid token")
        
        # Generate backup codes
        backup_codes = mfa_service.generate_backup_codes()
        
        # Enable MFA - backup codes will be automatically encrypted by the hybrid property
        user.mfa_enabled = True
        user.backup_codes = ','.join(backup_codes)
        db.commit()
        
        logger.info(f"MFA enabled for user {user_id}")
        
        return {
            "message": "MFA enabled successfully",
            "backup_codes": backup_codes,  # Only show once during setup
            "warning": "Save these backup codes in a secure location. They will not be shown again."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA enable failed for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="MFA enable failed")

async def disable_mfa(
    user_id: int,
    token: str,
    db: Session = Depends(get_db)
) -> dict:
    """Disable MFA for a user"""
    mfa_service = get_mfa_service()
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    try:
        # Get secret - it will be automatically decrypted by the hybrid property
        secret = user.mfa_secret
        
        # Verify token
        if not mfa_service.verify_token(secret, token):
            raise HTTPException(status_code=400, detail="Invalid token")
        
        # Disable MFA and clear secrets
        user.mfa_enabled = False
        user.mfa_secret = None
        user.backup_codes = None
        db.commit()
        
        logger.info(f"MFA disabled for user {user_id}")
        
        return {"message": "MFA disabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA disable failed for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="MFA disable failed")

async def verify_mfa_for_login(
    user: User,
    token: str,
    db: Session
) -> bool:
    """Verify MFA token for login (internal use)"""
    if not user.mfa_enabled:
        return True  # MFA not required
    
    if not user.mfa_secret:
        logger.warning(f"User {user.id} has MFA enabled but no secret")
        return False
    
    mfa_service = get_mfa_service()
    
    try:
        # Decrypt secret
        secret = mfa_service.decrypt_secret(user.mfa_secret)
        
        # Check TOTP token first
        if mfa_service.verify_token(secret, token):
            return True
        
        # Check backup code if TOTP fails
        if mfa_service.verify_backup_code(user, token, db):
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"MFA verification failed for user {user.id}: {e}")
        return False

async def generate_new_backup_codes(
    user_id: int,
    current_token: str,
    db: Session = Depends(get_db)
) -> dict:
    """Generate new backup codes for a user"""
    mfa_service = get_mfa_service()
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    
    try:
        # Verify current token/backup code
        if not await verify_mfa_for_login(user, current_token, db):
            raise HTTPException(status_code=400, detail="Invalid token")
        
        # Generate new backup codes
        backup_codes = mfa_service.generate_backup_codes()
        
        # Update user - will be automatically encrypted
        user.backup_codes = ','.join(backup_codes)
        db.commit()
        
        logger.info(f"New backup codes generated for user {user_id}")
        
        return {
            "message": "New backup codes generated successfully",
            "backup_codes": backup_codes,
            "warning": "These codes replace your previous backup codes. Save them securely."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup code generation failed for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Backup code generation failed")


# Alias for backward compatibility
verify_mfa = verify_mfa_for_login