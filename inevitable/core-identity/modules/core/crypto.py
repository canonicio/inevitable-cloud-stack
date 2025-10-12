"""
Enhanced cryptographic operations for Platform Forge
Fixes HIGH: Cryptographic weaknesses
"""
import os
import base64
import secrets
import hashlib
from typing import Optional, Tuple, Dict, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import logging

from .secure_config import settings

logger = logging.getLogger(__name__)

class CryptoError(Exception):
    """Base exception for cryptographic errors"""
    pass

class EnhancedCrypto:
    """
    Enhanced cryptographic operations with tenant isolation
    and modern encryption standards
    """
    
    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is None:
            master_key = settings.PLATFORM_FORGE_MASTER_KEY.encode()
        
        if len(master_key) < 32:
            raise CryptoError("Master key must be at least 32 bytes")
        
        self.master_key = master_key
        self._tenant_ciphers: Dict[str, Fernet] = {}
        self._tenant_aes_keys: Dict[str, bytes] = {}
    
    def get_tenant_cipher(self, tenant_id: str) -> Fernet:
        """Get or create tenant-specific Fernet cipher"""
        if tenant_id not in self._tenant_ciphers:
            # Derive tenant-specific key using Scrypt (memory-hard)
            kdf = Scrypt(
                salt=f"tenant_{tenant_id}_fernet_v1".encode(),
                length=32,
                n=2**14,  # CPU/memory cost
                r=8,      # Block size
                p=1,      # Parallelization
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
            self._tenant_ciphers[tenant_id] = Fernet(key)
        
        return self._tenant_ciphers[tenant_id]
    
    def get_tenant_aes_key(self, tenant_id: str) -> bytes:
        """Get tenant-specific AES key for AEAD encryption"""
        if tenant_id not in self._tenant_aes_keys:
            # Derive AES key
            kdf = Scrypt(
                salt=f"tenant_{tenant_id}_aes_v1".encode(),
                length=32,  # 256-bit key
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
            self._tenant_aes_keys[tenant_id] = kdf.derive(self.master_key)
        
        return self._tenant_aes_keys[tenant_id]
    
    def encrypt_field(self, data: str, tenant_id: str, use_aead: bool = False) -> str:
        """
        Encrypt data with tenant-specific key
        
        Args:
            data: Plain text to encrypt
            tenant_id: Tenant identifier
            use_aead: Use AES-GCM for authenticated encryption
        
        Returns:
            Base64-encoded encrypted data
        """
        if not data:
            return ""
        
        try:
            if use_aead:
                return self._encrypt_aead(data.encode(), tenant_id)
            else:
                return self._encrypt_fernet(data, tenant_id)
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise CryptoError("Encryption failed")
    
    def _encrypt_fernet(self, data: str, tenant_id: str) -> str:
        """Encrypt using Fernet (symmetric encryption)"""
        cipher = self.get_tenant_cipher(tenant_id)
        
        # Add random nonce to prevent deterministic encryption
        nonce = secrets.token_bytes(16)
        payload = nonce + data.encode()
        
        encrypted = cipher.encrypt(payload)
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def _encrypt_aead(self, data: bytes, tenant_id: str) -> str:
        """Encrypt using AES-GCM (authenticated encryption)"""
        key = self.get_tenant_aes_key(tenant_id)
        
        # Generate random nonce (96 bits for GCM)
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        aesgcm = AESGCM(key)
        
        # Add associated data for authentication
        associated_data = f"tenant:{tenant_id}".encode()
        
        # Encrypt
        ciphertext = aesgcm.encrypt(nonce, data, associated_data)
        
        # Combine nonce and ciphertext
        encrypted_data = nonce + ciphertext
        
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_field(self, encrypted_data: str, tenant_id: str, use_aead: bool = False) -> str:
        """
        Decrypt data with tenant-specific key
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            tenant_id: Tenant identifier
            use_aead: Use AES-GCM for authenticated decryption
        
        Returns:
            Decrypted plain text
        """
        if not encrypted_data:
            return ""
        
        try:
            if use_aead:
                return self._decrypt_aead(encrypted_data, tenant_id).decode()
            else:
                return self._decrypt_fernet(encrypted_data, tenant_id)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise CryptoError("Decryption failed")
    
    def _decrypt_fernet(self, encrypted_data: str, tenant_id: str) -> str:
        """Decrypt using Fernet"""
        cipher = self.get_tenant_cipher(tenant_id)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        
        decrypted = cipher.decrypt(encrypted_bytes)
        
        # Remove nonce (first 16 bytes)
        return decrypted[16:].decode()
    
    def _decrypt_aead(self, encrypted_data: str, tenant_id: str) -> bytes:
        """Decrypt using AES-GCM"""
        key = self.get_tenant_aes_key(tenant_id)
        
        # Decode from base64
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        
        # Extract nonce and ciphertext
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        
        # Create cipher
        aesgcm = AESGCM(key)
        
        # Add associated data for authentication
        associated_data = f"tenant:{tenant_id}".encode()
        
        # Decrypt
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """Constant time string comparison to prevent timing attacks"""
        return secrets.compare_digest(val1, val2)
    
    @staticmethod
    def hash_password_argon2(password: str) -> str:
        """Hash password using Argon2 (recommended by OWASP)"""
        # Using passlib for Argon2
        from passlib.hash import argon2
        return argon2.hash(password)
    
    @staticmethod
    def verify_password_argon2(password: str, hash: str) -> bool:
        """Verify Argon2 password hash"""
        from passlib.hash import argon2
        return argon2.verify(password, hash)

class MFAEncryption:
    """Specialized encryption for MFA secrets with additional security"""
    
    def __init__(self, crypto: EnhancedCrypto):
        self.crypto = crypto
    
    def encrypt_mfa_secret(self, secret: str, user_id: int, tenant_id: str) -> str:
        """
        Encrypt MFA secret with user-specific context
        Uses AEAD for authenticated encryption
        """
        # Create structured data with user context
        data = {
            "user_id": str(user_id),
            "secret": secret,
            "version": "1.0"
        }
        
        # Serialize to JSON
        import json
        json_data = json.dumps(data)
        
        # Encrypt with AEAD
        return self.crypto.encrypt_field(json_data, tenant_id, use_aead=True)
    
    def decrypt_mfa_secret(self, encrypted: str, user_id: int, tenant_id: str) -> str:
        """Decrypt and validate MFA secret"""
        # Decrypt
        json_data = self.crypto.decrypt_field(encrypted, tenant_id, use_aead=True)
        
        # Parse and validate
        import json
        data = json.loads(json_data)
        
        # Validate user ID matches
        if data.get("user_id") != str(user_id):
            raise CryptoError("MFA secret validation failed")
        
        return data["secret"]
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate secure backup codes"""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """Hash backup code for storage"""
        # Remove formatting
        clean_code = code.replace("-", "")
        
        # Use scrypt for hashing (resistant to GPU attacks)
        salt = secrets.token_bytes(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        hash_bytes = kdf.derive(clean_code.encode())
        
        # Return salt + hash
        return base64.b64encode(salt + hash_bytes).decode()
    
    def verify_backup_code(self, code: str, stored_hash: str) -> bool:
        """Verify backup code against stored hash"""
        # Remove formatting
        clean_code = code.replace("-", "")
        
        # Decode stored hash
        stored_bytes = base64.b64decode(stored_hash.encode())
        salt = stored_bytes[:16]
        expected_hash = stored_bytes[16:]
        
        # Derive hash from provided code
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        
        try:
            derived_hash = kdf.derive(clean_code.encode())
            return secrets.compare_digest(derived_hash, expected_hash)
        except Exception:
            return False

class KeyDerivation:
    """Advanced key derivation functions"""
    
    @staticmethod
    def derive_encryption_key(
        master_key: bytes,
        context: str,
        key_length: int = 32
    ) -> bytes:
        """
        Derive an encryption key from master key with context
        
        Args:
            master_key: Master key material
            context: Key derivation context (e.g., "user_123_encryption")
            key_length: Desired key length in bytes
        
        Returns:
            Derived key material
        """
        # Use HKDF for key derivation
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=b"platform_forge_v1",
            info=context.encode(),
            backend=default_backend()
        )
        
        return hkdf.derive(master_key)
    
    @staticmethod
    def generate_key_pair():
        """Generate an asymmetric key pair for future use"""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

# Global crypto instance
_crypto_instance: Optional[EnhancedCrypto] = None

def get_crypto() -> EnhancedCrypto:
    """Get global crypto instance"""
    global _crypto_instance
    if _crypto_instance is None:
        _crypto_instance = EnhancedCrypto()
    return _crypto_instance

# Export commonly used functions
crypto = get_crypto()
mfa_crypto = MFAEncryption(crypto)

# Standalone functions for backward compatibility
def encrypt_data(data: str, tenant_id: str) -> str:
    """Encrypt data using tenant-specific key"""
    return crypto.encrypt_field(data, tenant_id)

def decrypt_data(encrypted_data: str, tenant_id: str) -> str:
    """Decrypt data using tenant-specific key"""
    return crypto.decrypt_field(encrypted_data, tenant_id)