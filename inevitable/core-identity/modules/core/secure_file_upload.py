"""
Secure File Upload System
Addresses MEDIUM-001: File Upload Security Vulnerabilities
"""
import os
import magic
import hashlib
import tempfile
import logging
import shutil
from typing import List, Dict, Optional, Tuple, BinaryIO, Union
from pathlib import Path
from datetime import datetime, timedelta
from fastapi import UploadFile, HTTPException, status, Depends
from pydantic import BaseModel, Field
import uuid
import mimetypes

from modules.core.config import settings
from modules.core.enhanced_validators import APIParameterValidator

logger = logging.getLogger(__name__)


class FileUploadError(Exception):
    """Custom file upload error"""
    pass


class UploadConfig(BaseModel):
    """File upload configuration"""
    max_file_size: int = Field(default=10*1024*1024, description="Maximum file size in bytes")
    allowed_extensions: List[str] = Field(default=[
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt', '.csv', '.json', '.xml'
    ])
    allowed_mime_types: List[str] = Field(default=[
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf',
        'text/plain', 'text/csv', 'application/json', 'application/xml', 'text/xml'
    ])
    scan_for_malware: bool = Field(default=True)
    quarantine_suspicious: bool = Field(default=True)
    check_content_headers: bool = Field(default=True)


class SecureFileUpload:
    """
    Secure file upload handler with comprehensive security measures.
    MEDIUM FIX: Complete file upload security implementation
    """
    
    # MEDIUM FIX: Dangerous file extensions and MIME types
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs', '.js', '.jar',
        '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.py', '.rb', '.pl',
        '.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.svg', '.swf',
        '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi', '.apk', '.ipa',
        '.dll', '.so', '.dylib', '.bin'
    }
    
    DANGEROUS_MIME_TYPES = {
        'application/x-executable', 'application/x-msdos-program', 'application/x-msdownload',
        'application/x-bat', 'application/x-sh', 'application/javascript', 'text/javascript',
        'application/x-php', 'text/x-php', 'application/x-httpd-php', 'text/html',
        'application/x-shockwave-flash', 'application/vnd.android.package-archive'
    }
    
    # MEDIUM FIX: Magic number signatures for file type verification
    MAGIC_SIGNATURES = {
        'image/jpeg': [b'\xFF\xD8\xFF'],
        'image/png': [b'\x89PNG\r\n\x1A\n'],
        'image/gif': [b'GIF87a', b'GIF89a'],
        'image/webp': [b'RIFF', b'WEBP'],
        'application/pdf': [b'%PDF-'],
        'application/zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
        'text/plain': [],  # No magic signature needed
        'text/csv': [],    # No magic signature needed
        'application/json': [],  # No magic signature needed
        'application/xml': [b'<?xml'],
        'text/xml': [b'<?xml']
    }
    
    def __init__(self, config: Optional[UploadConfig] = None):
        """Initialize secure file upload handler"""
        self.config = config or UploadConfig()
        self.temp_dir = Path(tempfile.gettempdir()) / "platform_forge_uploads"
        self.quarantine_dir = self.temp_dir / "quarantine"
        
        # Create directories
        self.temp_dir.mkdir(exist_ok=True)
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # Setup libmagic if available
        self.magic_mime = self._setup_magic()
    
    def _setup_magic(self):
        """Setup libmagic for MIME type detection"""
        try:
            return magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"libmagic not available, using fallback MIME detection: {e}")
            return None
    
    async def validate_and_process_upload(
        self,
        file: UploadFile,
        allowed_types: Optional[List[str]] = None,
        max_size: Optional[int] = None
    ) -> Dict[str, any]:
        """
        MEDIUM FIX: Comprehensive file upload validation and processing
        
        Args:
            file: FastAPI UploadFile object
            allowed_types: Override allowed MIME types
            max_size: Override maximum file size
        
        Returns:
            Dict with file information and secure path
        """
        # Use provided limits or defaults
        max_file_size = max_size or self.config.max_file_size
        allowed_mime_types = allowed_types or self.config.allowed_mime_types
        
        # Basic file validation
        if not file.filename:
            raise FileUploadError("Filename is required")
        
        # Validate filename
        self._validate_filename(file.filename)
        
        # Check file size
        file_size = 0
        content_chunks = []
        
        # Read file content in chunks to check size
        chunk_size = 8192
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            
            file_size += len(chunk)
            if file_size > max_file_size:
                raise FileUploadError(f"File too large: {file_size} bytes (max {max_file_size})")
            
            content_chunks.append(chunk)
        
        # Combine chunks
        file_content = b''.join(content_chunks)
        
        # Reset file pointer for potential re-reading
        await file.seek(0)
        
        # Validate file content
        validation_result = await self._validate_file_content(
            file_content, file.filename, file.content_type, allowed_mime_types
        )
        
        # Generate secure filename and path
        secure_info = self._generate_secure_path(file.filename, validation_result['detected_mime'])
        
        # Save file securely
        saved_path = await self._save_file_securely(file_content, secure_info['secure_path'])
        
        # Perform security scans
        scan_results = await self._perform_security_scans(saved_path, file_content)
        
        if scan_results['quarantine']:
            # Move to quarantine
            quarantine_path = self.quarantine_dir / secure_info['secure_filename']
            shutil.move(saved_path, quarantine_path)
            
            logger.warning(
                f"File quarantined: {file.filename} -> {quarantine_path}, "
                f"Reason: {scan_results['reason']}"
            )
            
            raise FileUploadError(f"File failed security scan: {scan_results['reason']}")
        
        # Return file information
        return {
            "original_filename": file.filename,
            "secure_filename": secure_info['secure_filename'],
            "secure_path": str(saved_path),
            "file_size": file_size,
            "mime_type": validation_result['detected_mime'],
            "file_hash": validation_result['file_hash'],
            "upload_id": secure_info['upload_id'],
            "expires_at": secure_info['expires_at'],
            "validation_results": validation_result,
            "scan_results": scan_results
        }
    
    def _validate_filename(self, filename: str):
        """MEDIUM FIX: Comprehensive filename validation"""
        # Basic validation
        if not filename or len(filename) > 255:
            raise FileUploadError("Invalid filename length")
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise FileUploadError("Filename contains invalid path characters")
        
        # Check for dangerous extensions
        file_ext = Path(filename).suffix.lower()
        if file_ext in self.DANGEROUS_EXTENSIONS:
            raise FileUploadError(f"File extension '{file_ext}' is not allowed")
        
        # Check if extension is in allowed list
        if file_ext not in self.config.allowed_extensions:
            raise FileUploadError(f"File extension '{file_ext}' is not allowed")
        
        # Validate against injection patterns
        try:
            APIParameterValidator.validate_no_injection(filename, "filename")
        except Exception as e:
            raise FileUploadError(f"Filename contains dangerous patterns: {str(e)}")
        
        # Check for null bytes and control characters
        if '\x00' in filename or any(ord(c) < 32 for c in filename if c not in '\t\n\r'):
            raise FileUploadError("Filename contains control characters")
    
    async def _validate_file_content(
        self,
        content: bytes,
        filename: str,
        declared_mime: str,
        allowed_mimes: List[str]
    ) -> Dict[str, any]:
        """MEDIUM FIX: Comprehensive file content validation"""
        validation_results = {
            "declared_mime": declared_mime,
            "detected_mime": None,
            "file_hash": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "headers_valid": True,
            "content_matches_extension": True,
            "magic_signature_valid": True
        }
        
        # Check for empty files
        if len(content) == 0:
            raise FileUploadError("Empty files are not allowed")
        
        # Detect actual MIME type
        detected_mime = self._detect_mime_type(content, filename)
        validation_results["detected_mime"] = detected_mime
        
        # Verify MIME type is allowed
        if detected_mime not in allowed_mimes:
            raise FileUploadError(f"File type '{detected_mime}' is not allowed")
        
        # Check for dangerous MIME types
        if detected_mime in self.DANGEROUS_MIME_TYPES:
            raise FileUploadError(f"Dangerous file type detected: {detected_mime}")
        
        # Verify MIME type matches extension
        file_ext = Path(filename).suffix.lower()
        if not self._mime_matches_extension(detected_mime, file_ext):
            validation_results["content_matches_extension"] = False
            raise FileUploadError("File content doesn't match extension")
        
        # Verify declared MIME type matches detected
        if declared_mime and declared_mime != detected_mime:
            logger.warning(
                f"MIME type mismatch: declared='{declared_mime}', "
                f"detected='{detected_mime}', file='{filename}'"
            )
            # Allow but log - some browsers send incorrect MIME types
        
        # Validate magic signatures
        if not self._validate_magic_signature(content, detected_mime):
            validation_results["magic_signature_valid"] = False
            raise FileUploadError("File signature validation failed")
        
        # Check for embedded content
        await self._check_embedded_content(content, detected_mime)
        
        return validation_results
    
    def _detect_mime_type(self, content: bytes, filename: str) -> str:
        """Detect MIME type using multiple methods"""
        # Method 1: Use libmagic if available
        if self.magic_mime:
            try:
                detected = self.magic_mime.from_buffer(content)
                if detected:
                    return detected
            except Exception as e:
                logger.warning(f"libmagic detection failed: {e}")
        
        # Method 2: Use Python's mimetypes based on extension
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type:
            return mime_type
        
        # Method 3: Fallback based on file signature
        return self._detect_by_signature(content)
    
    def _detect_by_signature(self, content: bytes) -> str:
        """Detect file type by magic signature"""
        if not content:
            return 'application/octet-stream'
        
        # Check known signatures
        for mime_type, signatures in self.MAGIC_SIGNATURES.items():
            for signature in signatures:
                if content.startswith(signature):
                    return mime_type
        
        # Check for text content
        try:
            content.decode('utf-8')
            return 'text/plain'
        except UnicodeDecodeError:
            pass
        
        return 'application/octet-stream'
    
    def _mime_matches_extension(self, mime_type: str, extension: str) -> bool:
        """Check if MIME type matches file extension"""
        expected_extensions = {
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/gif': ['.gif'],
            'image/webp': ['.webp'],
            'application/pdf': ['.pdf'],
            'text/plain': ['.txt'],
            'text/csv': ['.csv'],
            'application/json': ['.json'],
            'application/xml': ['.xml'],
            'text/xml': ['.xml']
        }
        
        if mime_type in expected_extensions:
            return extension in expected_extensions[mime_type]
        
        return True  # Allow unknown types
    
    def _validate_magic_signature(self, content: bytes, mime_type: str) -> bool:
        """Validate file magic signature"""
        if mime_type not in self.MAGIC_SIGNATURES:
            return True  # No signature to check
        
        signatures = self.MAGIC_SIGNATURES[mime_type]
        if not signatures:  # No signature required
            return True
        
        # Check if content starts with any valid signature
        for signature in signatures:
            if content.startswith(signature):
                return True
        
        return False
    
    async def _check_embedded_content(self, content: bytes, mime_type: str):
        """MEDIUM FIX: Check for embedded malicious content"""
        # Check for script tags in any content
        content_str = content.decode('utf-8', errors='ignore').lower()
        
        dangerous_patterns = [
            b'<script', b'javascript:', b'vbscript:', b'onload=', b'onerror=',
            b'eval(', b'document.write', b'innerHTML', b'<iframe',
            b'<object', b'<embed', b'<form', b'<meta http-equiv'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in content:
                raise FileUploadError("File contains potentially dangerous embedded content")
        
        # Type-specific checks
        if mime_type.startswith('image/'):
            await self._check_image_metadata(content)
        elif mime_type == 'application/pdf':
            await self._check_pdf_content(content)
        elif mime_type.startswith('text/'):
            await self._check_text_content(content)
    
    async def _check_image_metadata(self, content: bytes):
        """Check image metadata for dangerous content"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            import io
            
            with Image.open(io.BytesIO(content)) as img:
                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        if isinstance(value, str):
                            # Check for scripts in EXIF data
                            value_lower = value.lower()
                            if any(dangerous in value_lower for dangerous in ['script', 'javascript', 'eval']):
                                raise FileUploadError("Image contains dangerous EXIF data")
        except ImportError:
            logger.warning("PIL not available for image metadata checking")
        except Exception as e:
            logger.warning(f"Image metadata check failed: {e}")
    
    async def _check_pdf_content(self, content: bytes):
        """Check PDF content for dangerous elements"""
        content_str = content.decode('utf-8', errors='ignore').lower()
        
        dangerous_pdf_patterns = [
            'javascript', 'action', 'openaction', 'aa', 'launch',
            'importdatasimport', 'exportvalues', 'submitform'
        ]
        
        for pattern in dangerous_pdf_patterns:
            if pattern in content_str:
                logger.warning(f"PDF contains potentially dangerous content: {pattern}")
                # Don't reject, but log for monitoring
    
    async def _check_text_content(self, content: bytes):
        """Check text content for dangerous patterns"""
        try:
            content_str = content.decode('utf-8')
            # Already checked in _check_embedded_content
        except UnicodeDecodeError:
            # Binary data in text file
            raise FileUploadError("Text file contains binary data")
    
    def _generate_secure_path(self, original_filename: str, mime_type: str) -> Dict[str, any]:
        """Generate secure file path and metadata"""
        # Generate unique upload ID
        upload_id = str(uuid.uuid4())
        
        # Get file extension
        original_ext = Path(original_filename).suffix.lower()
        
        # Generate secure filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        secure_filename = f"{upload_id}_{timestamp}{original_ext}"
        
        # Create secure path
        secure_path = self.temp_dir / secure_filename
        
        # Set expiration (24 hours from now)
        expires_at = datetime.now() + timedelta(hours=24)
        
        return {
            "upload_id": upload_id,
            "secure_filename": secure_filename,
            "secure_path": secure_path,
            "expires_at": expires_at.isoformat()
        }
    
    async def _save_file_securely(self, content: bytes, path: Path) -> Path:
        """Save file with secure permissions"""
        try:
            # Write file with restrictive permissions
            with open(path, 'wb') as f:
                f.write(content)
            
            # Set secure permissions (owner read/write only)
            os.chmod(path, 0o600)
            
            logger.info(f"File saved securely: {path}")
            return path
            
        except Exception as e:
            logger.error(f"Failed to save file securely: {e}")
            # Cleanup on failure
            if path.exists():
                path.unlink()
            raise FileUploadError(f"Failed to save file: {str(e)}")
    
    async def _perform_security_scans(self, file_path: Path, content: bytes) -> Dict[str, any]:
        """MEDIUM FIX: Perform security scans on uploaded file"""
        scan_results = {
            "quarantine": False,
            "reason": None,
            "virus_scan": "not_available",
            "entropy_check": "pass",
            "size_anomaly": "pass"
        }
        
        # Entropy check (detect encrypted/packed files)
        entropy = self._calculate_entropy(content)
        if entropy > 7.5:  # High entropy might indicate encryption/packing
            scan_results["entropy_check"] = "high_entropy"
            logger.warning(f"High entropy detected: {entropy}")
        
        # Size anomaly check
        if len(content) > 100*1024*1024:  # 100MB
            scan_results["size_anomaly"] = "very_large"
        
        # Basic malware patterns (very simple)
        if self._contains_malware_patterns(content):
            scan_results["quarantine"] = True
            scan_results["reason"] = "Malware patterns detected"
        
        return scan_results
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count frequency of each byte
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _contains_malware_patterns(self, content: bytes) -> bool:
        """Basic malware pattern detection"""
        malware_patterns = [
            # Common malware signatures
            b'This program cannot be run in DOS mode',
            b'WinExec', b'CreateProcess', b'RegSetValue',
            b'GetProcAddress', b'LoadLibrary',
            # Script patterns
            b'eval(', b'document.write(', b'createElement(',
            # Suspicious URLs
            b'http://bit.ly/', b'http://tinyurl.com/',
        ]
        
        content_lower = content.lower()
        for pattern in malware_patterns:
            if pattern.lower() in content_lower:
                return True
        
        return False
    
    def cleanup_expired_files(self):
        """Clean up expired uploaded files"""
        try:
            current_time = datetime.now()
            
            for file_path in self.temp_dir.glob("*"):
                if file_path.is_file():
                    # Check if file is older than 24 hours
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if current_time - file_time > timedelta(hours=24):
                        file_path.unlink()
                        logger.info(f"Cleaned up expired file: {file_path}")
                        
        except Exception as e:
            logger.error(f"Failed to cleanup expired files: {e}")


# Global instance
_secure_upload_handler = None


def get_secure_upload_handler(config: Optional[UploadConfig] = None) -> SecureFileUpload:
    """Get global secure upload handler instance"""
    global _secure_upload_handler
    if _secure_upload_handler is None:
        _secure_upload_handler = SecureFileUpload(config)
    return _secure_upload_handler


# MEDIUM FIX: Dependency for secure file upload
async def secure_file_upload_dependency(
    file: UploadFile,
    allowed_types: Optional[List[str]] = None,
    max_size: Optional[int] = None
) -> Dict[str, any]:
    """
    FastAPI dependency for secure file upload validation
    """
    handler = get_secure_upload_handler()
    
    try:
        result = await handler.validate_and_process_upload(
            file=file,
            allowed_types=allowed_types,
            max_size=max_size
        )
        return result
        
    except FileUploadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Secure file upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File upload processing failed"
        )


# MEDIUM FIX: Convenience functions for specific file types
async def secure_image_upload(file: UploadFile) -> Dict[str, any]:
    """Secure image upload with image-specific validation"""
    image_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']
    return await secure_file_upload_dependency(file, allowed_types=image_types)


async def secure_document_upload(file: UploadFile) -> Dict[str, any]:
    """Secure document upload with document-specific validation"""
    document_types = ['application/pdf', 'text/plain', 'text/csv', 'application/json']
    return await secure_file_upload_dependency(file, allowed_types=document_types)


async def secure_data_upload(file: UploadFile) -> Dict[str, any]:
    """Secure data file upload with size limits"""
    data_types = ['text/csv', 'application/json', 'application/xml', 'text/xml']
    max_data_size = 50 * 1024 * 1024  # 50MB for data files
    return await secure_file_upload_dependency(file, allowed_types=data_types, max_size=max_data_size)