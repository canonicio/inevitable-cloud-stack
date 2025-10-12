"""
Advanced Content Normalizer
Canonicalizes content to prevent bypass via encoding tricks
"""
import unicodedata
import re
import html
from typing import Tuple, List
import logging

logger = logging.getLogger(__name__)


class ContentNormalizer:
    """
    Normalizes content to prevent injection via encoding/formatting tricks.
    Handles Unicode, control characters, HTML, and other obfuscation methods.
    """
    
    # Control characters to remove (except common whitespace)
    CONTROL_CHARS = ''.join(
        chr(i) for i in range(32) if chr(i) not in '\t\n\r'
    ) + ''.join(chr(i) for i in range(127, 160))
    
    # Zero-width characters that can hide content
    ZERO_WIDTH_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\u2060',  # Word joiner
        '\ufeff',  # Zero-width no-break space
        '\u180e',  # Mongolian vowel separator
        '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',  # Various spaces
        '\u2005', '\u2006', '\u2007', '\u2008', '\u2009',
        '\u200a', '\u202f', '\u205f', '\u3000'
    ]
    
    def normalize(self, blob) -> str:
        """
        Main normalization pipeline.
        Updates blob.normalized_text and provenance.
        """
        text = blob.raw_text
        original_len = len(text)
        
        # Step 1: Unicode canonicalization (NFKC)
        text = self._canonicalize_unicode(text)
        
        # Step 2: Remove zero-width and control characters
        text = self._remove_hidden_chars(text)
        
        # Step 3: Clean HTML artifacts
        text = self._clean_html(text)
        
        # Step 4: Remove embedded scripts/macros
        text = self._remove_embedded_code(text)
        
        # Step 5: Normalize whitespace
        text = self._normalize_whitespace(text)
        
        # Step 6: Remove URL encoding
        text = self._decode_url_encoding(text)
        
        # Step 7: Remove base64 blocks (potential encoded commands)
        text, removed_b64 = self._remove_base64_blocks(text)
        
        # Update blob
        blob.normalized_text = text
        blob.add_provenance("normalize", "completed", {
            "original_length": original_len,
            "normalized_length": len(text),
            "removed_base64_blocks": len(removed_b64),
            "transformations": [
                "unicode_nfkc",
                "remove_hidden_chars",
                "clean_html",
                "remove_embedded_code",
                "normalize_whitespace",
                "decode_url",
                "remove_base64"
            ]
        })
        
        return text
    
    def _canonicalize_unicode(self, text: str) -> str:
        """Apply Unicode NFKC normalization."""
        try:
            return unicodedata.normalize('NFKC', text)
        except Exception as e:
            logger.warning(f"Unicode normalization failed: {e}")
            return text
    
    def _remove_hidden_chars(self, text: str) -> str:
        """Remove zero-width and control characters."""
        # Remove control characters
        text = text.translate(str.maketrans('', '', self.CONTROL_CHARS))
        
        # Remove zero-width characters
        for char in self.ZERO_WIDTH_CHARS:
            text = text.replace(char, '')
        
        return text
    
    def _clean_html(self, text: str) -> str:
        """Remove HTML comments and decode entities."""
        # Remove HTML comments
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
        
        # Remove script tags and content
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove style tags and content
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Remove remaining HTML tags (but keep content)
        text = re.sub(r'<[^>]+>', ' ', text)
        
        return text
    
    def _remove_embedded_code(self, text: str) -> str:
        """Remove embedded scripts, macros, and code blocks."""
        # Remove Office macro indicators
        text = re.sub(r'^\s*Sub\s+\w+\s*\(.*?\).*?End\s+Sub', '', text, 
                     flags=re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        # Remove VBA-style code
        text = re.sub(r'^\s*Private\s+Sub.*?End\s+Sub', '', text,
                     flags=re.MULTILINE | re.DOTALL | re.IGNORECASE)
        
        # Remove PowerShell scripts
        text = re.sub(r'\$\{.*?\}', '', text, flags=re.DOTALL)
        
        # Remove backtick command substitution
        text = re.sub(r'`[^`]+`', '[REMOVED_COMMAND]', text)
        
        # Remove $(command) substitution
        text = re.sub(r'\$\([^)]+\)', '[REMOVED_COMMAND]', text)
        
        return text
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize various whitespace to standard spaces."""
        # Replace multiple spaces with single space
        text = re.sub(r'\s+', ' ', text)
        
        # Replace multiple newlines with double newline
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Trim lines
        lines = [line.strip() for line in text.split('\n')]
        text = '\n'.join(lines)
        
        return text.strip()
    
    def _decode_url_encoding(self, text: str) -> str:
        """Decode URL-encoded content."""
        import urllib.parse
        
        # Find and decode URL-encoded sections
        def decode_match(match):
            try:
                return urllib.parse.unquote(match.group(0))
            except:
                return match.group(0)
        
        # Decode %XX patterns
        text = re.sub(r'(?:%[0-9a-fA-F]{2})+', decode_match, text)
        
        return text
    
    def _remove_base64_blocks(self, text: str) -> Tuple[str, List[str]]:
        """
        Remove suspicious base64 blocks that might encode commands.
        Returns cleaned text and list of removed blocks.
        """
        removed = []
        
        # Pattern for base64 blocks (min 20 chars to avoid false positives)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        
        def check_and_remove(match):
            b64_str = match.group(0)
            # Try to decode and check for suspicious content
            try:
                import base64
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                
                # Check for command patterns in decoded content
                suspicious_patterns = [
                    r'(system|exec|eval|import|require|include)',
                    r'(cmd|powershell|bash|sh)\s',
                    r'(SELECT|INSERT|DELETE|DROP|UPDATE)\s',
                    r'<script',
                    r'tool\s*:\s*',
                    r'(fs\.|web\.|api\.)'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        removed.append(b64_str)
                        return '[REMOVED_BASE64]'
                
                # If not suspicious, keep it
                return b64_str
                
            except:
                # If can't decode, keep it (might be legitimate data)
                return b64_str
        
        text = re.sub(b64_pattern, check_and_remove, text)
        
        return text, removed


class URLNormalizer:
    """Specialized normalizer for URLs to detect parameter stuffing."""
    
    @staticmethod
    def normalize_url(url: str) -> Tuple[str, List[str]]:
        """
        Normalize URL and extract suspicious parameters.
        Returns cleaned URL and list of suspicious params.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        suspicious_params = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Check each parameter for injection attempts
            clean_params = {}
            suspicious_keywords = [
                'ignore', 'system', 'prompt', 'instruction',
                'override', 'bypass', 'admin', 'root',
                'exec', 'eval', 'import'
            ]
            
            for key, values in params.items():
                # Check parameter name
                if any(keyword in key.lower() for keyword in suspicious_keywords):
                    suspicious_params.append(f"{key}={values}")
                    continue
                
                # Check parameter values
                clean_values = []
                for value in values:
                    if any(keyword in value.lower() for keyword in suspicious_keywords):
                        suspicious_params.append(f"{key}={value}")
                    else:
                        clean_values.append(value)
                
                if clean_values:
                    clean_params[key] = clean_values
            
            # Rebuild URL with clean parameters
            clean_query = urlencode(clean_params, doseq=True)
            clean_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                clean_query,
                parsed.fragment
            ))
            
            return clean_url, suspicious_params
            
        except Exception as e:
            logger.warning(f"URL normalization failed: {e}")
            return url, []


# Global normalizer instance
normalizer = ContentNormalizer()
url_normalizer = URLNormalizer()