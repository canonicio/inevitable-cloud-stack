"""
Content Sanitizer - Neutralizes dangerous content while preserving information
Converts imperatives to neutral statements and wraps as data
"""
import re
import logging
from typing import List, Tuple, Dict, Any

logger = logging.getLogger(__name__)


class ContentSanitizer:
    """
    Sanitizes content by neutralizing instructions while preserving information.
    Converts imperatives to third-person statements and wraps as data.
    """
    
    # Imperative patterns to neutralize
    IMPERATIVE_PATTERNS = [
        # Direct commands
        (r"^(ignore|disregard|forget)\s+", "The user wrote about ignoring "),
        (r"^(execute|run|perform)\s+", "The user mentioned executing "),
        (r"^(call|invoke|trigger)\s+", "The user referenced calling "),
        (r"^(print|output|display)\s+", "The user requested displaying "),
        (r"^(list|show|reveal)\s+", "The user asked about listing "),
        
        # Role changes
        (r"^you\s+are\s+", "The user suggested the system is "),
        (r"^act\s+as\s+", "The user proposed acting as "),
        (r"^pretend\s+", "The user mentioned pretending "),
        (r"^become\s+", "The user referenced becoming "),
        
        # System directives
        (r"^system:\s*", "The user wrote a system-like message: "),
        (r"^instruction:\s*", "The user provided text labeled as instruction: "),
        (r"^command:\s*", "The user wrote a command-like message: "),
    ]
    
    def sanitize(self, blob) -> str:
        """
        Main sanitization pipeline.
        Updates blob.sanitized_text and returns wrapped content.
        """
        text = blob.normalized_text
        
        # Step 1: Neutralize imperatives
        text = self._neutralize_imperatives(text)
        
        # Step 2: Escape special tokens
        text = self._escape_special_tokens(text)
        
        # Step 3: Apply tenant-specific redactions
        text = self._apply_redactions(text, blob.tenant_id)
        
        # Step 4: Chunk by semantics
        chunks = self._create_semantic_chunks(text)
        blob.chunk_ids = [blob.generate_chunk_id(chunk) for chunk in chunks]
        
        # Update blob
        blob.sanitized_text = text
        
        # Add to provenance
        blob.add_provenance("sanitize", "completed", {
            "imperatives_neutralized": True,
            "tokens_escaped": True,
            "chunks_created": len(blob.chunk_ids)
        })
        
        # Step 5: Wrap as data
        wrapped = self._wrap_as_data(blob)
        
        return wrapped
    
    def _neutralize_imperatives(self, text: str) -> str:
        """Convert imperatives to neutral third-person statements."""
        lines = text.split('\n')
        neutralized_lines = []
        
        for line in lines:
            line_lower = line.lower().strip()
            neutralized = line
            
            # Check each imperative pattern
            for pattern, replacement in self.IMPERATIVE_PATTERNS:
                if re.match(pattern, line_lower):
                    # Replace with neutral statement
                    neutralized = re.sub(
                        pattern,
                        replacement,
                        line,
                        flags=re.IGNORECASE
                    )
                    break
            
            # Additional neutralization for "you" statements
            if "you are" in line_lower and not line_lower.startswith("the user"):
                neutralized = line.replace("you are", "the system is described as")
                neutralized = neutralized.replace("You are", "The system is described as")
            
            neutralized_lines.append(neutralized)
        
        return '\n'.join(neutralized_lines)
    
    def _escape_special_tokens(self, text: str) -> str:
        """Escape tokens that might be interpreted as control sequences."""
        # Escape angle brackets that might be interpreted as XML/HTML
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        
        # Escape potential template variables
        text = re.sub(r'\{\{([^}]+)\}\}', r'[[TEMPLATE:\1]]', text)
        text = re.sub(r'\${([^}]+)}', r'[VAR:\1]', text)
        
        # Escape backticks
        text = text.replace('`', '&#96;')
        
        return text
    
    def _apply_redactions(self, text: str, tenant_id: str) -> str:
        """Apply tenant-specific redaction rules."""
        # In production, would load tenant-specific rules from database
        # For now, apply common redactions
        
        # Redact potential secrets
        text = re.sub(
            r'\b([A-Z0-9]{20,})\b',  # Long alphanumeric strings
            '[REDACTED_TOKEN]',
            text
        )
        
        # Redact email addresses
        text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[REDACTED_EMAIL]',
            text
        )
        
        # Redact IP addresses
        text = re.sub(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            '[REDACTED_IP]',
            text
        )
        
        return text
    
    def _create_semantic_chunks(self, text: str, max_chunk_size: int = 500) -> List[str]:
        """Split text into semantic chunks for processing."""
        chunks = []
        
        # Split by paragraphs first
        paragraphs = text.split('\n\n')
        
        current_chunk = []
        current_size = 0
        
        for para in paragraphs:
            para_size = len(para)
            
            if current_size + para_size > max_chunk_size and current_chunk:
                # Save current chunk
                chunks.append('\n\n'.join(current_chunk))
                current_chunk = [para]
                current_size = para_size
            else:
                current_chunk.append(para)
                current_size += para_size
        
        # Add remaining chunk
        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))
        
        # If no chunks created, treat entire text as one chunk
        if not chunks:
            chunks = [text]
        
        return chunks
    
    def _wrap_as_data(self, blob) -> str:
        """Wrap sanitized content as data with metadata."""
        return f"""<DATA origin="{blob.source}" scope="text" role="user_intent" trust="{blob.trust['score']:.2f}">
{blob.sanitized_text}
</DATA>"""


class TenantRedactionRules:
    """Manages tenant-specific redaction rules."""
    
    def __init__(self):
        self.rules = {}
    
    def add_rule(self, tenant_id: str, pattern: str, replacement: str):
        """Add a redaction rule for a tenant."""
        if tenant_id not in self.rules:
            self.rules[tenant_id] = []
        
        self.rules[tenant_id].append({
            "pattern": re.compile(pattern, re.IGNORECASE),
            "replacement": replacement
        })
    
    def apply_rules(self, text: str, tenant_id: str) -> str:
        """Apply tenant-specific redaction rules."""
        if tenant_id not in self.rules:
            return text
        
        for rule in self.rules[tenant_id]:
            text = rule["pattern"].sub(rule["replacement"], text)
        
        return text


class SafeRewriter:
    """
    Rewrites content to extract facts and requirements safely.
    Used for advanced content transformation.
    """
    
    def rewrite_as_structured(self, text: str) -> Dict[str, List[str]]:
        """
        Rewrite content as structured facts and requirements.
        This is a simplified version - in production would use LLM.
        """
        facts = []
        requirements = []
        questions = []
        
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Classify line type
            if any(word in line.lower() for word in ['is', 'are', 'was', 'were', 'has', 'have']):
                facts.append(line)
            elif any(word in line.lower() for word in ['need', 'require', 'must', 'should']):
                requirements.append(line)
            elif '?' in line:
                questions.append(line)
            else:
                # Default to fact
                facts.append(line)
        
        return {
            "facts": facts,
            "requirements": requirements,
            "open_questions": questions
        }


# Global instances
sanitizer = ContentSanitizer()
tenant_rules = TenantRedactionRules()
safe_rewriter = SafeRewriter()