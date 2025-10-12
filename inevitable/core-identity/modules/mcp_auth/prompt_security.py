"""
Prompt Injection Protection for MCP Service
Protects against prompt injection attacks in Model Context Protocol
"""
import re
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat levels for prompt injection detection"""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented
    
    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented
    
    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented
    
    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class PromptSecurityValidator:
    """
    Validates and sanitizes prompts to prevent injection attacks.
    Implements defense-in-depth against prompt injection.
    """
    
    # Known injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction override attempts
        r"ignore\s+(all\s+)?(previous|above|prior|existing)\s*(instructions?|prompts?|rules?|commands?)",
        r"disregard\s+(all\s+)?(previous|above|prior|existing)\s*(instructions?|prompts?|rules?|commands?)",
        r"forget\s+(everything|all|previous)",
        r"new\s+instructions?:",
        r"system\s*:\s*",
        r"assistant\s*:\s*",
        
        # Role manipulation attempts
        r"you\s+are\s+(now|a|an)\s+",
        r"act\s+as\s+(a|an|if)",
        r"pretend\s+(to\s+be|you\s+are)",
        r"roleplay\s+as",
        r"from\s+now\s+on",
        
        # Output manipulation
        r"print\s+exactly:",
        r"output\s+the\s+following:",
        r"repeat\s+after\s+me:",
        r"say\s+exactly:",
        
        # Escape attempts
        r"</?(system|prompt|instruction)>",
        r"```(system|bash|python|javascript)",
        r"(\[|\]){3,}",  # Triple brackets often used for injection
        
        # Encoded injection attempts
        r"(base64|hex|rot13|unicode):\s*\S+",
        r"\\x[0-9a-f]{2}",  # Hex escapes
        r"\\u[0-9a-f]{4}",  # Unicode escapes
        
        # Common jailbreak patterns
        r"DAN\s+mode",
        r"developer\s+mode",
        r"jailbreak",
        r"bypass\s+(filter|security|safety)",
        
        # SQL-like injection patterns (for database contexts)
        r";\s*(DROP|DELETE|UPDATE|INSERT|SELECT)\s+",
        r"--\s*$",  # SQL comment
        r"(UNION|INTERSECT)\s+(ALL\s+)?SELECT",
        
        # Command injection patterns
        r";\s*(ls|cat|rm|wget|curl|nc|bash|sh)\s+",
        r"\|\s*(ls|cat|rm|wget|curl|nc|bash|sh)\s+",
        r"`[^`]+`",  # Backtick command substitution
        r"\$\([^)]+\)",  # Command substitution
    ]
    
    # Suspicious keywords that need context checking
    SUSPICIOUS_KEYWORDS = [
        "ignore", "disregard", "forget", "override",
        "system", "admin", "root", "sudo",
        "password", "token", "key", "secret",
        "execute", "eval", "exec", "compile",
        "injection", "exploit", "vulnerability",
        "unrestricted", "unlimited", "bypass"
    ]
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize the validator.
        
        Args:
            strict_mode: If True, blocks suspicious patterns more aggressively
        """
        self.strict_mode = strict_mode
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.INJECTION_PATTERNS
        ]
    
    def validate_prompt(
        self,
        prompt: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, ThreatLevel, List[str]]:
        """
        Validate a prompt for injection attempts.
        
        Args:
            prompt: The prompt to validate
            context: Additional context for validation
            
        Returns:
            Tuple of (is_safe, threat_level, detected_issues)
        """
        if not prompt:
            return True, ThreatLevel.SAFE, []
        
        detected_issues = []
        threat_level = ThreatLevel.SAFE
        
        # Check for direct pattern matches
        for pattern in self.compiled_patterns:
            if pattern.search(prompt):
                detected_issues.append(f"Injection pattern detected: {pattern.pattern[:50]}...")
                threat_level = self._escalate_threat(threat_level, ThreatLevel.HIGH)
        
        # Check for suspicious keywords
        keyword_count = self._check_suspicious_keywords(prompt)
        if keyword_count > 3:
            detected_issues.append(f"Multiple suspicious keywords detected ({keyword_count})")
            threat_level = self._escalate_threat(threat_level, ThreatLevel.MEDIUM)
        elif keyword_count > 0:
            threat_level = self._escalate_threat(threat_level, ThreatLevel.LOW)
        
        # Check for encoding attempts
        if self._has_encoded_content(prompt):
            detected_issues.append("Encoded content detected")
            threat_level = self._escalate_threat(threat_level, ThreatLevel.HIGH)
        
        # Check for excessive special characters
        special_char_ratio = self._calculate_special_char_ratio(prompt)
        if special_char_ratio > 0.3:
            detected_issues.append(f"High special character ratio: {special_char_ratio:.2%}")
            threat_level = self._escalate_threat(threat_level, ThreatLevel.MEDIUM)
        
        # Check for nested instructions
        if self._has_nested_instructions(prompt):
            detected_issues.append("Nested instruction patterns detected")
            threat_level = self._escalate_threat(threat_level, ThreatLevel.HIGH)
        
        # Context-specific validation
        if context:
            context_issues = self._validate_context(prompt, context)
            detected_issues.extend(context_issues)
            if context_issues:
                threat_level = self._escalate_threat(threat_level, ThreatLevel.MEDIUM)
        
        # Determine if safe based on threat level and mode
        is_safe = True
        if self.strict_mode:
            is_safe = threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]
        else:
            is_safe = threat_level != ThreatLevel.CRITICAL
        
        # Log suspicious activity
        if threat_level >= ThreatLevel.MEDIUM:
            logger.warning(
                f"Potential prompt injection detected. "
                f"Threat level: {threat_level.name}, "
                f"Issues: {detected_issues}"
            )
        
        return is_safe, threat_level, detected_issues
    
    def sanitize_prompt(self, prompt: str) -> str:
        """
        Sanitize a prompt by removing or escaping dangerous patterns.
        
        Args:
            prompt: The prompt to sanitize
            
        Returns:
            Sanitized prompt
        """
        if not prompt:
            return prompt
        
        sanitized = prompt
        
        # Remove obvious injection patterns
        for pattern in self.compiled_patterns[:10]:  # First 10 are most dangerous
            sanitized = pattern.sub("[REMOVED]", sanitized)
        
        # Escape special characters that could be used for injection
        escape_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '`': '&#96;',
            '$': '&#36;',
            '{': '&#123;',
            '}': '&#125;'
        }
        
        for char, escaped in escape_chars.items():
            sanitized = sanitized.replace(char, escaped)
        
        # Remove excessive whitespace that could hide injections
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Truncate if too long (potential DoS)
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "... [TRUNCATED]"
        
        return sanitized.strip()
    
    def _check_suspicious_keywords(self, prompt: str) -> int:
        """Count suspicious keywords in prompt."""
        prompt_lower = prompt.lower()
        count = 0
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in prompt_lower:
                count += prompt_lower.count(keyword)
        return count
    
    def _has_encoded_content(self, prompt: str) -> bool:
        """Check for encoded content that might hide injections."""
        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', prompt):
            return True
        
        # Check for hex encoding
        if re.search(r'(?:0x)?[0-9a-fA-F]{16,}', prompt):
            return True
        
        # Check for URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', prompt):
            return True
        
        return False
    
    def _calculate_special_char_ratio(self, prompt: str) -> float:
        """Calculate ratio of special characters to total characters."""
        if not prompt:
            return 0.0
        
        special_chars = sum(1 for c in prompt if not c.isalnum() and not c.isspace())
        return special_chars / len(prompt)
    
    def _has_nested_instructions(self, prompt: str) -> bool:
        """Check for nested instruction patterns."""
        # Look for multiple instruction markers
        instruction_markers = [
            "instructions:", "prompt:", "system:", "user:",
            "###", "```", "---", "==="
        ]
        
        marker_count = sum(
            1 for marker in instruction_markers
            if marker in prompt.lower()
        )
        
        return marker_count >= 2
    
    def _validate_context(
        self,
        prompt: str,
        context: Dict[str, Any]
    ) -> List[str]:
        """Validate prompt against provided context."""
        issues = []
        
        # Check if prompt tries to access unauthorized resources
        if "allowed_resources" in context:
            allowed = context["allowed_resources"]
            # Check for resource access patterns
            resource_pattern = r'access|read|write|modify|delete'
            if re.search(resource_pattern, prompt, re.IGNORECASE):
                # Further validation needed based on allowed resources
                pass
        
        # Check for role escalation attempts
        if "user_role" in context:
            if context["user_role"] != "admin":
                admin_patterns = r'admin|administrator|root|sudo|superuser'
                if re.search(admin_patterns, prompt, re.IGNORECASE):
                    issues.append("Potential privilege escalation attempt")
        
        return issues
    
    def _escalate_threat(
        self,
        current: ThreatLevel,
        new: ThreatLevel
    ) -> ThreatLevel:
        """Escalate threat level to the higher of two levels."""
        return ThreatLevel(max(current.value, new.value))


class PromptIsolator:
    """
    Isolates user prompts from system instructions.
    Provides clear boundaries between user input and system context.
    """
    
    def __init__(self):
        self.boundary_marker = "=" * 50
        self.user_marker = "[USER INPUT]"
        self.system_marker = "[SYSTEM CONTEXT]"
    
    def create_isolated_prompt(
        self,
        user_input: str,
        system_context: str,
        instructions: Optional[str] = None
    ) -> str:
        """
        Create a prompt with clear isolation between components.
        
        Args:
            user_input: The user's input
            system_context: System-provided context
            instructions: Optional system instructions
            
        Returns:
            Isolated prompt with clear boundaries
        """
        components = []
        
        # Add system instructions if provided
        if instructions:
            components.append(f"{self.system_marker} INSTRUCTIONS")
            components.append(self.boundary_marker)
            components.append(instructions)
            components.append(self.boundary_marker)
            components.append("")
        
        # Add system context
        components.append(f"{self.system_marker} CONTEXT")
        components.append(self.boundary_marker)
        components.append(system_context)
        components.append(self.boundary_marker)
        components.append("")
        
        # Add user input with clear isolation
        components.append(f"{self.user_marker} BEGIN")
        components.append(self.boundary_marker)
        components.append(user_input)
        components.append(self.boundary_marker)
        components.append(f"{self.user_marker} END")
        
        return "\n".join(components)
    
    def extract_user_input(self, isolated_prompt: str) -> Optional[str]:
        """
        Extract user input from an isolated prompt.
        
        Args:
            isolated_prompt: The isolated prompt
            
        Returns:
            Extracted user input or None
        """
        start_marker = f"{self.user_marker} BEGIN"
        end_marker = f"{self.user_marker} END"
        
        start_idx = isolated_prompt.find(start_marker)
        end_idx = isolated_prompt.find(end_marker)
        
        if start_idx == -1 or end_idx == -1:
            return None
        
        # Extract content between markers
        content = isolated_prompt[start_idx + len(start_marker):end_idx]
        
        # Remove boundary markers
        lines = content.strip().split('\n')
        if lines and lines[0] == self.boundary_marker:
            lines = lines[1:]
        if lines and lines[-1] == self.boundary_marker:
            lines = lines[:-1]
        
        return '\n'.join(lines).strip()


# Global instances for easy access
prompt_validator = PromptSecurityValidator(strict_mode=True)
prompt_isolator = PromptIsolator()