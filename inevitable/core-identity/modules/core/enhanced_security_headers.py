"""
Enhanced Security Headers System for Platform Forge
Addresses LOW-002: Security Headers Enhancements

Provides comprehensive security headers with:
- Advanced Content Security Policy management
- Dynamic header configuration based on request context
- Security header validation and reporting
- Compliance with latest security standards
- Integration with security monitoring
"""
import re
import json
import logging
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from fastapi import Request, Response
from datetime import datetime, timedelta

from .config import settings
from .security import SecurityError

logger = logging.getLogger(__name__)


class SecurityHeaderLevel(Enum):
    """Security header strictness levels"""
    PERMISSIVE = "permissive"
    BALANCED = "balanced" 
    STRICT = "strict"
    PARANOID = "paranoid"


class ContentType(Enum):
    """Response content types for header customization"""
    HTML = "text/html"
    JSON = "application/json"
    XML = "application/xml"
    PDF = "application/pdf"
    IMAGE = "image/"
    CSS = "text/css"
    JAVASCRIPT = "application/javascript"
    FONT = "font/"


@dataclass
class CSPDirective:
    """Content Security Policy directive configuration"""
    name: str
    sources: Set[str] = field(default_factory=set)
    allow_unsafe_inline: bool = False
    allow_unsafe_eval: bool = False
    allow_data_uri: bool = False
    report_only: bool = False


@dataclass
class SecurityHeaderPolicy:
    """Complete security header policy configuration"""
    level: SecurityHeaderLevel = SecurityHeaderLevel.BALANCED
    csp_directives: Dict[str, CSPDirective] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    excluded_paths: Set[str] = field(default_factory=set)
    content_type_overrides: Dict[ContentType, Dict[str, str]] = field(default_factory=dict)


class EnhancedSecurityHeadersManager:
    """
    Enhanced security headers manager with dynamic policy application
    """
    
    def __init__(self, default_level: SecurityHeaderLevel = SecurityHeaderLevel.BALANCED):
        self.default_level = default_level
        self.policies = self._initialize_policies()
        
        # Header validation patterns
        self.header_validators = {
            "Content-Security-Policy": self._validate_csp,
            "Strict-Transport-Security": self._validate_hsts,
            "Permissions-Policy": self._validate_permissions_policy
        }
        
        # Security metrics
        self.violation_counts = {}
        self.header_coverage = {}
        
    def _initialize_policies(self) -> Dict[SecurityHeaderLevel, SecurityHeaderPolicy]:
        """Initialize security policies for different levels"""
        policies = {}
        
        # PERMISSIVE - Minimal restrictions for development
        policies[SecurityHeaderLevel.PERMISSIVE] = SecurityHeaderPolicy(
            level=SecurityHeaderLevel.PERMISSIVE,
            csp_directives={
                "default-src": CSPDirective("default-src", {"'self'", "'unsafe-inline'", "'unsafe-eval'"}),
                "script-src": CSPDirective("script-src", {"'self'", "'unsafe-inline'", "'unsafe-eval'", "https:"}),
                "style-src": CSPDirective("style-src", {"'self'", "'unsafe-inline'", "https:"}),
                "img-src": CSPDirective("img-src", {"'self'", "data:", "https:"}),
                "connect-src": CSPDirective("connect-src", {"'self'", "https:", "wss:", "ws:"}),
                "font-src": CSPDirective("font-src", {"'self'", "https:", "data:"}),
                "object-src": CSPDirective("object-src", {"'none'"}),
                "base-uri": CSPDirective("base-uri", {"'self'"})
            },
            custom_headers={
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "origin-when-cross-origin"
            }
        )
        
        # BALANCED - Good security with reasonable flexibility
        policies[SecurityHeaderLevel.BALANCED] = SecurityHeaderPolicy(
            level=SecurityHeaderLevel.BALANCED,
            csp_directives={
                "default-src": CSPDirective("default-src", {"'self'"}),
                "script-src": CSPDirective("script-src", {"'self'", "https://js.stripe.com", "https://cdn.jsdelivr.net"}),
                "style-src": CSPDirective("style-src", {"'self'", "'unsafe-inline'", "https://fonts.googleapis.com"}),
                "img-src": CSPDirective("img-src", {"'self'", "data:", "https:"}),
                "connect-src": CSPDirective("connect-src", {"'self'", "https://api.stripe.com", "wss:"}),
                "font-src": CSPDirective("font-src", {"'self'", "https://fonts.gstatic.com"}),
                "frame-src": CSPDirective("frame-src", {"'self'", "https://js.stripe.com"}),
                "object-src": CSPDirective("object-src", {"'none'"}),
                "media-src": CSPDirective("media-src", {"'self'"}),
                "worker-src": CSPDirective("worker-src", {"'self'"}),
                "child-src": CSPDirective("child-src", {"'self'"}),
                "form-action": CSPDirective("form-action", {"'self'"}),
                "frame-ancestors": CSPDirective("frame-ancestors", {"'none'"}),
                "base-uri": CSPDirective("base-uri", {"'self'"}),
                "upgrade-insecure-requests": CSPDirective("upgrade-insecure-requests", set())
            },
            custom_headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": (
                    "geolocation=(), microphone=(), camera=(), "
                    "accelerometer=(), gyroscope=(), magnetometer=(), "
                    "payment=(), usb=(), autoplay=self"
                ),
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin"
            }
        )
        
        # STRICT - High security for production
        policies[SecurityHeaderLevel.STRICT] = SecurityHeaderPolicy(
            level=SecurityHeaderLevel.STRICT,
            csp_directives={
                "default-src": CSPDirective("default-src", {"'none'"}),
                "script-src": CSPDirective("script-src", {"'self'", "https://js.stripe.com"}),
                "style-src": CSPDirective("style-src", {"'self'", "https://fonts.googleapis.com"}),
                "img-src": CSPDirective("img-src", {"'self'", "data:"}),
                "connect-src": CSPDirective("connect-src", {"'self'", "https://api.stripe.com"}),
                "font-src": CSPDirective("font-src", {"'self'", "https://fonts.gstatic.com"}),
                "frame-src": CSPDirective("frame-src", {"'none'"}),
                "object-src": CSPDirective("object-src", {"'none'"}),
                "media-src": CSPDirective("media-src", {"'none'"}),
                "worker-src": CSPDirective("worker-src", {"'none'"}),
                "child-src": CSPDirective("child-src", {"'none'"}),
                "form-action": CSPDirective("form-action", {"'self'"}),
                "frame-ancestors": CSPDirective("frame-ancestors", {"'none'"}),
                "base-uri": CSPDirective("base-uri", {"'none'"}),
                "upgrade-insecure-requests": CSPDirective("upgrade-insecure-requests", set()),
                "block-all-mixed-content": CSPDirective("block-all-mixed-content", set())
            },
            custom_headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-site",
                "Clear-Site-Data": "\"cache\", \"cookies\", \"storage\", \"executionContexts\"",
                "Feature-Policy": "geolocation 'none'; microphone 'none'; camera 'none'"
            }
        )
        
        # PARANOID - Maximum security
        policies[SecurityHeaderLevel.PARANOID] = SecurityHeaderPolicy(
            level=SecurityHeaderLevel.PARANOID,
            csp_directives={
                "default-src": CSPDirective("default-src", {"'none'"}),
                "script-src": CSPDirective("script-src", {"'self'"}),  # No external scripts
                "style-src": CSPDirective("style-src", {"'self'"}),   # No external styles
                "img-src": CSPDirective("img-src", {"'self'"}),       # No external images
                "connect-src": CSPDirective("connect-src", {"'self'"}),
                "font-src": CSPDirective("font-src", {"'self'"}),
                "frame-src": CSPDirective("frame-src", {"'none'"}),
                "object-src": CSPDirective("object-src", {"'none'"}),
                "media-src": CSPDirective("media-src", {"'none'"}),
                "worker-src": CSPDirective("worker-src", {"'none'"}),
                "child-src": CSPDirective("child-src", {"'none'"}),
                "form-action": CSPDirective("form-action", {"'self'"}),
                "frame-ancestors": CSPDirective("frame-ancestors", {"'none'"}),
                "base-uri": CSPDirective("base-uri", {"'none'"}),
                "upgrade-insecure-requests": CSPDirective("upgrade-insecure-requests", set()),
                "block-all-mixed-content": CSPDirective("block-all-mixed-content", set())
            },
            custom_headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "",  # Block all features
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Clear-Site-Data": "\"cache\", \"cookies\", \"storage\", \"executionContexts\"",
                "Expect-CT": "max-age=86400, enforce",
                "Feature-Policy": ""  # Block all features
            }
        )
        
        return policies
    
    def get_headers_for_request(
        self, 
        request: Request, 
        response: Response,
        level: Optional[SecurityHeaderLevel] = None
    ) -> Dict[str, str]:
        """
        Generate appropriate security headers for a specific request/response
        """
        # Determine security level
        security_level = level or self._determine_security_level(request)
        policy = self.policies[security_level]
        
        # Check if path is excluded
        if any(request.url.path.startswith(path) for path in policy.excluded_paths):
            return {}
        
        headers = {}
        
        # Add CSP header
        csp_header = self._build_csp_header(policy.csp_directives, request)
        if csp_header:
            headers["Content-Security-Policy"] = csp_header
        
        # Add custom headers
        headers.update(policy.custom_headers)
        
        # Add content-type specific headers
        content_type = response.headers.get("content-type", "")
        content_type_enum = self._get_content_type_enum(content_type)
        if content_type_enum in policy.content_type_overrides:
            headers.update(policy.content_type_overrides[content_type_enum])
        
        # Add conditional headers
        self._add_conditional_headers(headers, request, response)
        
        # Validate headers
        validated_headers = self._validate_headers(headers)
        
        return validated_headers
    
    def _determine_security_level(self, request: Request) -> SecurityHeaderLevel:
        """Determine appropriate security level based on request context"""
        path = request.url.path
        
        # API endpoints get strict security
        if path.startswith("/api/"):
            if any(sensitive in path for sensitive in ["/auth/", "/admin/", "/billing/"]):
                return SecurityHeaderLevel.STRICT
            return SecurityHeaderLevel.BALANCED
        
        # Admin interfaces get paranoid security
        if "/admin" in path:
            return SecurityHeaderLevel.PARANOID
        
        # Development mode gets permissive
        if settings.DEBUG:
            return SecurityHeaderLevel.PERMISSIVE
        
        # Default to balanced
        return SecurityHeaderLevel.BALANCED
    
    def _build_csp_header(
        self, 
        directives: Dict[str, CSPDirective], 
        request: Request
    ) -> str:
        """Build Content Security Policy header string"""
        csp_parts = []
        
        for directive in directives.values():
            if not directive.sources and directive.name in ["upgrade-insecure-requests", "block-all-mixed-content"]:
                # Directives without sources
                csp_parts.append(directive.name)
            else:
                # Directives with sources
                sources = list(directive.sources)
                
                # Add conditional sources
                if directive.allow_unsafe_inline and "'unsafe-inline'" not in sources:
                    sources.append("'unsafe-inline'")
                if directive.allow_unsafe_eval and "'unsafe-eval'" not in sources:
                    sources.append("'unsafe-eval'")
                if directive.allow_data_uri and "data:" not in sources:
                    sources.append("data:")
                
                if sources:
                    csp_parts.append(f"{directive.name} {' '.join(sources)}")
        
        csp_header = "; ".join(csp_parts)
        
        # Add CSP reporting
        if not settings.DEBUG:
            report_uri = "/api/security/csp-report"
            csp_header += f"; report-uri {report_uri}"
        
        return csp_header
    
    def _get_content_type_enum(self, content_type: str) -> Optional[ContentType]:
        """Get ContentType enum from content-type header"""
        content_type = content_type.lower()
        
        for ct_enum in ContentType:
            if content_type.startswith(ct_enum.value):
                return ct_enum
        return None
    
    def _add_conditional_headers(
        self, 
        headers: Dict[str, str], 
        request: Request, 
        response: Response
    ):
        """Add headers based on request/response conditions"""
        # Add HSTS for HTTPS
        if request.url.scheme == "https":
            headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Add cache control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            headers["Pragma"] = "no-cache"
            headers["Expires"] = "0"
        
        # Add timing attack protection
        if request.url.path.startswith("/api/auth/"):
            headers["X-Response-Time-Policy"] = "enforce-constant-time"
        
        # Add request ID for tracing
        if "X-Request-ID" not in response.headers:
            import uuid
            headers["X-Request-ID"] = str(uuid.uuid4())
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data"""
        sensitive_patterns = [
            r"/api/auth/",
            r"/api/admin/", 
            r"/api/billing/",
            r"/api/user/profile",
            r"/api/mfa/",
            r"/login",
            r"/admin"
        ]
        
        return any(re.match(pattern, path) for pattern in sensitive_patterns)
    
    def _validate_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize security headers"""
        validated = {}
        
        for name, value in headers.items():
            if name in self.header_validators:
                if self.header_validators[name](value):
                    validated[name] = value
                else:
                    logger.warning(f"Invalid security header {name}: {value}")
            else:
                # Basic validation for other headers
                if self._is_safe_header_value(value):
                    validated[name] = value
                else:
                    logger.warning(f"Potentially unsafe header value for {name}: {value}")
        
        return validated
    
    def _validate_csp(self, csp_value: str) -> bool:
        """Validate Content Security Policy header"""
        try:
            # Basic CSP validation - check for common issues
            dangerous_patterns = [
                r"'unsafe-inline'\s+[^;]*script-src",  # unsafe-inline in script-src
                r"data:\s+[^;]*script-src",            # data: in script-src
                r"\*\s+[^;]*script-src",               # wildcard in script-src
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, csp_value, re.IGNORECASE):
                    logger.warning(f"Potentially unsafe CSP pattern: {pattern}")
                    return False
            
            return True
        except Exception:
            return False
    
    def _validate_hsts(self, hsts_value: str) -> bool:
        """Validate Strict-Transport-Security header"""
        try:
            # Check for minimum max-age
            max_age_match = re.search(r"max-age=(\d+)", hsts_value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                return max_age >= 31536000  # At least 1 year
            return False
        except Exception:
            return False
    
    def _validate_permissions_policy(self, policy_value: str) -> bool:
        """Validate Permissions-Policy header"""
        try:
            # Basic validation - check format
            if not policy_value:
                return True  # Empty policy is valid (blocks all)
            
            # Check for valid format: feature=allowlist
            parts = policy_value.split(",")
            for part in parts:
                part = part.strip()
                if "=" not in part:
                    continue
                feature, allowlist = part.split("=", 1)
                if not feature.strip() or not allowlist.strip():
                    return False
            
            return True
        except Exception:
            return False
    
    def _is_safe_header_value(self, value: str) -> bool:
        """Basic validation for header values"""
        try:
            # Check for control characters and potentially dangerous content
            if re.search(r'[\x00-\x1f\x7f]', value):  # Control characters
                return False
            if re.search(r'<script[^>]*>', value, re.IGNORECASE):  # Script injection
                return False
            return True
        except Exception:
            return False
    
    def generate_security_report(self, request: Request) -> Dict[str, Any]:
        """Generate security headers compliance report"""
        current_level = self._determine_security_level(request)
        policy = self.policies[current_level]
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_path": request.url.path,
            "security_level": current_level.value,
            "csp_directives": len(policy.csp_directives),
            "custom_headers": len(policy.custom_headers),
            "compliance_score": self._calculate_compliance_score(policy),
            "recommendations": self._generate_recommendations(policy)
        }
        
        return report
    
    def _calculate_compliance_score(self, policy: SecurityHeaderPolicy) -> float:
        """Calculate compliance score for a security policy"""
        max_score = 100.0
        score = max_score
        
        # Deduct points for missing or weak configurations
        if not policy.csp_directives:
            score -= 30
        if policy.level == SecurityHeaderLevel.PERMISSIVE:
            score -= 20
        if "upgrade-insecure-requests" not in [d.name for d in policy.csp_directives.values()]:
            score -= 10
        
        return max(0.0, score)
    
    def _generate_recommendations(self, policy: SecurityHeaderPolicy) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if policy.level == SecurityHeaderLevel.PERMISSIVE:
            recommendations.append("Consider upgrading to BALANCED or STRICT security level")
        
        if not any("frame-ancestors" in d.name for d in policy.csp_directives.values()):
            recommendations.append("Add frame-ancestors directive to prevent clickjacking")
        
        if "Cross-Origin-Embedder-Policy" not in policy.custom_headers:
            recommendations.append("Add Cross-Origin-Embedder-Policy header for isolation")
        
        return recommendations


# Global enhanced security headers manager
_enhanced_headers_manager = None


def get_enhanced_headers_manager() -> EnhancedSecurityHeadersManager:
    """Get global enhanced security headers manager"""
    global _enhanced_headers_manager
    if _enhanced_headers_manager is None:
        _enhanced_headers_manager = EnhancedSecurityHeadersManager()
    return _enhanced_headers_manager