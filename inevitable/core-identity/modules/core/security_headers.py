"""
Security Headers Middleware
Comprehensive security headers implementation following OWASP guidelines
Fixes LOW-002: Missing Security Headers
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add comprehensive security headers to all responses
    Implements OWASP security header recommendations
    """
    
    def __init__(self, app, config: Optional[Dict[str, str]] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Default security headers configuration
        self.default_headers = {
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # Enable XSS filtering (legacy but still useful)
            "X-XSS-Protection": "1; mode=block",
            
            # Referrer policy for privacy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permissions policy (modern feature policy)
            "Permissions-Policy": (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "accelerometer=(), "
                "gyroscope=(), "
                "magnetometer=(), "
                "payment=(), "
                "usb=(), "
                "autoplay=()"
            ),
            
            # Content Security Policy (restrictive but functional)
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https://api.stripe.com https://checkout.stripe.com wss:; "
                "frame-src 'self' https://js.stripe.com https://checkout.stripe.com; "
                "object-src 'none'; "
                "media-src 'self'; "
                "worker-src 'self'; "
                "child-src 'self'; "
                "form-action 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "upgrade-insecure-requests"
            ),
            
            # Cache control for sensitive responses
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            
            # Server identification hiding
            "Server": "Platform-Forge/1.0"
        }
        
        # Merge with user config
        self.headers = {**self.default_headers, **self.config}
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Add security headers to response"""
        try:
            # Process the request
            response = await call_next(request)
            
            # Add security headers
            for header_name, header_value in self.headers.items():
                # Handle conditional headers
                if header_name == "Strict-Transport-Security":
                    # Only add HSTS for HTTPS requests
                    if request.url.scheme == "https":
                        response.headers[header_name] = header_value
                elif header_name == "Content-Security-Policy":
                    # Adjust CSP for API vs web content
                    if request.url.path.startswith("/api/"):
                        # More restrictive CSP for API endpoints
                        api_csp = (
                            "default-src 'none'; "
                            "connect-src 'self'; "
                            "frame-ancestors 'none'"
                        )
                        response.headers[header_name] = api_csp
                    else:
                        response.headers[header_name] = header_value
                elif header_name == "Cache-Control":
                    # Only add no-cache for sensitive endpoints
                    if self._is_sensitive_endpoint(request.url.path):
                        response.headers[header_name] = header_value
                        response.headers["Pragma"] = "no-cache"
                        response.headers["Expires"] = "0"
                    else:
                        # Allow caching for static resources
                        if self._is_static_resource(request.url.path):
                            response.headers[header_name] = "public, max-age=3600"
                        else:
                            response.headers[header_name] = "no-cache"
                else:
                    response.headers[header_name] = header_value
            
            # Add HSTS header for HTTPS
            if request.url.scheme == "https":
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains; preload"
                )
            
            # Remove server information leakage  
            # Use del instead of pop for MutableHeaders
            if "server" in response.headers:
                del response.headers["server"]
            
            # Add security-specific headers based on response content
            self._add_content_specific_headers(request, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Error in SecurityHeadersMiddleware: {e}")
            # Don't let security headers middleware break the app
            response = await call_next(request)
            return response
    
    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint contains sensitive data"""
        sensitive_paths = [
            "/api/auth/",
            "/api/admin/",
            "/api/billing/",
            "/api/user/",
            "/api/mfa/",
            "/login",
            "/logout",
            "/admin"
        ]
        
        return any(sensitive in path for sensitive in sensitive_paths)
    
    def _is_static_resource(self, path: str) -> bool:
        """Check if path is a static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2']
        return any(path.endswith(ext) for ext in static_extensions)
    
    def _add_content_specific_headers(self, request: Request, response: Response):
        """Add headers specific to response content type"""
        content_type = response.headers.get("content-type", "").lower()
        
        if "application/json" in content_type:
            # Additional headers for JSON API responses
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
            
        elif "text/html" in content_type:
            # Additional headers for HTML responses
            response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
            
        elif content_type.startswith("application/"):
            # Headers for downloadable content
            response.headers["X-Download-Options"] = "noopen"
            response.headers["X-Permitted-Cross-Domain-Policies"] = "none"


class CSPViolationReporter(BaseHTTPMiddleware):
    """
    Middleware to handle Content Security Policy violation reports
    Helps monitor and improve CSP policy
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Handle CSP violation reports"""
        if request.url.path == "/api/security/csp-report" and request.method == "POST":
            try:
                # Log CSP violations for monitoring
                body = await request.body()
                violation_data = body.decode('utf-8')
                
                logger.warning(f"CSP Violation Report: {violation_data}")
                
                # In production, you might want to:
                # 1. Parse the violation report
                # 2. Store in database for analysis  
                # 3. Alert security team for repeated violations
                # 4. Automatically adjust CSP policy
                
                return Response(status_code=204)  # No content
                
            except Exception as e:
                logger.error(f"Error processing CSP report: {e}")
                return Response(status_code=400)
        
        return await call_next(request)


def create_security_headers_middleware(
    csp_report_uri: Optional[str] = None,
    additional_headers: Optional[Dict[str, str]] = None
) -> SecurityHeadersMiddleware:
    """
    Factory function to create security headers middleware with custom configuration
    
    Args:
        csp_report_uri: URI to send CSP violation reports
        additional_headers: Additional security headers to add
    
    Returns:
        Configured SecurityHeadersMiddleware instance
    """
    config = {}
    
    if additional_headers:
        config.update(additional_headers)
    
    # Add CSP reporting if URI provided
    if csp_report_uri:
        current_csp = config.get("Content-Security-Policy", "")
        if current_csp:
            config["Content-Security-Policy"] = f"{current_csp}; report-uri {csp_report_uri}"
    
    return SecurityHeadersMiddleware(app=None, config=config)


# Pre-configured middleware for different environments
def get_production_security_headers() -> Dict[str, str]:
    """Get production-grade security headers configuration"""
    return {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src 'none'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "worker-src 'none'; "
            "child-src 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "upgrade-insecure-requests; "
            "block-all-mixed-content"
        ),
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

def get_development_security_headers() -> Dict[str, str]:
    """Get development-friendly security headers configuration"""
    return {
        "Content-Security-Policy": (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://api.stripe.com ws: wss:; "
            "font-src 'self' https://fonts.gstatic.com"
        ),
        "X-Frame-Options": "SAMEORIGIN",  # Allow framing for dev tools
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "origin-when-cross-origin"
    }