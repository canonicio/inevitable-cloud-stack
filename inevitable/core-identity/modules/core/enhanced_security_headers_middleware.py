"""
Enhanced Security Headers Middleware for Platform Forge
Integrates with existing security headers to provide comprehensive protection

Features:
- Dynamic security level adjustment based on request context
- Advanced CSP management with violation reporting  
- Security metrics collection and monitoring
- Integration with existing security systems
- Performance optimized header application
"""
import json
import time
import logging
from typing import Dict, Any, Optional, List
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from datetime import datetime

from .enhanced_security_headers import (
    get_enhanced_headers_manager, 
    SecurityHeaderLevel, 
    EnhancedSecurityHeadersManager
)
from .config import settings

logger = logging.getLogger(__name__)


class EnhancedSecurityHeadersMiddleware:
    """
    Enhanced security headers middleware with dynamic policy application
    """
    
    def __init__(self, app):
        self.app = app
        self.headers_manager = get_enhanced_headers_manager()
        
        # Performance metrics
        self.header_application_times = []
        self.csp_violation_count = 0
        
        # Paths that bypass enhanced security
        self.bypass_paths = {
            "/health",
            "/metrics", 
            "/openapi.json",
            "/docs",
            "/redoc",
            "/favicon.ico"
        }
        
        # Security monitoring
        self.security_events = []
        self.max_events = 1000  # Keep last 1000 events
        
    async def __call__(self, request: Request, call_next):
        # Start timing
        start_time = time.time()
        
        # Check if path should bypass enhanced security
        if any(request.url.path.startswith(path) for path in self.bypass_paths):
            return await call_next(request)
        
        # Process request
        response = await call_next(request)
        
        try:
            # Apply enhanced security headers
            enhanced_headers = self.headers_manager.get_headers_for_request(
                request, 
                response
            )
            
            # Apply headers to response
            for header_name, header_value in enhanced_headers.items():
                response.headers[header_name] = header_value
            
            # Add security monitoring headers in debug mode
            if settings.DEBUG:
                self._add_debug_headers(response, request, enhanced_headers)
            
            # Record security event
            self._record_security_event(request, response, enhanced_headers)
            
            # Record performance metrics
            processing_time = time.time() - start_time
            self.header_application_times.append(processing_time)
            if len(self.header_application_times) > 1000:
                self.header_application_times = self.header_application_times[-1000:]
            
        except Exception as e:
            logger.error(f"Enhanced security headers middleware error: {e}")
            # Don't let header errors break the application
            pass
        
        return response
    
    def _add_debug_headers(
        self, 
        response: Response, 
        request: Request, 
        applied_headers: Dict[str, str]
    ):
        """Add debug headers for development"""
        try:
            # Add header application summary
            response.headers["X-Security-Headers-Applied"] = str(len(applied_headers))
            
            # Add security level info
            security_level = self.headers_manager._determine_security_level(request)
            response.headers["X-Security-Level"] = security_level.value
            
            # Add CSP directive count
            csp_header = applied_headers.get("Content-Security-Policy", "")
            if csp_header:
                directive_count = csp_header.count(";") + 1
                response.headers["X-CSP-Directive-Count"] = str(directive_count)
            
            # Add performance metrics
            if self.header_application_times:
                avg_time = sum(self.header_application_times) / len(self.header_application_times)
                response.headers["X-Header-Processing-Time-Avg"] = f"{avg_time:.4f}ms"
            
        except Exception as e:
            logger.warning(f"Debug header addition failed: {e}")
    
    def _record_security_event(
        self, 
        request: Request, 
        response: Response, 
        applied_headers: Dict[str, str]
    ):
        """Record security event for monitoring"""
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.url.path,
                "method": request.method,
                "user_agent": request.headers.get("User-Agent", "")[:100],  # Truncate
                "ip_address": getattr(request.client, 'host', '') if request.client else '',
                "status_code": response.status_code,
                "headers_applied": len(applied_headers),
                "security_level": self.headers_manager._determine_security_level(request).value,
                "has_csp": "Content-Security-Policy" in applied_headers,
                "has_hsts": "Strict-Transport-Security" in applied_headers
            }
            
            # Add event to monitoring queue
            self.security_events.append(event)
            if len(self.security_events) > self.max_events:
                self.security_events = self.security_events[-self.max_events:]
                
        except Exception as e:
            logger.warning(f"Security event recording failed: {e}")
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics for monitoring"""
        try:
            total_events = len(self.security_events)
            if total_events == 0:
                return {"message": "No security events recorded"}
            
            # Calculate metrics
            recent_events = self.security_events[-100:]  # Last 100 events
            
            # Path distribution
            path_counts = {}
            status_counts = {}
            security_level_counts = {}
            
            for event in recent_events:
                path = event["path"]
                status = event["status_code"]
                level = event["security_level"]
                
                path_counts[path] = path_counts.get(path, 0) + 1
                status_counts[status] = status_counts.get(status, 0) + 1
                security_level_counts[level] = security_level_counts.get(level, 0) + 1
            
            # Performance metrics
            avg_processing_time = 0
            if self.header_application_times:
                avg_processing_time = sum(self.header_application_times) / len(self.header_application_times)
            
            metrics = {
                "total_events": total_events,
                "recent_events_count": len(recent_events),
                "csp_violation_count": self.csp_violation_count,
                "avg_header_processing_time_ms": round(avg_processing_time * 1000, 4),
                "path_distribution": dict(sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                "status_code_distribution": status_counts,
                "security_level_distribution": security_level_counts,
                "events_with_csp": sum(1 for e in recent_events if e.get("has_csp", False)),
                "events_with_hsts": sum(1 for e in recent_events if e.get("has_hsts", False))
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Security metrics calculation failed: {e}")
            return {"error": "Failed to calculate metrics"}
    
    def get_recent_security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security events for analysis"""
        try:
            return self.security_events[-limit:] if self.security_events else []
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []


class CSPViolationHandler:
    """
    Enhanced CSP violation reporting and analysis
    """
    
    def __init__(self):
        self.violations = []
        self.max_violations = 1000
        self.violation_patterns = {}
        
    async def handle_csp_report(self, request: Request) -> Response:
        """Handle CSP violation reports with enhanced analysis"""
        try:
            # Parse violation report
            body = await request.body()
            report_data = json.loads(body.decode('utf-8'))
            
            # Extract violation details
            csp_report = report_data.get('csp-report', {})
            
            violation = {
                "timestamp": datetime.utcnow().isoformat(),
                "blocked_uri": csp_report.get('blocked-uri', ''),
                "document_uri": csp_report.get('document-uri', ''),
                "violated_directive": csp_report.get('violated-directive', ''),
                "original_policy": csp_report.get('original-policy', ''),
                "source_file": csp_report.get('source-file', ''),
                "line_number": csp_report.get('line-number', 0),
                "column_number": csp_report.get('column-number', 0),
                "user_agent": request.headers.get("User-Agent", "")[:100],
                "ip_address": getattr(request.client, 'host', '') if request.client else ''
            }
            
            # Store violation
            self.violations.append(violation)
            if len(self.violations) > self.max_violations:
                self.violations = self.violations[-self.max_violations:]
            
            # Analyze violation pattern
            pattern_key = f"{violation['violated_directive']}:{violation['blocked_uri']}"
            self.violation_patterns[pattern_key] = self.violation_patterns.get(pattern_key, 0) + 1
            
            # Log violation
            logger.warning(
                f"CSP Violation: {violation['violated_directive']} "
                f"blocked {violation['blocked_uri']} on {violation['document_uri']}"
            )
            
            # Generate recommendations if pattern detected
            if self.violation_patterns[pattern_key] >= 5:
                self._generate_csp_recommendations(violation)
            
            return Response(status_code=204)  # No content
            
        except Exception as e:
            logger.error(f"CSP violation handling error: {e}")
            return Response(status_code=400)
    
    def _generate_csp_recommendations(self, violation: Dict[str, Any]):
        """Generate CSP policy recommendations based on violations"""
        try:
            violated_directive = violation['violated_directive']
            blocked_uri = violation['blocked_uri']
            
            recommendations = []
            
            if 'script-src' in violated_directive:
                if blocked_uri.startswith('https://'):
                    recommendations.append(f"Consider adding '{blocked_uri}' to script-src allowlist")
                elif 'inline' in blocked_uri:
                    recommendations.append("Consider using nonces or hashes instead of 'unsafe-inline'")
            
            elif 'style-src' in violated_directive:
                if blocked_uri.startswith('https://'):
                    recommendations.append(f"Consider adding '{blocked_uri}' to style-src allowlist")
            
            elif 'img-src' in violated_directive:
                if blocked_uri.startswith('https://'):
                    recommendations.append(f"Consider adding '{blocked_uri}' to img-src allowlist")
            
            if recommendations:
                logger.info(f"CSP Recommendations: {'; '.join(recommendations)}")
                
        except Exception as e:
            logger.error(f"CSP recommendation generation failed: {e}")
    
    def get_violation_summary(self) -> Dict[str, Any]:
        """Get summary of CSP violations"""
        try:
            if not self.violations:
                return {"message": "No CSP violations recorded"}
            
            # Recent violations (last 24 hours simulation - using last 100 for demo)
            recent_violations = self.violations[-100:]
            
            # Group by violated directive
            directive_counts = {}
            blocked_uri_counts = {}
            
            for violation in recent_violations:
                directive = violation['violated_directive']
                blocked_uri = violation['blocked_uri']
                
                directive_counts[directive] = directive_counts.get(directive, 0) + 1
                blocked_uri_counts[blocked_uri] = blocked_uri_counts.get(blocked_uri, 0) + 1
            
            summary = {
                "total_violations": len(self.violations),
                "recent_violations": len(recent_violations),
                "top_violated_directives": dict(sorted(directive_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                "top_blocked_uris": dict(sorted(blocked_uri_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                "violation_patterns": dict(sorted(self.violation_patterns.items(), key=lambda x: x[1], reverse=True)[:10])
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Violation summary generation failed: {e}")
            return {"error": "Failed to generate summary"}


# Global instances
_enhanced_middleware = None
_csp_violation_handler = None


def get_enhanced_headers_middleware() -> EnhancedSecurityHeadersMiddleware:
    """Get global enhanced headers middleware instance"""
    global _enhanced_middleware
    if _enhanced_middleware is None:
        _enhanced_middleware = EnhancedSecurityHeadersMiddleware(app=None)
    return _enhanced_middleware


def get_csp_violation_handler() -> CSPViolationHandler:
    """Get global CSP violation handler instance"""
    global _csp_violation_handler
    if _csp_violation_handler is None:
        _csp_violation_handler = CSPViolationHandler()
    return _csp_violation_handler