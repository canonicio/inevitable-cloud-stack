"""
Security Headers Management API Routes for Platform Forge
Provides endpoints for monitoring and configuring security headers

Features:
- Security headers monitoring and reporting
- CSP violation analysis
- Dynamic security policy configuration
- Compliance assessment
- Performance metrics
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .database import get_db
from .deps import get_current_active_user, get_current_superuser
from ..auth.models import User
from .enhanced_security_headers import (
    get_enhanced_headers_manager, 
    SecurityHeaderLevel,
    EnhancedSecurityHeadersManager
)
from .enhanced_security_headers_middleware import (
    get_enhanced_headers_middleware,
    get_csp_violation_handler
)
from .enhanced_validators import SecureBaseModel

router = APIRouter(prefix="/api/security-headers", tags=["security-headers"])


class SecurityHeadersReport(SecureBaseModel):
    """Security headers compliance report"""
    timestamp: str
    request_path: str
    security_level: str
    csp_directives: int
    custom_headers: int
    compliance_score: float
    recommendations: List[str]


class CSPViolationSummary(SecureBaseModel):
    """CSP violation summary"""
    total_violations: int
    recent_violations: int
    top_violated_directives: Dict[str, int]
    top_blocked_uris: Dict[str, int]
    violation_patterns: Dict[str, int]


class SecurityMetrics(SecureBaseModel):
    """Security headers performance metrics"""
    total_events: int
    recent_events_count: int
    csp_violation_count: int
    avg_header_processing_time_ms: float
    path_distribution: Dict[str, int]
    status_code_distribution: Dict[int, int]
    security_level_distribution: Dict[str, int]


class SecurityPolicyRequest(SecureBaseModel):
    """Request to update security policy"""
    security_level: str = Field(..., description="Security level: permissive, balanced, strict, paranoid")
    custom_headers: Optional[Dict[str, str]] = Field(default=None, description="Custom security headers")
    excluded_paths: Optional[List[str]] = Field(default=None, description="Paths to exclude from security policy")


@router.get("/report", response_model=SecurityHeadersReport)
async def get_security_headers_report(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    headers_manager: EnhancedSecurityHeadersManager = Depends(get_enhanced_headers_manager)
):
    """Get comprehensive security headers report for current request"""
    try:
        report = headers_manager.generate_security_report(request)
        
        return SecurityHeadersReport(
            timestamp=report["timestamp"],
            request_path=report["request_path"],
            security_level=report["security_level"],
            csp_directives=report["csp_directives"],
            custom_headers=report["custom_headers"],
            compliance_score=report["compliance_score"],
            recommendations=report["recommendations"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate security headers report"
        )


@router.get("/metrics", response_model=SecurityMetrics)
async def get_security_metrics(
    current_user: User = Depends(get_current_superuser),
):
    """Get security headers performance metrics (admin only)"""
    try:
        middleware = get_enhanced_headers_middleware()
        metrics = middleware.get_security_metrics()
        
        if "error" in metrics:
            raise HTTPException(status_code=500, detail=metrics["error"])
        
        return SecurityMetrics(**metrics)
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security metrics"
        )


@router.get("/csp-violations", response_model=CSPViolationSummary)
async def get_csp_violations(
    current_user: User = Depends(get_current_superuser),
):
    """Get CSP violation summary (admin only)"""
    try:
        violation_handler = get_csp_violation_handler()
        summary = violation_handler.get_violation_summary()
        
        if "error" in summary:
            raise HTTPException(status_code=500, detail=summary["error"])
        
        if "message" in summary:
            # No violations recorded
            return CSPViolationSummary(
                total_violations=0,
                recent_violations=0,
                top_violated_directives={},
                top_blocked_uris={},
                violation_patterns={}
            )
        
        return CSPViolationSummary(**summary)
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve CSP violations"
        )


@router.post("/csp-report")
async def handle_csp_violation_report(
    request: Request
):
    """Handle CSP violation reports from browsers"""
    try:
        violation_handler = get_csp_violation_handler()
        response = await violation_handler.handle_csp_report(request)
        return response
        
    except Exception as e:
        logger.error(f"CSP report handling error: {e}")
        return Response(status_code=400)


@router.get("/test-headers")
async def test_security_headers(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_active_user),
    headers_manager: EnhancedSecurityHeadersManager = Depends(get_enhanced_headers_manager)
):
    """Test security headers application for current request"""
    try:
        # Get headers that would be applied
        test_headers = headers_manager.get_headers_for_request(request, response)
        
        # Apply them to the response for demonstration
        for header_name, header_value in test_headers.items():
            response.headers[f"X-Test-{header_name}"] = header_value
        
        return {
            "success": True,
            "message": "Security headers tested and applied with X-Test- prefix",
            "headers_applied": len(test_headers),
            "security_level": headers_manager._determine_security_level(request).value,
            "headers": test_headers
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Security headers test failed"
        )


@router.get("/policy/{security_level}")
async def get_security_policy(
    security_level: str,
    current_user: User = Depends(get_current_superuser),
    headers_manager: EnhancedSecurityHeadersManager = Depends(get_enhanced_headers_manager)
):
    """Get security policy configuration for a specific level (admin only)"""
    try:
        # Validate security level
        try:
            level_enum = SecurityHeaderLevel(security_level.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid security level. Must be one of: {[l.value for l in SecurityHeaderLevel]}"
            )
        
        policy = headers_manager.policies.get(level_enum)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        # Convert policy to serializable format
        policy_data = {
            "level": policy.level.value,
            "csp_directives": {
                name: {
                    "sources": list(directive.sources),
                    "allow_unsafe_inline": directive.allow_unsafe_inline,
                    "allow_unsafe_eval": directive.allow_unsafe_eval,
                    "allow_data_uri": directive.allow_data_uri
                }
                for name, directive in policy.csp_directives.items()
            },
            "custom_headers": policy.custom_headers,
            "excluded_paths": list(policy.excluded_paths)
        }
        
        return policy_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security policy"
        )


@router.get("/validate-current-headers")
async def validate_current_headers(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    headers_manager: EnhancedSecurityHeadersManager = Depends(get_enhanced_headers_manager)
):
    """Validate security headers that would be applied to current request"""
    try:
        # Get proposed headers
        test_response = Response()
        proposed_headers = headers_manager.get_headers_for_request(request, test_response)
        
        # Validate each header
        validation_results = {}
        
        for header_name, header_value in proposed_headers.items():
            if header_name in headers_manager.header_validators:
                is_valid = headers_manager.header_validators[header_name](header_value)
                validation_results[header_name] = {
                    "valid": is_valid,
                    "value": header_value,
                    "length": len(header_value)
                }
            else:
                # Basic validation
                is_safe = headers_manager._is_safe_header_value(header_value)
                validation_results[header_name] = {
                    "valid": is_safe,
                    "value": header_value,
                    "length": len(header_value)
                }
        
        # Calculate overall validation score
        total_headers = len(validation_results)
        valid_headers = sum(1 for result in validation_results.values() if result["valid"])
        validation_score = (valid_headers / total_headers * 100) if total_headers > 0 else 0
        
        return {
            "validation_score": validation_score,
            "total_headers": total_headers,
            "valid_headers": valid_headers,
            "invalid_headers": total_headers - valid_headers,
            "validation_results": validation_results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Header validation failed"
        )


@router.get("/security-events")
async def get_security_events(
    limit: int = 50,
    current_user: User = Depends(get_current_superuser),
):
    """Get recent security events for analysis (admin only)"""
    try:
        middleware = get_enhanced_headers_middleware()
        events = middleware.get_recent_security_events(limit)
        
        return {
            "events": events,
            "count": len(events),
            "limit": limit
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security events"
        )