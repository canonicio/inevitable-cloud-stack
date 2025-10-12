"""
Cookie Security API Routes for Platform Forge
Provides endpoints for managing cookie security and GDPR compliance

Features:
- Cookie consent management
- Security validation endpoints
- Cookie policy configuration
- Compliance reporting
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .database import get_db
from .deps import get_current_active_user
from ..auth.models import User
from .secure_cookie_manager import get_cookie_manager, CookieType, SecureCookieManager
from .enhanced_validators import SecureBaseModel

router = APIRouter(prefix="/api/cookie-security", tags=["cookie-security"])


class CookieConsentRequest(SecureBaseModel):
    """Cookie consent preferences"""
    essential: bool = Field(default=True, description="Essential cookies (always required)")
    preferences: bool = Field(default=False, description="Preference cookies")
    analytics: bool = Field(default=False, description="Analytics cookies")
    marketing: bool = Field(default=False, description="Marketing cookies")


class CookieSecurityReport(SecureBaseModel):
    """Cookie security assessment report"""
    total_cookies: int
    secure_cookies: int
    insecure_cookies: list
    security_score: float
    compliance_status: str
    recommendations: list


class CookiePolicyResponse(SecureBaseModel):
    """Cookie policy information"""
    categories: Dict[str, Any]
    privacy_policy_url: str
    cookie_policy_url: str
    consent_required: bool


@router.get("/policy", response_model=CookiePolicyResponse)
async def get_cookie_policy(
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Get cookie policy information for GDPR compliance"""
    banner_data = cookie_manager.generate_consent_banner_data()
    
    return CookiePolicyResponse(
        categories=banner_data["categories"],
        privacy_policy_url=banner_data["privacy_policy_url"],
        cookie_policy_url=banner_data["cookie_policy_url"],
        consent_required=True
    )


@router.post("/consent")
async def set_cookie_consent(
    consent: CookieConsentRequest,
    request: Request,
    response: Response,
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Set user cookie consent preferences"""
    try:
        preferences = {
            "essential": consent.essential,
            "preferences": consent.preferences,
            "analytics": consent.analytics,
            "marketing": consent.marketing
        }
        
        # Set consent cookie
        cookie_manager.set_consent_preferences(
            response=response,
            preferences=preferences,
            request=request
        )
        
        return {
            "success": True,
            "message": "Cookie consent preferences saved",
            "preferences": preferences
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to save consent preferences"
        )


@router.get("/consent")
async def get_cookie_consent(
    request: Request,
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Get current cookie consent preferences"""
    try:
        consent_data = cookie_manager.get_secure_cookie(
            request,
            "cookie_consent",
            CookieType.CONSENT,
            return_json=True
        )
        
        if not consent_data:
            return {
                "has_consent": False,
                "preferences": {
                    "essential": True,
                    "preferences": False,
                    "analytics": False,
                    "marketing": False
                }
            }
        
        return {
            "has_consent": True,
            "preferences": consent_data.get("preferences", {}),
            "timestamp": consent_data.get("timestamp"),
            "version": consent_data.get("version", "1.0")
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve consent preferences"
        )


@router.get("/security-report", response_model=CookieSecurityReport)
async def get_cookie_security_report(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Get comprehensive cookie security report (authenticated users only)"""
    try:
        validation_results = cookie_manager.validate_cookie_security(request)
        
        # Determine compliance status
        compliance_status = "compliant"
        if validation_results["security_score"] < 80:
            compliance_status = "needs_improvement"
        if validation_results["insecure_cookies"]:
            compliance_status = "non_compliant"
        
        return CookieSecurityReport(
            total_cookies=validation_results["total_cookies"],
            secure_cookies=validation_results["secure_cookies"],
            insecure_cookies=validation_results["insecure_cookies"],
            security_score=validation_results["security_score"],
            compliance_status=compliance_status,
            recommendations=validation_results["recommendations"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate security report"
        )


@router.post("/validate-cookie")
async def validate_cookie_security(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Validate security of all cookies in the request"""
    try:
        results = cookie_manager.validate_cookie_security(request)
        
        return {
            "validation_results": results,
            "is_compliant": len(results["insecure_cookies"]) == 0,
            "security_grade": _calculate_security_grade(results["security_score"])
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Cookie validation failed"
        )


@router.delete("/clear-cookies")
async def clear_all_cookies(
    response: Response,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Clear all non-essential cookies (authenticated users only)"""
    try:
        # List of cookies to clear (non-essential)
        cookies_to_clear = []
        
        for cookie_name in request.cookies.keys():
            # Keep essential cookies
            if cookie_name not in ["session", "csrf_token", "auth_token", "consent"]:
                cookies_to_clear.append(cookie_name)
                cookie_manager.delete_cookie(response, cookie_name)
        
        return {
            "success": True,
            "message": f"Cleared {len(cookies_to_clear)} cookies",
            "cleared_cookies": cookies_to_clear
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Failed to clear cookies"
        )


@router.get("/test-secure-cookie")
async def test_secure_cookie(
    request: Request,
    response: Response,
    cookie_manager: SecureCookieManager = Depends(get_cookie_manager)
):
    """Test endpoint to demonstrate secure cookie functionality"""
    try:
        # Set test cookies with different security policies
        test_cookies = [
            ("test_session", "test_session_value", CookieType.SESSION),
            ("test_preferences", {"theme": "dark", "lang": "en"}, CookieType.PREFERENCES),
            ("test_analytics", "analytics_data", CookieType.ANALYTICS)
        ]
        
        results = []
        for name, value, cookie_type in test_cookies:
            success = cookie_manager.set_secure_cookie(
                response=response,
                name=name,
                value=value,
                cookie_type=cookie_type,
                request=request
            )
            results.append({
                "cookie": name,
                "type": cookie_type.value,
                "set": success
            })
        
        return {
            "success": True,
            "message": "Test cookies set with security policies",
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail="Test cookie creation failed"
        )


def _calculate_security_grade(security_score: float) -> str:
    """Calculate security grade based on score"""
    if security_score >= 95:
        return "A+"
    elif security_score >= 90:
        return "A"
    elif security_score >= 80:
        return "B"
    elif security_score >= 70:
        return "C"
    elif security_score >= 60:
        return "D"
    else:
        return "F"