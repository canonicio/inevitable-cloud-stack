"""
PRISM Intelligence Proxy Module for Platform Forge
Provides seamless integration between Platform Forge and PRISM Analysis engines
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional
import aiohttp
import os
import logging
from pydantic import BaseModel, Field

from ..auth.dependencies import get_current_user
from ..auth.models import User
from ..mcp_auth.safety.orchestrator import SafetyOrchestrator, SafetyAPI

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/prism", tags=["PRISM Analysis"])

# Configuration
PRISM_URL = os.getenv("PRISM_URL", "http://localhost:8001")
PRISM_INTERNAL_KEY = os.getenv("PRISM_INTERNAL_KEY", "pk_internal_platform_forge_2025")

# Initialize safety layer (Platform Forge's first line of defense)
safety_orchestrator = SafetyOrchestrator(strict_mode=True)
safety_api = SafetyAPI(strict_mode=True)

# Request models
class BeliefAnalysisRequest(BaseModel):
    """Request model for belief analysis"""
    question: str = Field(..., description="The question or topic for epistemic analysis")
    cultural_perspectives: list[str] = Field(
        default=["western_business"],
        description="Cultural perspectives to analyze"
    )
    domain_focus: str = Field(default="strategic", description="Domain focus for analysis")
    analysis_depth: str = Field(default="standard", description="Analysis depth: quick, standard, comprehensive")
    include_stakeholder_analysis: bool = Field(default=True, description="Include WithPI stakeholder behavior analysis")
    include_causal_insights: bool = Field(default=True, description="Include CausalLattice integration")
    include_interventions: bool = Field(default=False, description="Include intervention recommendations")
    max_belief_shards: int = Field(default=10, description="Maximum number of belief shards to generate")
    confidence_threshold: float = Field(default=0.6, description="Minimum confidence threshold")


class CausalAnalysisRequest(BaseModel):
    """Request model for causal analysis"""
    question: str = Field(..., description="Question for causal analysis")
    context: Optional[str] = Field(None, description="Additional context")
    analysis_type: str = Field(default="comprehensive", description="Type: basic, ensemble, comprehensive")
    output_format: str = Field(default="executive", description="Format: simple, detailed, executive, technical, api")
    include_interventions: bool = Field(default=True, description="Include intervention analysis")
    max_depth: int = Field(default=3, description="Maximum causal depth")
    confidence_threshold: float = Field(default=0.7, description="Minimum confidence threshold")


# Universal proxy endpoint
@router.post("/{endpoint:path}")
async def prism_proxy(
    endpoint: str,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """
    Universal proxy to PRISM endpoints with authentication passthrough.
    Maps Platform Forge authentication to PRISM's internal API key.
    """

    try:
        # Get request body
        request_body = await request.json()

        # Check for internal bypass flag (for trusted internal services)
        # This allows Platform Forge's own analysis services to call PRISM without double-screening
        bypass_security = request.headers.get("X-Internal-Bypass") == PRISM_INTERNAL_KEY

        # SECURITY LAYER 1: Platform Forge SafetyOrchestrator
        # Apply prompt injection defense as first layer of protection
        # Especially critical for the dangerous BeliefLattice /analyze endpoint
        if not bypass_security and (endpoint == "belief/analyze" or endpoint == "epistemic/analyze"):
            # This is the DANGEROUS endpoint - apply strictest security
            logger.warning(f"High-risk BeliefLattice /analyze request from {current_user.email}")

            # Extract the question/prompt from request
            prompt_text = request_body.get("question", "")
            if prompt_text:
                # Process through Platform Forge's safety pipeline
                routing, blob = safety_orchestrator.process_content(
                    text=prompt_text,
                    source="api_request",
                    tenant_id=current_user.tenant_id,
                    author_id=str(current_user.id)
                )

                # Check if request should be blocked
                if routing["action"] == "reject":
                    logger.error(f"Blocked dangerous prompt from {current_user.email}: {routing.get('reason')}")
                    raise HTTPException(
                        status_code=400,
                        detail=f"Request blocked by security: {routing.get('reason', 'Potential prompt injection detected')}"
                    )
                elif routing["action"] == "require_human_review":
                    logger.warning(f"Quarantined prompt from {current_user.email} for review")
                    raise HTTPException(
                        status_code=403,
                        detail="Request requires human review before processing"
                    )

                # Replace with sanitized version if modified
                if blob and blob.sanitized_text != prompt_text:
                    request_body["question"] = blob.sanitized_text
                    logger.info(f"Sanitized prompt for {current_user.email}")

        # Apply lighter security check for other endpoints (unless bypassed)
        elif not bypass_security and ("question" in request_body or "prompt" in request_body or "query" in request_body):
            prompt_field = "question" if "question" in request_body else ("prompt" if "prompt" in request_body else "query")
            prompt_text = request_body.get(prompt_field, "")

            if prompt_text:
                # Quick safety check for non-critical endpoints
                safety_result = safety_api.check_prompt(prompt_text, current_user.tenant_id)

                if not safety_result["safe"] and safety_result["threat_level"] in ["high", "critical"]:
                    logger.warning(f"Blocked potentially unsafe prompt from {current_user.email}")
                    raise HTTPException(
                        status_code=400,
                        detail=f"Request blocked: {safety_result.get('reason', 'Security violation detected')}"
                    )

        # Map the endpoints correctly
        url_mappings = {
            "belief/analyze": f"{PRISM_URL}/api/belief/analyze",
            "epistemic/analyze": f"{PRISM_URL}/api/belief/analyze",  # Alias
            "causal/analyze": f"{PRISM_URL}/api/causal/analyze",
            "belief/interpret": f"{PRISM_URL}/api/belief/interpret",
            "belief/trace": f"{PRISM_URL}/api/belief/trace",
            "belief/what-if": f"{PRISM_URL}/api/belief/what-if",
            "causal/interventions": f"{PRISM_URL}/api/causal/interventions",
            "causal/replay": f"{PRISM_URL}/api/causal/replay",
        }

        # Get the mapped URL or use default
        if endpoint in url_mappings:
            url = url_mappings[endpoint]
        else:
            # Default passthrough for unmapped endpoints
            url = f"{PRISM_URL}/api/{endpoint}"

        logger.info(f"Proxying request from user {current_user.email} to {url}")

        # Make the request to PRISM with full user context
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=request_body,
                headers={
                    "X-API-Key": PRISM_INTERNAL_KEY,
                    "X-Forwarded-For": request.client.host if request.client else "unknown",
                    "X-Original-User": current_user.email,
                    "X-User-Id": str(current_user.id),
                    "X-Tenant-Id": current_user.tenant_id,
                    "X-Is-Admin": "true" if hasattr(current_user, 'is_admin') and current_user.is_admin else "false",
                    "X-Is-Superadmin": "true" if hasattr(current_user, 'is_superadmin') and current_user.is_superadmin else "false",
                    "X-Security-Screened": "false" if bypass_security else "true",  # Indicate if security was applied
                    "X-Security-Layer": "bypassed" if bypass_security else "platform-forge",  # Identify security layer
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=120)  # 2 minute timeout for complex analyses
            ) as response:
                response_data = await response.json()

                if response.status != 200:
                    logger.error(f"PRISM returned error {response.status}: {response_data}")
                    raise HTTPException(
                        status_code=response.status,
                        detail=response_data.get("detail", "PRISM analysis failed")
                    )

                # Add metadata about the proxy and verify tenant isolation
                if isinstance(response_data, dict):
                    # Check if response contains tenant_id and verify it matches
                    if "tenant_id" in response_data and response_data["tenant_id"] != current_user.tenant_id:
                        # Only superadmins can see cross-tenant data
                        if not (hasattr(current_user, 'is_superadmin') and current_user.is_superadmin):
                            logger.error(f"Tenant isolation violation: User {current_user.email} (tenant {current_user.tenant_id}) received data from tenant {response_data['tenant_id']}")
                            raise HTTPException(
                                status_code=403,
                                detail="Tenant isolation violation detected"
                            )

                    response_data["_proxy_metadata"] = {
                        "proxied_by": "platform-forge",
                        "user": current_user.email,
                        "tenant_id": current_user.tenant_id,
                        "enforced_isolation": True
                    }

                return response_data

    except aiohttp.ClientError as e:
        logger.error(f"Connection error to PRISM: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"PRISM service unavailable: {str(e)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in PRISM proxy: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal proxy error: {str(e)}"
        )


# Specific endpoint for belief analysis with validation
@router.post("/belief/analyze")
async def analyze_belief(
    request: BeliefAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze beliefs and cultural perspectives through PRISM BeliefLattice.
    This endpoint provides type-safe access to belief analysis.
    DANGEROUS: Requires superadmin privileges and strict security screening.
    """

    # Only superadmins can use this dangerous endpoint
    if not (hasattr(current_user, 'is_superadmin') and current_user.is_superadmin):
        raise HTTPException(
            status_code=403,
            detail="Superadmin privileges required for BeliefLattice analysis"
        )

    # SECURITY LAYER 1: Platform Forge SafetyOrchestrator
    logger.warning(f"High-risk BeliefLattice /analyze request from superadmin {current_user.email}")

    # Apply strictest security even for superadmins
    routing, blob = safety_orchestrator.process_content(
        text=request.question,
        source="belief_analysis",
        tenant_id=current_user.tenant_id,
        author_id=str(current_user.id)
    )

    if routing["action"] == "reject":
        logger.error(f"Blocked dangerous belief analysis from {current_user.email}")
        raise HTTPException(
            status_code=400,
            detail=f"Request blocked by security: {routing.get('reason', 'Dangerous prompt detected')}"
        )

    # Use sanitized version if modified
    if blob and blob.sanitized_text != request.question:
        request.question = blob.sanitized_text
        logger.info(f"Sanitized belief analysis prompt for {current_user.email}")

    url = f"{PRISM_URL}/api/belief/analyze"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=request.dict(),
                headers={
                    "X-API-Key": PRISM_INTERNAL_KEY,
                    "X-Original-User": current_user.email,
                    "X-User-Id": str(current_user.id),
                    "X-Tenant-Id": current_user.tenant_id,
                    "X-Is-Admin": "true" if hasattr(current_user, 'is_admin') and current_user.is_admin else "false",
                    "X-Is-Superadmin": "true" if hasattr(current_user, 'is_superadmin') and current_user.is_superadmin else "false",
                    "X-Security-Screened": "true",  # Platform Forge security applied
                    "X-Security-Layer": "platform-forge",
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=120)
            ) as response:
                response_data = await response.json()

                if response.status != 200:
                    raise HTTPException(
                        status_code=response.status,
                        detail=response_data.get("detail", "Belief analysis failed")
                    )

                return response_data

    except Exception as e:
        logger.error(f"Belief analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Belief analysis failed: {str(e)}"
        )


# Specific endpoint for causal analysis with validation
@router.post("/causal/analyze")
async def analyze_causal(
    request: CausalAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Perform causal analysis through PRISM CausalLattice.
    This endpoint provides type-safe access to causal analysis.
    """

    url = f"{PRISM_URL}/api/causal/analyze"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=request.dict(),
                headers={
                    "X-API-Key": PRISM_INTERNAL_KEY,
                    "X-Original-User": current_user.email,
                    "X-User-Id": str(current_user.id),
                    "X-Tenant-Id": current_user.tenant_id,
                    "X-Is-Admin": "true" if hasattr(current_user, 'is_admin') and current_user.is_admin else "false",
                    "X-Is-Superadmin": "true" if hasattr(current_user, 'is_superadmin') and current_user.is_superadmin else "false",
                    "X-Security-Screened": "true",  # Platform Forge security applied
                    "X-Security-Layer": "platform-forge",
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=120)
            ) as response:
                response_data = await response.json()

                if response.status != 200:
                    raise HTTPException(
                        status_code=response.status,
                        detail=response_data.get("detail", "Causal analysis failed")
                    )

                return response_data

    except Exception as e:
        logger.error(f"Causal analysis error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Causal analysis failed: {str(e)}"
        )


# Health check for PRISM connectivity
@router.get("/health")
async def prism_health_check(
    current_user: User = Depends(get_current_user)
):
    """
    Check PRISM service health and connectivity.
    """

    health_status = {
        "platform_forge": "healthy",
        "prism_url": PRISM_URL,
        "authenticated_as": current_user.email
    }

    try:
        # Check BeliefLattice health
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{PRISM_URL}/api/belief/health",
                headers={"X-API-Key": PRISM_INTERNAL_KEY},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    belief_health = await response.json()
                    health_status["belief_lattice"] = belief_health
                else:
                    health_status["belief_lattice"] = {"status": "unhealthy", "code": response.status}
    except Exception as e:
        health_status["belief_lattice"] = {"status": "unreachable", "error": str(e)}

    try:
        # Check CausalLattice health
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{PRISM_URL}/api/causal/health",
                headers={"X-API-Key": PRISM_INTERNAL_KEY},
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    causal_health = await response.json()
                    health_status["causal_lattice"] = causal_health
                else:
                    health_status["causal_lattice"] = {"status": "unhealthy", "code": response.status}
    except Exception as e:
        health_status["causal_lattice"] = {"status": "unreachable", "error": str(e)}

    # Determine overall health
    if (health_status.get("belief_lattice", {}).get("status") == "healthy" and
        health_status.get("causal_lattice", {}).get("status") == "healthy"):
        health_status["overall"] = "healthy"
    else:
        health_status["overall"] = "degraded"

    return health_status


# Security metrics endpoint
@router.get("/security/metrics")
async def get_security_metrics(
    current_user: User = Depends(get_current_user)
):
    """
    Get security metrics showing both Platform Forge and PRISM security layers.
    Requires admin privileges to view security metrics.
    """

    # Check admin privileges
    if not (hasattr(current_user, 'is_admin') and current_user.is_admin):
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required to view security metrics"
        )

    # Get Platform Forge metrics (Layer 1)
    platform_forge_metrics = safety_orchestrator.get_metrics()

    # Try to get PRISM metrics (Layer 2)
    prism_metrics = {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{PRISM_URL}/api/security/metrics",
                headers={
                    "X-API-Key": PRISM_INTERNAL_KEY,
                    "X-Original-User": current_user.email,
                    "X-User-Id": str(current_user.id),
                    "X-Tenant-Id": current_user.tenant_id,
                    "X-Is-Admin": "true",
                    "X-Is-Superadmin": str(hasattr(current_user, 'is_superadmin') and current_user.is_superadmin).lower()
                },
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    prism_metrics = await response.json()
    except Exception as e:
        logger.warning(f"Could not fetch PRISM security metrics: {e}")
        prism_metrics = {"status": "unavailable", "error": str(e)}

    return {
        "security_layers": {
            "layer_1": {
                "name": "Platform Forge SafetyOrchestrator",
                "status": "active",
                "metrics": platform_forge_metrics
            },
            "layer_2": {
                "name": "PRISM Security (PromptInjectionDefense + InputSanitizer)",
                "status": "active" if prism_metrics else "unknown",
                "metrics": prism_metrics
            }
        },
        "configuration": {
            "strict_mode": safety_orchestrator.gate.strict_mode,
            "belief_analyze_protection": "MAXIMUM - Superadmin only + dual layer screening",
            "other_endpoints_protection": "STANDARD - Regular users allowed + security screening"
        },
        "threat_summary": {
            "requests_blocked_layer_1": platform_forge_metrics.get("high_risk_blocked", 0),
            "requests_quarantined_layer_1": platform_forge_metrics.get("quarantined", 0),
            "requests_sanitized_layer_1": platform_forge_metrics.get("data_only", 0),
            "total_processed": platform_forge_metrics.get("total_processed", 0)
        }
    }


# Guatemala-specific analysis endpoint
@router.post("/guatemala/analyze")
async def analyze_guatemala_market(
    current_user: User = Depends(get_current_user)
):
    """
    Special endpoint for Guatemala asphalt market analysis.
    Combines belief and causal analysis for comprehensive insights.
    """

    guatemala_question = "Analyze Guatemala asphalt market dynamics after Perenco exit and potential entry strategies"

    results = {
        "analysis_id": "guatemala_market_analysis",
        "user": current_user.email,
        "question": guatemala_question
    }

    # Run belief analysis
    try:
        belief_request = BeliefAnalysisRequest(
            question=guatemala_question,
            cultural_perspectives=["latin_american_business", "western_business", "local_guatemala"],
            domain_focus="strategic",
            analysis_depth="comprehensive",
            include_stakeholder_analysis=True,
            include_causal_insights=True,
            include_interventions=True
        )

        results["belief_analysis"] = await analyze_belief(belief_request, current_user)
    except Exception as e:
        logger.error(f"Guatemala belief analysis failed: {e}")
        results["belief_analysis"] = {"error": str(e)}

    # Run causal analysis
    try:
        causal_request = CausalAnalysisRequest(
            question=guatemala_question,
            context="Focus on market dynamics, regulatory environment, and competitive landscape",
            analysis_type="comprehensive",
            output_format="executive",
            include_interventions=True
        )

        results["causal_analysis"] = await analyze_causal(causal_request, current_user)
    except Exception as e:
        logger.error(f"Guatemala causal analysis failed: {e}")
        results["causal_analysis"] = {"error": str(e)}

    return results