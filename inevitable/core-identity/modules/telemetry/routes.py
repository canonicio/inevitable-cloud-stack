"""
Telemetry API routes for generated applications
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from modules.core.database import get_db
from modules.auth.dependencies import get_current_user
from modules.auth.models import User
from .models import TelemetryConfig, UsageMetrics
from .client import TelemetryClient
from .services import TelemetryService

router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])


@router.get("/config")
async def get_telemetry_config(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get current telemetry configuration"""
    service = TelemetryService(db)
    config = await service.get_config(current_user.tenant_id)
    
    return {
        "enabled": config.enabled,
        "mode": config.mode,
        "privacy_mode": config.privacy_mode,
        "consent_required": config.mode != "none",
        "data_collected": await service.get_collected_data_types(config.privacy_mode)
    }


@router.post("/consent")
async def update_consent(
    consent: bool,
    purpose: str = "telemetry",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Update user's consent for telemetry collection"""
    service = TelemetryService(db)
    await service.update_consent(current_user.id, purpose, consent)
    
    return {
        "user_id": current_user.id,
        "purpose": purpose,
        "consent": consent,
        "updated": True
    }


@router.get("/consent")
async def get_consent_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get user's consent status"""
    service = TelemetryService(db)
    status = await service.get_consent_status(current_user.id)
    
    return status


@router.post("/export")
async def export_telemetry(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Export telemetry data (for airgapped environments)"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can export telemetry"
        )
    
    service = TelemetryService(db)
    export_path = await service.export_telemetry(current_user.tenant_id)
    
    return {
        "status": "exported",
        "path": export_path,
        "instructions": "Transfer this file to your control center for upload"
    }


@router.get("/metrics/current")
async def get_current_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> UsageMetrics:
    """Get current usage metrics (privacy-filtered)"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view metrics"
        )
    
    service = TelemetryService(db)
    metrics = await service.get_current_metrics(current_user.tenant_id)
    
    return metrics


@router.post("/test")
async def test_telemetry(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Test telemetry connection"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can test telemetry"
        )
    
    service = TelemetryService(db)
    result = await service.test_connection()
    
    return result