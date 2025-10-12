"""
Enhanced Admin Routes with Dynamic CRUD and Modern UI
Integrates the CRUD generator and UI components
"""
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, validator
from modules.core.enhanced_validators import SecureBaseModel, APIParameterValidator
from modules.core.database import get_db
from modules.auth.dependencies import get_current_user
from modules.auth.rbac import require_permissions, Permission
from modules.admin.audit_logs import SecureAuditService as AuditService
from modules.admin.crud_generator import crud_generator
from modules.admin.ui_components import ui_generator
from modules.admin.mfa import setup_mfa, enable_mfa, disable_mfa
from modules.core.secure_search import secure_user_search
from modules.core.authorization import AuthorizationService
import json


# Create main admin router
router = APIRouter(prefix="/admin", tags=["admin"])

# Include UI routes
router.include_router(ui_generator.router)

# Include existing MFA routes from original routes.py
class MFASetupResponse(SecureBaseModel):
    secret: str
    qr_code: str
    message: str

    @validator('message')
    def validate_message(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'message')
                        return v

class MFATokenRequest(SecureBaseModel):
    token: str

class MFAResponse(SecureBaseModel):
    message: str
    backup_codes: Optional[List[str]] = None

    @validator('message')
    def validate_message(cls, v):
                        if v:
                            return APIParameterValidator.validate_no_injection(v, 'message')
                        return v

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_user_mfa(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initialize MFA setup for the current user"""
    result = await setup_mfa(current_user.id, db)
    return result

@router.post("/mfa/enable", response_model=MFAResponse)
async def enable_user_mfa(
    token_request: MFATokenRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enable MFA for the current user"""
    result = await enable_mfa(current_user.id, token_request.token, db)
    
    await AuditService.log_action(
        action="mfa_enabled",
        user_id=current_user.id,
        resource_type="user",
        resource_id=str(current_user.id),
        request=request,
        db=db
    )
    
    return result

@router.post("/mfa/disable", response_model=MFAResponse)
async def disable_user_mfa(
    token_request: MFATokenRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable MFA for the current user"""
    result = await disable_mfa(current_user.id, token_request.token, db)
    
    await AuditService.log_action(
        action="mfa_disabled",
        user_id=current_user.id,
        resource_type="user",
        resource_id=str(current_user.id),
        request=request,
        db=db
    )
    
    return result


# Dynamic CRUD API endpoints
@router.get("/api/metadata")
async def get_admin_metadata(
    current_user = Depends(get_current_user)
):
    """Get admin metadata for UI generation"""
    return crud_generator.get_admin_metadata()


@router.get("/api/stats")
async def get_admin_stats(
    current_user = Depends(require_permissions([Permission.ADMIN_PANEL.value])),
    db: Session = Depends(get_db)
):
    """Get admin dashboard statistics - CRITICAL FIX: Tenant-filtered statistics only"""
    from modules.auth.models import User
    
    # CRITICAL FIX: Always filter statistics by current user's tenant
    if not current_user.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access required")
    
    # Get user statistics ONLY for current tenant
    total_users = db.query(User).filter(User.tenant_id == current_user.tenant_id).count()
    active_users = db.query(User).filter(
        User.tenant_id == current_user.tenant_id,
        User.is_active == True
    ).count()
    
    # Get recent activity count ONLY for current tenant
    recent_activity = db.query(AuditService.model).filter(
        AuditService.model.tenant_id == current_user.tenant_id
    ).count() if hasattr(AuditService.model, 'tenant_id') else 0
    
    # Mock some additional stats (would be real in production)
    stats = {
        "totalUsers": total_users,
        "activeUsers": active_users,
        "activeSessions": active_users,  # Simplified
        "securityAlerts": 2,  # Mock data
        "systemHealth": 99.9
    }
    
    return stats


# Generate and include dynamic CRUD routes
def setup_dynamic_routes(modules: List[str]):
    """Setup dynamic CRUD routes for all discovered models"""
    
    # Generate CRUD routers for all models
    crud_routers = crud_generator.generate_all_crud_routers(modules)
    
    # Include each CRUD router
    for model_key, crud_router in crud_routers.items():
        # Add the CRUD router under /api/admin/ prefix
        router.include_router(crud_router, prefix="/api")
        
        # Add count endpoint for each model
        config = crud_generator.configs[model_key]
        model = crud_generator.models[model_key]
        
        @router.get(f"/api/{config.table_name}/count")
        async def get_model_count(
            current_user = Depends(get_current_user),
            db: Session = Depends(get_db),
            _model=model  # Capture model in closure
        ):
            """Get count for a specific model"""
            try:
                count = db.query(_model).count()
                return {"count": count}
            except Exception as e:
                return {"count": 0}


# System management endpoints
@router.get("/api/system/health")
async def get_system_health(
    current_user = Depends(require_permissions([Permission.ADMIN_PANEL.value]))
):
    """Get system health status"""
    # Mock system health data
    return {
        "database": {"status": "healthy", "response_time": "15ms"},
        "api": {"status": "online", "response_time": "8ms"},
        "security": {"status": "protected", "last_scan": "2024-01-15T10:30:00Z"},
        "backups": {"status": "current", "last_backup": "2024-01-15T02:00:00Z"}
    }


@router.get("/api/security/alerts")
async def get_security_alerts(
    current_user = Depends(require_permissions([Permission.ADMIN_SETTINGS.value])),
    limit: int = Query(10, ge=1, le=100)
):
    """Get security alerts"""
    # Mock security alerts data
    alerts = [
        {
            "id": 1,
            "type": "suspicious_login",
            "message": "Multiple failed login attempts from 192.168.1.100",
            "severity": "medium",
            "timestamp": "2024-01-15T14:30:00Z",
            "status": "open"
        },
        {
            "id": 2,
            "type": "unusual_activity",
            "message": "Unusual API usage pattern detected",
            "severity": "low",
            "timestamp": "2024-01-15T13:45:00Z",
            "status": "investigating"
        }
    ]
    
    return alerts[:limit]


# User management endpoints (enhanced from original)
@router.get("/api/users")
async def get_users_api(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    search: Optional[str] = Query(None),
    current_user = Depends(require_permissions([Permission.USERS_READ.value])),
    db: Session = Depends(get_db)
):
    """Enhanced user list API with pagination and search"""
    from modules.auth.models import User
    
    query = db.query(User)
    
    # CRITICAL-004 FIX: Apply secure search to prevent SQL injection
    # Replaces vulnerable f-string formatting with parameterized queries
    if search:
        query = secure_user_search(query, search)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    users = query.offset(offset).limit(page_size).all()
    
    # Log access
    await AuditService.log_action(
        action="users_api_accessed",
        user_id=current_user.id,
        resource_type="users",
        details={
            "page": page,
            "page_size": page_size,
            "search": search,
            "total_results": total
        },
        request=request,
        db=db
    )
    
    # Format user data
    user_data = [
        {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "mfa_enabled": user.mfa_enabled,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
            "tenant_id": user.tenant_id
        }
        for user in users
    ]
    
    return {
        "items": user_data,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    }


@router.put("/api/users/{user_id}/status")
async def update_user_status_api(
    user_id: int,
    status_data: Dict[str, bool],
    request: Request,
    current_user = Depends(require_permissions([Permission.USERS_STATUS.value])),
    db: Session = Depends(get_db)
):
    """
    Update user status via API with IDOR protection.
    CRITICAL-008 FIX: Added authorization check to prevent IDOR vulnerability
    """
    from modules.auth.models import User
    
    # CRITICAL FIX: Use authorization service to prevent IDOR
    # This ensures the current user can only modify users within their tenant/scope
    user = AuthorizationService.check_resource_access(
        db=db,
        model=User,
        resource_id=user_id,
        user=current_user,
        operation="update"
    )
    
    old_status = user.is_active
    user.is_active = status_data.get("is_active", user.is_active)
    db.commit()
    
    await AuditService.log_action(
        action="user_status_updated",
        user_id=current_user.id,
        resource_type="user",
        resource_id=str(user_id),
        details={
            "old_status": old_status,
            "new_status": user.is_active,
            "target_user_email": user.email
        },
        request=request,
        db=db
    )
    
    return {
        "message": f"User {'activated' if user.is_active else 'deactivated'} successfully",
        "user": {
            "id": user.id,
            "email": user.email,
            "is_active": user.is_active
        }
    }


# Audit logs API (enhanced from original)
@router.get("/api/audit-logs")
async def get_audit_logs_api(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    action_filter: Optional[str] = Query(None),
    resource_type_filter: Optional[str] = Query(None),
    current_user = Depends(require_permissions([Permission.AUDIT_READ.value])),
    db: Session = Depends(get_db)
):
    """Enhanced audit logs API with pagination and filtering"""
    
    logs = await AuditService.get_all_audit_logs(
        limit=page_size,
        offset=(page - 1) * page_size,
        action_filter=action_filter,
        resource_type_filter=resource_type_filter,
        db=db
    )
    
    # Get total count (simplified for now)
    total = len(logs) if len(logs) < page_size else (page * page_size) + 1
    
    await AuditService.log_action(
        action="audit_logs_api_accessed",
        user_id=current_user.id,
        resource_type="audit_logs",
        details={
            "page": page,
            "page_size": page_size,
            "action_filter": action_filter,
            "resource_type_filter": resource_type_filter
        },
        request=request,
        db=db
    )
    
    return {
        "items": logs,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size
    }


# Settings management
@router.get("/api/settings")
async def get_system_settings(
    current_user = Depends(require_permissions([Permission.ADMIN_PANEL.value])),
    db: Session = Depends(get_db)
):
    """Get system settings"""
    from modules.admin.models import SystemSetting
    
    settings = db.query(SystemSetting).all()
    
    return [
        {
            "id": setting.id,
            "key": setting.key,
            "value": setting.value if not setting.is_encrypted else "***encrypted***",
            "description": setting.description,
            "is_encrypted": setting.is_encrypted,
            "updated_at": setting.updated_at.isoformat()
        }
        for setting in settings
    ]


@router.post("/api/settings")
async def create_system_setting(
    setting_data: Dict[str, Any],
    request: Request,
    current_user = Depends(require_permissions([Permission.ADMIN_SETTINGS.value])),
    db: Session = Depends(get_db)
):
    """Create new system setting"""
    from modules.admin.models import SystemSetting
    
    new_setting = SystemSetting(
        key=setting_data["key"],
        value=setting_data["value"],
        description=setting_data.get("description"),
        is_encrypted=setting_data.get("is_encrypted", False),
        modified_by=current_user.id
    )
    
    db.add(new_setting)
    db.commit()
    db.refresh(new_setting)
    
    await AuditService.log_action(
        action="system_setting_created",
        user_id=current_user.id,
        resource_type="system_setting",
        resource_id=str(new_setting.id),
        details={"key": new_setting.key},
        request=request,
        db=db
    )
    
    return {
        "message": "Setting created successfully",
        "setting": {
            "id": new_setting.id,
            "key": new_setting.key,
            "value": new_setting.value,
            "description": new_setting.description
        }
    }


# Initialize dynamic routes when the module is imported
# This will be called by the main app factory
def init_admin_routes(enabled_modules: List[str]):
    """Initialize admin routes with dynamic CRUD for enabled modules"""
    setup_dynamic_routes(enabled_modules)
    return router