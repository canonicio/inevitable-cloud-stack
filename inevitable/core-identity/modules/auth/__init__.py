"""
Authentication and Authorization Module
"""
from .routes import router as auth_router
from .rbac_routes import router as rbac_router
from .models import User, Role, Permission
from .service import auth_service
from .permissions import permission_service, require_permission

# Combine routers
from fastapi import APIRouter

router = APIRouter()
router.include_router(auth_router)
router.include_router(rbac_router)

__all__ = [
    "router",
    "User",
    "Role",
    "Permission",
    "auth_service",
    "permission_service",
    "require_permission"
]