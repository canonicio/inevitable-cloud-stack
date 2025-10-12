"""
Platform Forge Admin Module
Enhanced with Dynamic CRUD Generation and Modern UI
"""

from .crud_generator import crud_generator, CRUDGenerator, CRUDConfig, FieldConfig
from .ui_components import ui_generator, AdminUIGenerator, NavigationItem, CardConfig
from .enhanced_routes import init_admin_routes
from .audit_logs import SecureAuditService
from .mfa import get_mfa_service
from .crud_security import FieldSecurity, TenantSecurity, CRUDSecurityMonitor, SecureCRUDHelper

# Version info
__version__ = "2.0.0"
__description__ = "Enhanced admin module with dynamic CRUD and modern UI"

# Export main components
__all__ = [
    "crud_generator",
    "CRUDGenerator", 
    "CRUDConfig",
    "FieldConfig",
    "ui_generator",
    "AdminUIGenerator",
    "NavigationItem", 
    "CardConfig",
    "init_admin_routes",
    "AuditService",
    "setup_mfa",
    "enable_mfa", 
    "disable_mfa",
    "verify_mfa",
    "FieldSecurity",
    "TenantSecurity",
    "CRUDSecurityMonitor",
    "SecureCRUDHelper"
]