"""
Modern UI Components for Platform Forge Admin
Left Navigation + Stacked Cards Interface
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from modules.auth.dependencies import get_current_user
from modules.admin.crud_generator import crud_generator
import json


@dataclass
class NavigationItem:
    """Navigation item for left sidebar"""
    id: str
    label: str
    icon: str
    url: str
    badge: Optional[str] = None
    children: List['NavigationItem'] = None


@dataclass
class CardConfig:
    """Configuration for a stacked card"""
    id: str
    title: str
    subtitle: Optional[str] = None
    icon: str = "table"
    color: str = "blue"
    actions: List[Dict[str, str]] = None
    data_source: Optional[str] = None
    card_type: str = "list"  # list, form, chart, stats


class AdminUIGenerator:
    """Generates modern admin UI with left navigation and stacked cards"""
    
    def __init__(self):
        self.templates = Jinja2Templates(directory="modules/admin/templates")
        self.router = APIRouter(prefix="/admin", tags=["admin-ui"])
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup UI routes"""
        
        @self.router.get("/", response_class=HTMLResponse)
        async def admin_dashboard(
            request: Request,
            current_user = Depends(get_current_user)
        ):
            """Main admin dashboard"""
            navigation = self._build_navigation()
            cards = self._build_dashboard_cards()
            
            return self.templates.TemplateResponse("admin/dashboard.html", {
                "request": request,
                "user": current_user,
                "navigation": navigation,
                "cards": cards,
                "page_title": "Dashboard",
                "active_section": "dashboard"
            })
        
        @self.router.get("/models/{model_key}", response_class=HTMLResponse)
        async def model_list_view(
            model_key: str,
            request: Request,
            current_user = Depends(get_current_user)
        ):
            """Model list view with stacked cards"""
            if model_key not in crud_generator.configs:
                raise HTTPException(status_code=404, detail="Model not found")
            
            config = crud_generator.configs[model_key]
            navigation = self._build_navigation()
            
            return self.templates.TemplateResponse("admin/model_list.html", {
                "request": request,
                "user": current_user,
                "navigation": navigation,
                "model_config": config,
                "model_key": model_key,
                "page_title": config.display_name,
                "active_section": model_key
            })
        
        @self.router.get("/models/{model_key}/create", response_class=HTMLResponse)
        async def model_create_view(
            model_key: str,
            request: Request,
            current_user = Depends(get_current_user)
        ):
            """Model create form view"""
            if model_key not in crud_generator.configs:
                raise HTTPException(status_code=404, detail="Model not found")
            
            config = crud_generator.configs[model_key]
            navigation = self._build_navigation()
            
            return self.templates.TemplateResponse("admin/model_form.html", {
                "request": request,
                "user": current_user,
                "navigation": navigation,
                "model_config": config,
                "model_key": model_key,
                "form_mode": "create",
                "page_title": f"Create {config.display_name}",
                "active_section": model_key
            })
        
        @self.router.get("/models/{model_key}/{item_id}/edit", response_class=HTMLResponse)
        async def model_edit_view(
            model_key: str,
            item_id: int,
            request: Request,
            current_user = Depends(get_current_user)
        ):
            """Model edit form view"""
            if model_key not in crud_generator.configs:
                raise HTTPException(status_code=404, detail="Model not found")
            
            config = crud_generator.configs[model_key]
            navigation = self._build_navigation()
            
            return self.templates.TemplateResponse("admin/model_form.html", {
                "request": request,
                "user": current_user,
                "navigation": navigation,
                "model_config": config,
                "model_key": model_key,
                "item_id": item_id,
                "form_mode": "edit",
                "page_title": f"Edit {config.display_name}",
                "active_section": model_key
            })
        
        @self.router.get("/api/metadata", response_model=Dict[str, Any])
        async def get_admin_metadata(
            current_user = Depends(get_current_user)
        ):
            """Get admin metadata for UI generation"""
            return crud_generator.get_admin_metadata()
    
    def _build_navigation(self) -> List[NavigationItem]:
        """Build left navigation structure"""
        navigation = [
            NavigationItem(
                id="dashboard",
                label="Dashboard",
                icon="home",
                url="/admin/"
            ),
            NavigationItem(
                id="users",
                label="User Management",
                icon="users",
                url="#",
                children=[
                    NavigationItem(
                        id="users_list",
                        label="All Users",
                        icon="user",
                        url="/admin/users"
                    ),
                    NavigationItem(
                        id="roles",
                        label="Roles & Permissions",
                        icon="shield",
                        url="/admin/roles"
                    )
                ]
            )
        ]
        
        # Add dynamic model navigation
        metadata = crud_generator.get_admin_metadata()
        for nav_group in metadata.get("navigation", []):
            module_name = nav_group["module"]
            models = nav_group["models"]
            
            if models:
                children = []
                for model in models:
                    children.append(NavigationItem(
                        id=model["key"],
                        label=model["name"],
                        icon="table",
                        url=f"/admin/models/{model['key']}"
                    ))
                
                navigation.append(NavigationItem(
                    id=f"module_{module_name.lower()}",
                    label=module_name,
                    icon="box",
                    url="#",
                    children=children
                ))
        
        # Add system navigation
        navigation.extend([
            NavigationItem(
                id="system",
                label="System",
                icon="settings",
                url="#",
                children=[
                    NavigationItem(
                        id="audit_logs",
                        label="Audit Logs",
                        icon="file-text",
                        url="/admin/audit-logs"
                    ),
                    NavigationItem(
                        id="system_settings",
                        label="Settings",
                        icon="cog",
                        url="/admin/settings"
                    ),
                    NavigationItem(
                        id="backup_jobs",
                        label="Backups",
                        icon="download",
                        url="/admin/backups"
                    ),
                    NavigationItem(
                        id="feature_flags",
                        label="Feature Flags",
                        icon="flag",
                        url="/admin/feature-flags"
                    )
                ]
            ),
            NavigationItem(
                id="security",
                label="Security",
                icon="lock",
                url="#",
                children=[
                    NavigationItem(
                        id="api_keys",
                        label="API Keys",
                        icon="key",
                        url="/admin/api-keys"
                    ),
                    NavigationItem(
                        id="maintenance",
                        label="Maintenance Mode",
                        icon="tool",
                        url="/admin/maintenance"
                    )
                ]
            )
        ])
        
        return navigation
    
    def _build_dashboard_cards(self) -> List[CardConfig]:
        """Build dashboard cards configuration"""
        cards = [
            CardConfig(
                id="user_stats",
                title="User Statistics",
                subtitle="Active users and registrations",
                icon="users",
                color="blue",
                card_type="stats",
                data_source="/api/admin/stats/users"
            ),
            CardConfig(
                id="system_health",
                title="System Health",
                subtitle="Server status and performance",
                icon="activity",
                color="green",
                card_type="stats",
                data_source="/api/admin/stats/system"
            ),
            CardConfig(
                id="recent_activity",
                title="Recent Activity",
                subtitle="Latest user actions",
                icon="clock",
                color="yellow",
                card_type="list",
                data_source="/api/admin/audit-logs?limit=10"
            ),
            CardConfig(
                id="security_alerts",
                title="Security Alerts",
                subtitle="Security events and warnings",
                icon="shield-alert",
                color="red",
                card_type="list",
                data_source="/api/admin/security/alerts"
            )
        ]
        
        # Add dynamic model cards
        metadata = crud_generator.get_admin_metadata()
        for nav_group in metadata.get("navigation", []):
            for model in nav_group["models"]:
                cards.append(CardConfig(
                    id=f"model_{model['key']}",
                    title=model["name"],
                    subtitle=model.get("description", f"Manage {model['name'].lower()}"),
                    icon="table",
                    color="gray",
                    card_type="list",
                    actions=[
                        {"label": "View All", "url": f"/admin/models/{model['key']}"},
                        {"label": "Create New", "url": f"/admin/models/{model['key']}/create"}
                    ] if model["can_create"] else [
                        {"label": "View All", "url": f"/admin/models/{model['key']}"}
                    ]
                ))
        
        return cards


# Global UI generator instance
ui_generator = AdminUIGenerator()