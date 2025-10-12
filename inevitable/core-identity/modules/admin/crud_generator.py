"""
Dynamic CRUD Generator for Platform Forge Admin
Automatically generates CRUD interfaces for any SQLAlchemy models
"""
from typing import Dict, Any, List, Optional, Type, Union
from dataclasses import dataclass, field
from sqlalchemy import inspect, Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey
from sqlalchemy.orm import Session, relationship
from sqlalchemy.ext.declarative import DeclarativeMeta
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, create_model
from modules.core.database import Base, get_db
from modules.auth.dependencies import get_current_user
from modules.auth.rbac import require_permissions, Permission
from modules.admin.audit_logs import SecureAuditService
from modules.admin.crud_security import (
    FieldSecurity, TenantSecurity, CRUDSecurityMonitor, SecureCRUDHelper
)
import json
import importlib
import inspect as python_inspect
from datetime import datetime


@dataclass
class FieldConfig:
    """Configuration for individual fields in CRUD operations"""
    field_name: str
    field_type: str
    is_required: bool = True
    is_readonly: bool = False
    is_searchable: bool = True
    is_filterable: bool = True
    is_sortable: bool = True
    display_name: Optional[str] = None
    description: Optional[str] = None
    widget_type: str = "input"  # input, textarea, select, checkbox, etc.
    validation_rules: Dict[str, Any] = field(default_factory=dict)
    foreign_key_display: Optional[str] = None  # For FK relationships


@dataclass
class CRUDConfig:
    """Configuration for CRUD operations on a model"""
    model_name: str
    table_name: str
    display_name: str
    description: Optional[str] = None
    
    # Permissions
    can_create: bool = True
    can_read: bool = True
    can_update: bool = True
    can_delete: bool = True
    required_permissions: List[str] = field(default_factory=list)
    
    # UI Configuration
    list_display: List[str] = field(default_factory=list)
    list_filter: List[str] = field(default_factory=list)
    search_fields: List[str] = field(default_factory=list)
    ordering: List[str] = field(default_factory=list)
    
    # Pagination
    page_size: int = 25
    max_page_size: int = 100
    
    # Field configurations
    fields: Dict[str, FieldConfig] = field(default_factory=dict)
    
    # Custom actions
    custom_actions: List[str] = field(default_factory=list)
    
    # Validation
    custom_validators: List[str] = field(default_factory=list)


class CRUDGenerator:
    """Dynamic CRUD generator for SQLAlchemy models"""
    
    def __init__(self):
        self.configs: Dict[str, CRUDConfig] = {}
        self.models: Dict[str, Type[Base]] = {}
        self.routers: Dict[str, APIRouter] = {}
    
    def discover_models(self, modules: List[str]) -> Dict[str, Type[Base]]:
        """Discover all SQLAlchemy models from specified modules"""
        discovered_models = {}
        
        for module_name in modules:
            try:
                if module_name == "core":
                    continue  # Skip core module models
                    
                module_path = f"modules.{module_name}.models"
                module = importlib.import_module(module_path)
                
                # Get all classes from the module
                for name, obj in python_inspect.getmembers(module, python_inspect.isclass):
                    # Check if it's a SQLAlchemy model
                    if (hasattr(obj, '__tablename__') and 
                        hasattr(obj, '__table__') and 
                        issubclass(obj, Base)):
                        discovered_models[f"{module_name}_{name}"] = obj
                        
            except ImportError:
                # Module doesn't have models, skip
                continue
                
        return discovered_models
    
    def introspect_model(self, model: Type[Base]) -> CRUDConfig:
        """Introspect a SQLAlchemy model and generate CRUD configuration"""
        mapper = inspect(model)
        table_name = model.__tablename__
        model_name = model.__name__
        
        # Create base configuration
        config = CRUDConfig(
            model_name=model_name,
            table_name=table_name,
            display_name=model_name.replace('_', ' ').title(),
            description=f"CRUD operations for {model_name}"
        )
        
        # Introspect fields
        for column in mapper.columns:
            field_config = self._introspect_column(column)
            config.fields[column.name] = field_config
            
            # Auto-configure list display
            if len(config.list_display) < 5 and not column.foreign_keys:
                config.list_display.append(column.name)
            
            # Auto-configure search fields
            if isinstance(column.type, (String, Text)) and len(config.search_fields) < 3:
                config.search_fields.append(column.name)
                
        # Introspect relationships
        for relationship_prop in mapper.relationships:
            rel_config = self._introspect_relationship(relationship_prop)
            config.fields[relationship_prop.key] = rel_config
            
        # Set default ordering
        if 'created_at' in config.fields:
            config.ordering = ['-created_at']
        elif 'id' in config.fields:
            config.ordering = ['-id']
            
        return config
    
    def _introspect_column(self, column: Column) -> FieldConfig:
        """Introspect a SQLAlchemy column"""
        field_type = self._get_field_type(column.type)
        widget_type = self._get_widget_type(column)
        
        return FieldConfig(
            field_name=column.name,
            field_type=field_type,
            is_required=not column.nullable and not column.default,
            is_readonly=column.primary_key or column.name in ['created_at', 'updated_at'],
            display_name=column.name.replace('_', ' ').title(),
            widget_type=widget_type,
            validation_rules=self._get_validation_rules(column)
        )
    
    def _introspect_relationship(self, rel) -> FieldConfig:
        """Introspect a SQLAlchemy relationship"""
        return FieldConfig(
            field_name=rel.key,
            field_type="relationship",
            is_required=False,
            is_readonly=True,
            display_name=rel.key.replace('_', ' ').title(),
            widget_type="select" if rel.direction.name == "MANYTOONE" else "multiselect"
        )
    
    def _get_field_type(self, column_type) -> str:
        """Determine field type from SQLAlchemy column type"""
        type_mapping = {
            Integer: "integer",
            String: "string",
            Text: "text",
            Boolean: "boolean",
            DateTime: "datetime",
            JSON: "json"
        }
        
        for sql_type, field_type in type_mapping.items():
            if isinstance(column_type, sql_type):
                return field_type
                
        return "string"  # Default fallback
    
    def _get_widget_type(self, column: Column) -> str:
        """Determine widget type from column properties"""
        if isinstance(column.type, Boolean):
            return "checkbox"
        elif isinstance(column.type, Text):
            return "textarea"
        elif isinstance(column.type, JSON):
            return "json_editor"
        elif isinstance(column.type, DateTime):
            return "datetime"
        elif column.foreign_keys:
            return "select"
        else:
            return "input"
    
    def _get_validation_rules(self, column: Column) -> Dict[str, Any]:
        """Extract validation rules from column definition"""
        rules = {}
        
        if hasattr(column.type, 'length') and column.type.length:
            rules['max_length'] = column.type.length
            
        if not column.nullable:
            rules['required'] = True
            
        if column.unique:
            rules['unique'] = True
            
        return rules
    
    def create_pydantic_models(self, config: CRUDConfig, model: Type[Base]):
        """Create Pydantic models for request/response"""
        # Create response model
        response_fields = {}
        create_fields = {}
        update_fields = {}
        
        for field_name, field_config in config.fields.items():
            if field_config.field_type == "relationship":
                continue  # Skip relationships for now
                
            # Determine Python type
            python_type = self._get_python_type(field_config.field_type)
            
            # Response model includes all fields
            response_fields[field_name] = (python_type, ...)
            
            # Create model excludes readonly fields
            if not field_config.is_readonly:
                default_value = ... if field_config.is_required else None
                create_fields[field_name] = (python_type, default_value)
                
                # Update model makes all fields optional
                update_fields[field_name] = (Optional[python_type], None)
        
        # Create the models
        response_model = create_model(f"{config.model_name}Response", **response_fields)
        create_model_type = create_model(f"{config.model_name}Create", **create_fields)
        update_model_type = create_model(f"{config.model_name}Update", **update_fields)
        
        return response_model, create_model_type, update_model_type
    
    def _get_python_type(self, field_type: str):
        """Convert field type to Python type"""
        type_mapping = {
            "integer": int,
            "string": str,
            "text": str,
            "boolean": bool,
            "datetime": datetime,
            "json": dict
        }
        return type_mapping.get(field_type, str)
    
    def generate_crud_router(self, config: CRUDConfig, model: Type[Base]) -> APIRouter:
        """Generate a complete CRUD router for a model"""
        router = APIRouter(prefix=f"/{config.table_name}", tags=[config.display_name])
        
        # Create Pydantic models
        response_model, create_model_type, update_model_type = self.create_pydantic_models(config, model)
        
        # List endpoint
        @router.get("", response_model=List[response_model])
        async def list_items(
            request: Request,
            page: int = Query(1, ge=1),
            page_size: int = Query(config.page_size, ge=1, le=config.max_page_size),
            search: Optional[str] = Query(None),
            sort_by: Optional[str] = Query(None),
            sort_desc: bool = Query(False),
            current_user = Depends(get_current_user),
            db: Session = Depends(get_db)
        ):
            if config.required_permissions:
                # Check permissions if required
                pass  # Implement permission checking
                
            # SECURITY FIX: Apply tenant filtering first
            query = db.query(model)
            query = SecureCRUDHelper.secure_query(query, model, current_user)
            
            # Apply search - CRITICAL FIX: Sanitize search input to prevent SQL injection
            if search and config.search_fields:
                # Sanitize search input - remove SQL special characters
                import re
                # Remove any SQL wildcard characters and escape sequences
                safe_search = re.sub(r'[%_\\\'\";]', '', search)
                # Limit search length to prevent DoS
                safe_search = safe_search[:100] if safe_search else ""
                
                if safe_search:  # Only search if there's safe content left
                    search_conditions = []
                    for field in config.search_fields:
                        if hasattr(model, field):
                            attr = getattr(model, field)
                            # Use parameterized query with sanitized input
                            search_conditions.append(attr.ilike(f"%{safe_search}%"))
                    if search_conditions:
                        query = query.filter(db.or_(*search_conditions))
            
            # Apply sorting - CRITICAL FIX: Validate sort_by parameter
            if sort_by:
                # Sanitize sort_by - only allow alphanumeric and underscore
                import re
                if re.match(r'^[a-zA-Z0-9_]+$', sort_by) and hasattr(model, sort_by):
                    attr = getattr(model, sort_by)
                    if sort_desc:
                        query = query.order_by(attr.desc())
                    else:
                        query = query.order_by(attr)
                else:
                    # Log potential SQL injection attempt
                    import logging
                    logging.warning(f"Invalid sort_by parameter: {sort_by[:50]}")
            elif config.ordering:
                for order_field in config.ordering:
                    if order_field.startswith('-'):
                        field_name = order_field[1:]
                        if hasattr(model, field_name):
                            query = query.order_by(getattr(model, field_name).desc())
                    else:
                        if hasattr(model, order_field):
                            query = query.order_by(getattr(model, order_field))
            
            # Apply pagination
            total = query.count()
            offset = (page - 1) * page_size
            items = query.offset(offset).limit(page_size).all()
            
            # Log access
            await SecureAuditService.log_action(
                action=f"{config.table_name}_list_accessed",
                user_id=current_user.id,
                resource_type=config.table_name,
                details={"page": page, "page_size": page_size, "search": search},
                request=request,
                db=db
            )
            
            return items
        
        # Get single item endpoint
        @router.get("/{item_id}", response_model=response_model)
        async def get_item(
            item_id: int,
            request: Request,
            current_user = Depends(get_current_user),
            db: Session = Depends(get_db)
        ):
            # SECURITY FIX: Apply tenant filtering to single item access
            query = db.query(model)
            query = SecureCRUDHelper.secure_query(query, model, current_user)
            item = query.filter(model.id == item_id).first()
            
            if not item:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # SECURITY FIX: Validate tenant access
            if not await SecureCRUDHelper.validate_access(item, current_user, "read", db):
                raise HTTPException(status_code=404, detail="Item not found")
            
            await SecureAuditService.log_action(
                action=f"{config.table_name}_item_accessed",
                user_id=current_user.id,
                resource_type=config.table_name,
                resource_id=str(item_id),
                request=request,
                db=db
            )
            
            return item
        
        # Create endpoint
        if config.can_create:
            @router.post("", response_model=response_model)
            async def create_item(
                item_data: create_model_type,
                request: Request,
                current_user = Depends(get_current_user),
                db: Session = Depends(get_db)
            ):
                # SECURITY FIX: Prepare data with mass assignment protection
                raw_data = item_data.dict(exclude_unset=True)
                provided_fields = set(raw_data.keys())
                
                # Apply security filtering
                item_dict = SecureCRUDHelper.prepare_create_data(raw_data, current_user, model)
                filtered_fields = set(item_dict.keys())
                
                # Monitor for security violations
                await CRUDSecurityMonitor.detect_mass_assignment_attempt(
                    model_name=config.model_name,
                    provided_fields=provided_fields,
                    filtered_fields=filtered_fields,
                    user_id=current_user.id,
                    db=db
                )
                
                new_item = model(**item_dict)
                db.add(new_item)
                db.commit()
                db.refresh(new_item)
                
                await SecureAuditService.log_action(
                    action=f"{config.table_name}_created",
                    user_id=current_user.id,
                    resource_type=config.table_name,
                    resource_id=str(new_item.id),
                    details=item_dict,
                    request=request,
                    db=db
                )
                
                return new_item
        
        # Update endpoint
        if config.can_update:
            @router.put("/{item_id}", response_model=response_model)
            async def update_item(
                item_id: int,
                item_data: update_model_type,
                request: Request,
                current_user = Depends(get_current_user),
                db: Session = Depends(get_db)
            ):
                # SECURITY FIX: Apply tenant filtering to find item
                query = db.query(model)
                query = SecureCRUDHelper.secure_query(query, model, current_user)
                item = query.filter(model.id == item_id).first()
                
                if not item:
                    raise HTTPException(status_code=404, detail="Item not found")
                
                # SECURITY FIX: Validate tenant access
                if not await SecureCRUDHelper.validate_access(item, current_user, "update", db):
                    raise HTTPException(status_code=404, detail="Item not found")
                
                # SECURITY FIX: Apply mass assignment protection
                raw_data = item_data.dict(exclude_unset=True)
                provided_fields = set(raw_data.keys())
                
                # Apply security filtering for updates
                update_dict = SecureCRUDHelper.prepare_update_data(raw_data, current_user, model)
                filtered_fields = set(update_dict.keys())
                
                # Monitor for security violations
                await CRUDSecurityMonitor.detect_mass_assignment_attempt(
                    model_name=config.model_name,
                    provided_fields=provided_fields,
                    filtered_fields=filtered_fields,
                    user_id=current_user.id,
                    db=db
                )
                
                # Apply filtered updates
                for field, value in update_dict.items():
                    if hasattr(item, field):
                        setattr(item, field, value)
                
                db.commit()
                db.refresh(item)
                
                await SecureAuditService.log_action(
                    action=f"{config.table_name}_updated",
                    user_id=current_user.id,
                    resource_type=config.table_name,
                    resource_id=str(item_id),
                    details=update_dict,
                    request=request,
                    db=db
                )
                
                return item
        
        # Delete endpoint
        if config.can_delete:
            @router.delete("/{item_id}")
            async def delete_item(
                item_id: int,
                request: Request,
                current_user = Depends(get_current_user),
                db: Session = Depends(get_db)
            ):
                # SECURITY FIX: Apply tenant filtering to find item
                query = db.query(model)
                query = SecureCRUDHelper.secure_query(query, model, current_user)
                item = query.filter(model.id == item_id).first()
                
                if not item:
                    raise HTTPException(status_code=404, detail="Item not found")
                
                # SECURITY FIX: Validate tenant access
                if not await SecureCRUDHelper.validate_access(item, current_user, "delete", db):
                    raise HTTPException(status_code=404, detail="Item not found")
                
                db.delete(item)
                db.commit()
                
                await SecureAuditService.log_action(
                    action=f"{config.table_name}_deleted",
                    user_id=current_user.id,
                    resource_type=config.table_name,
                    resource_id=str(item_id),
                    request=request,
                    db=db
                )
                
                return {"message": "Item deleted successfully"}
        
        return router
    
    def generate_all_crud_routers(self, modules: List[str]) -> Dict[str, APIRouter]:
        """Generate CRUD routers for all discovered models"""
        # Discover models
        self.models = self.discover_models(modules)
        
        # Generate configurations and routers
        for model_key, model in self.models.items():
            config = self.introspect_model(model)
            self.configs[model_key] = config
            self.routers[model_key] = self.generate_crud_router(config, model)
        
        return self.routers
    
    def get_admin_metadata(self) -> Dict[str, Any]:
        """Get metadata for admin UI generation"""
        metadata = {
            "models": {},
            "navigation": []
        }
        
        # Group models by module
        modules_dict = {}
        for model_key, config in self.configs.items():
            module_name = model_key.split('_')[0]
            if module_name not in modules_dict:
                modules_dict[module_name] = []
            modules_dict[module_name].append({
                "key": model_key,
                "name": config.display_name,
                "table_name": config.table_name,
                "description": config.description,
                "can_create": config.can_create,
                "can_read": config.can_read,
                "can_update": config.can_update,
                "can_delete": config.can_delete
            })
        
        # Build navigation structure
        for module_name, models in modules_dict.items():
            metadata["navigation"].append({
                "module": module_name.title(),
                "models": models
            })
        
        # Add model configurations
        for model_key, config in self.configs.items():
            metadata["models"][model_key] = {
                "config": config,
                "fields": {name: field for name, field in config.fields.items()}
            }
        
        return metadata


# Global CRUD generator instance
crud_generator = CRUDGenerator()