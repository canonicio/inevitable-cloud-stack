"""
Tenant Data Migration API Routes

Provides API endpoints for tenant data migration, export, import, backup and restore.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from modules.core.secure_error_messages import create_api_error, create_auth_error, create_billing_error, create_admin_error
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import os
import tempfile

from .database import get_db
from .deps import get_current_active_user, get_current_tenant_id
from .migration import tenant_migrator
from ..auth.models import User
from ..auth.permissions import Permission, require_permission
from .secure_file_upload import secure_file_upload_dependency, SecureFileUpload
from .enhanced_validators import SecureBaseModel

router = APIRouter(prefix="/api/migration", tags=["migration"])


class ExportRequest(SecureBaseModel):
    """Request model for tenant data export"""
    format: str = Field(default="json", description="Export format: json, yaml, sql")
    include_sensitive: bool = Field(default=False, description="Include sensitive data")
    
    @field_validator('format')
    @classmethod
    def validate_format(cls, v):
        allowed_formats = ['json', 'yaml', 'sql', 'csv']
        if v not in allowed_formats:
            raise ValueError(f'Format must be one of: {allowed_formats}')
        return v


class ImportRequest(SecureBaseModel):
    """Request model for tenant data import"""
    target_tenant_id: Optional[str] = Field(None, description="Override tenant ID")
    merge_existing: bool = Field(default=False, description="Merge with existing data")
    validate_only: bool = Field(default=False, description="Only validate, don't import")


class MigrationRequest(SecureBaseModel):
    """Request model for tenant migration"""
    source_tenant_id: str = Field(..., description="Source tenant ID")
    target_tenant_id: Optional[str] = Field(None, description="Target tenant ID")
    target_database_url: Optional[str] = Field(None, description="Target database URL")
    include_audit_logs: bool = Field(default=True, description="Include audit logs")


class BackupRequest(SecureBaseModel):
    """Request model for tenant backup"""
    backup_path: Optional[str] = Field(None, description="Backup directory path")


class RestoreRequest(SecureBaseModel):
    """Request model for tenant restore"""
    backup_file: str = Field(..., description="Path to backup file")
    target_tenant_id: Optional[str] = Field(None, description="Override tenant ID")
    force: bool = Field(default=False, description="Force restore even if data exists")


@router.post("/export")
@require_permission(Permission.TENANT_ADMIN)
async def export_tenant_data(
    request: ExportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    tenant_id: str = Depends(get_current_tenant_id)
):
    """
    Export tenant data in specified format
    
    Requires TENANT_ADMIN permission
    """
    try:
        # Create temporary file for export
        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=f".{request.format}"
        )
        temp_file.close()
        
        # Perform export
        success, message, file_path = tenant_migrator.export_tenant_data(
            db=db,
            tenant_id=tenant_id,
            export_format=request.format,
            include_sensitive=request.include_sensitive,
            output_path=temp_file.name
        )
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        # Schedule cleanup after download
        def cleanup_file():
            if os.path.exists(file_path):
                os.remove(file_path)
        
        background_tasks.add_task(cleanup_file)
        
        # Return file for download
        return FileResponse(
            path=file_path,
            filename=f"tenant_{tenant_id}_export.{request.format}",
            media_type="application/octet-stream"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Export failed: Operation failed. Please try again later.")


@router.post("/import")
@require_permission(Permission.TENANT_ADMIN)
async def import_tenant_data(
    target_tenant_id: Optional[str] = None,
    merge_existing: bool = False,
    validate_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    tenant_id: str = Depends(get_current_tenant_id),
    secure_upload: SecureFileUpload = Depends(secure_file_upload_dependency)
):
    """
    Import tenant data from uploaded file
    
    Requires TENANT_ADMIN permission
    """
    try:
        # Define allowed file types for imports
        allowed_types = [
            'application/json',
            'text/yaml', 'application/yaml',
            'application/sql', 'text/sql',
            'text/csv', 'application/csv'
        ]
        
        # Validate and process uploaded file using secure handler
        upload_result = await secure_upload.validate_and_process_upload(
            allowed_types=allowed_types,
            max_size=50 * 1024 * 1024  # 50MB limit for import files
        )
        
        if not upload_result['valid']:
            raise HTTPException(
                status_code=400, 
                detail=f"File validation failed: {upload_result['message']}"
            )
        
        # Use current tenant if no target specified
        use_tenant_id = target_tenant_id or tenant_id
        
        # Perform import using the validated file
        success, message, stats = tenant_migrator.import_tenant_data(
            db=db,
            file_path=upload_result['file_path'],
            target_tenant_id=use_tenant_id,
            merge_existing=merge_existing,
            validate_only=validate_only
        )
        
        # Clean up temp file (secure upload handles this automatically)
        # File cleanup is handled by SecureFileUpload background task
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        return {
            "success": success,
            "message": message,
            "stats": stats,
            "file_info": {
                "filename": upload_result['filename'],
                "size": upload_result['size'],
                "mime_type": upload_result['mime_type']
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Import failed: Operation failed. Please try again later.")


@router.post("/backup")
@require_permission(Permission.TENANT_ADMIN)
async def backup_tenant(
    request: BackupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    tenant_id: str = Depends(get_current_tenant_id)
):
    """
    Create a backup of tenant data
    
    Requires TENANT_ADMIN permission
    """
    try:
        success, message, backup_path = tenant_migrator.backup_tenant(
            db=db,
            tenant_id=tenant_id,
            backup_path=request.backup_path
        )
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        return {
            "success": success,
            "message": message,
            "backup_path": backup_path
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Backup failed: Operation failed. Please try again later.")


@router.post("/restore")
@require_permission(Permission.TENANT_ADMIN)
async def restore_tenant(
    request: RestoreRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    tenant_id: str = Depends(get_current_tenant_id)
):
    """
    Restore tenant from backup
    
    Requires TENANT_ADMIN permission
    """
    try:
        # Use current tenant if no target specified
        use_tenant_id = request.target_tenant_id or tenant_id
        
        success, message, stats = tenant_migrator.restore_tenant(
            db=db,
            backup_file=request.backup_file,
            target_tenant_id=use_tenant_id,
            force=request.force
        )
        
        if not success:
            raise HTTPException(status_code=400, detail=message)
        
        return {
            "success": success,
            "message": message,
            "stats": stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Restore failed: Operation failed. Please try again later.")


@router.get("/export/formats")
async def get_export_formats():
    """Get supported export formats"""
    return {
        "formats": tenant_migrator.supported_formats,
        "default": "json"
    }


@router.post("/validate")
@require_permission(Permission.TENANT_ADMIN)
async def validate_import_file(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    secure_upload: SecureFileUpload = Depends(secure_file_upload_dependency)
):
    """
    Validate an import file without performing import
    
    Requires TENANT_ADMIN permission
    """
    try:
        # Define allowed file types for validation
        allowed_types = [
            'application/json',
            'text/yaml', 'application/yaml', 
            'application/sql', 'text/sql',
            'text/csv', 'application/csv'
        ]
        
        # Validate and process uploaded file using secure handler
        upload_result = await secure_upload.validate_and_process_upload(
            allowed_types=allowed_types,
            max_size=50 * 1024 * 1024  # 50MB limit
        )
        
        if not upload_result['valid']:
            return {
                "valid": False,
                "message": f"File security validation failed: {upload_result['message']}",
                "validation_results": None
            }
        
        # Perform content validation using the secure file
        success, message, validation_results = tenant_migrator.import_tenant_data(
            db=db,
            file_path=upload_result['file_path'],
            validate_only=True
        )
        
        # File cleanup is handled by SecureFileUpload background task
        
        return {
            "valid": success,
            "message": message,
            "validation_results": validation_results,
            "security_scan_results": upload_result['security_scans'] if upload_result.get('security_scans') else None
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Validation failed: Operation failed. Please try again later.")


@router.post("/migrate")
@require_permission(Permission.SUPER_ADMIN)
async def migrate_tenant_between_databases(
    request: MigrationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Migrate tenant data between databases
    
    Requires SUPER_ADMIN permission
    """
    try:
        # This would create a connection to target database
        # For now, we'll use the same database
        target_db = db
        
        # Perform migration in background
        def perform_migration():
            success, message, stats = tenant_migrator.migrate_tenant(
                source_db=db,
                target_db=target_db,
                tenant_id=request.source_tenant_id,
                new_tenant_id=request.target_tenant_id,
                include_audit_logs=request.include_audit_logs
            )
            
            # Log result
            if success:
                logger.info(f"Migration completed: {message}")
            else:
                logger.error(f"Migration failed: {message}")
        
        background_tasks.add_task(perform_migration)
        
        return {
            "message": "Migration started in background",
            "source_tenant_id": request.source_tenant_id,
            "target_tenant_id": request.target_tenant_id or request.source_tenant_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Migration failed: Operation failed. Please try again later.")


@router.get("/status/{tenant_id}")
@require_permission(Permission.TENANT_ADMIN)
async def get_tenant_data_status(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get data status for a tenant
    
    Requires TENANT_ADMIN permission
    """
    try:
        tenant_models = tenant_migrator._get_tenant_models()
        status = {
            "tenant_id": tenant_id,
            "models": {}
        }
        
        for model_name, model_class in tenant_models.items():
            count = db.query(model_class).filter(
                model_class.tenant_id == tenant_id
            ).count()
            
            status["models"][model_name] = {
                "count": count,
                "has_data": count > 0
            }
        
        status["total_records"] = sum(m["count"] for m in status["models"].values())
        
        return status
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get status: Operation failed. Please try again later.")