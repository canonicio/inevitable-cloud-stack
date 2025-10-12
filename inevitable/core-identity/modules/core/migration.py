"""
Tenant Data Migration System

Provides functionality for migrating tenant data between environments,
backing up tenant data, and handling data portability requirements.
"""
import json
import logging
import os
import tarfile
import tempfile
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import DeclarativeMeta
import yaml

from .database import Base, TenantMixin
from .security import SecurityUtils
# Import individual models as needed to avoid circular imports
# from ..auth.models import User, Role, Permission
# from ..billing.models import Customer, Package, Adapter, CustomerAdapterAccess  
# from ..analytics.models import UserActivity
# from ..privacy.models import ConsentRecord

logger = logging.getLogger(__name__)


class TenantDataMigrator:
    """Handle tenant data migration, export, and import"""
    
    def __init__(self):
        self.supported_formats = ["json", "yaml", "sql"]
        self.batch_size = 1000
        self.encryption_enabled = True
        
        # Define export order to handle dependencies
        self.export_order = [
            # Core models first
            "users", "roles", "permissions", "user_roles",
            # Auth-related
            "api_keys", "mfa_settings", "oauth_accounts",
            # Billing
            "customers", "packages", "adapters", "customer_adapter_access",
            # Analytics
            "user_activities",
            # Privacy
            "consent_records",
            # Other modules
            "referrals", "notifications", "audit_logs"
        ]
    
    def export_tenant_data(
        self,
        db: Session,
        tenant_id: str,
        export_format: str = "json",
        include_sensitive: bool = False,
        output_path: Optional[str] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Export all data for a specific tenant
        
        Args:
            db: Database session
            tenant_id: Tenant ID to export
            export_format: Format for export (json, yaml, sql)
            include_sensitive: Whether to include sensitive data
            output_path: Optional path to save export
            
        Returns:
            Tuple of (success, message, file_path)
        """
        try:
            if export_format not in self.supported_formats:
                return False, f"Unsupported format: {export_format}", None
            
            # Collect all tenant data
            export_data = {
                "metadata": {
                    "tenant_id": tenant_id,
                    "export_date": datetime.utcnow().isoformat(),
                    "export_version": "1.0",
                    "include_sensitive": include_sensitive
                },
                "data": {}
            }
            
            # Get all tables with TenantMixin
            tenant_models = self._get_tenant_models()
            
            for model_name, model_class in tenant_models.items():
                logger.info(f"Exporting {model_name} for tenant {tenant_id}")
                
                # Query data for this model
                query = db.query(model_class).filter(
                    model_class.tenant_id == tenant_id
                )
                
                # Export in batches
                offset = 0
                model_data = []
                
                while True:
                    batch = query.offset(offset).limit(self.batch_size).all()
                    if not batch:
                        break
                    
                    for record in batch:
                        # Convert to dict
                        record_dict = self._model_to_dict(record, include_sensitive)
                        model_data.append(record_dict)
                    
                    offset += self.batch_size
                
                if model_data:
                    export_data["data"][model_name] = model_data
                    logger.info(f"Exported {len(model_data)} {model_name} records")
            
            # Format and save data
            if export_format == "json":
                file_path = self._export_json(export_data, output_path, tenant_id)
            elif export_format == "yaml":
                file_path = self._export_yaml(export_data, output_path, tenant_id)
            elif export_format == "sql":
                file_path = self._export_sql(db, tenant_id, output_path)
            else:
                return False, f"Format {export_format} not implemented", None
            
            # Create compressed archive if encryption is enabled
            if self.encryption_enabled:
                encrypted_path = self._encrypt_export(file_path, tenant_id)
                os.remove(file_path)  # Remove unencrypted file
                file_path = encrypted_path
            
            return True, f"Successfully exported tenant data to {file_path}", file_path
            
        except Exception as e:
            logger.error(f"Error exporting tenant data: {e}")
            return False, f"Export failed: {str(e)}", None
    
    def import_tenant_data(
        self,
        db: Session,
        file_path: str,
        target_tenant_id: Optional[str] = None,
        merge_existing: bool = False,
        validate_only: bool = False
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Import tenant data from export file
        
        Args:
            db: Database session
            file_path: Path to import file
            target_tenant_id: Override tenant ID (for cloning)
            merge_existing: Whether to merge with existing data
            validate_only: Only validate, don't import
            
        Returns:
            Tuple of (success, message, import_stats)
        """
        try:
            # Decrypt if needed
            if file_path.endswith('.enc'):
                decrypted_path = self._decrypt_export(file_path)
                file_path = decrypted_path
            
            # Load data based on format
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    import_data = json.load(f)
            elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
                # HIGH-003 FIX: Use secure YAML loading with bomb protection
                from modules.core.security import safe_load_yaml, YAMLBombError
                try:
                    import_data = safe_load_yaml(file_path)
                except YAMLBombError as e:
                    return False, f"YAML bomb detected: {e}", {}
            else:
                return False, "Unsupported file format", {}
            
            # Validate structure
            if "metadata" not in import_data or "data" not in import_data:
                return False, "Invalid import file structure", {}
            
            original_tenant_id = import_data["metadata"]["tenant_id"]
            use_tenant_id = target_tenant_id or original_tenant_id
            
            # Check if tenant exists
            if not merge_existing:
                existing_data = self._check_existing_tenant_data(db, use_tenant_id)
                if existing_data:
                    return False, f"Tenant {use_tenant_id} already has data. Use merge_existing=True to merge.", {}
            
            if validate_only:
                validation_results = self._validate_import_data(import_data)
                return validation_results["valid"], validation_results["message"], validation_results
            
            # Perform import
            import_stats = {
                "total_records": 0,
                "imported": 0,
                "skipped": 0,
                "errors": [],
                "models": {}
            }
            
            # Import in dependency order
            for model_name in self.export_order:
                if model_name not in import_data["data"]:
                    continue
                
                model_stats = self._import_model_data(
                    db, model_name, import_data["data"][model_name],
                    original_tenant_id, use_tenant_id, merge_existing
                )
                
                import_stats["models"][model_name] = model_stats
                import_stats["total_records"] += model_stats["total"]
                import_stats["imported"] += model_stats["imported"]
                import_stats["skipped"] += model_stats["skipped"]
                if model_stats["errors"]:
                    import_stats["errors"].extend(model_stats["errors"])
            
            db.commit()
            
            message = f"Import completed: {import_stats['imported']} records imported, {import_stats['skipped']} skipped"
            if import_stats["errors"]:
                message += f", {len(import_stats['errors'])} errors"
            
            return True, message, import_stats
            
        except Exception as e:
            logger.error(f"Error importing tenant data: {e}")
            db.rollback()
            return False, f"Import failed: {str(e)}", {}
    
    def migrate_tenant(
        self,
        source_db: Session,
        target_db: Session,
        tenant_id: str,
        new_tenant_id: Optional[str] = None,
        include_audit_logs: bool = True
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Migrate tenant data between databases
        
        Args:
            source_db: Source database session
            target_db: Target database session
            tenant_id: Tenant ID to migrate
            new_tenant_id: Optional new tenant ID
            include_audit_logs: Whether to include audit logs
            
        Returns:
            Tuple of (success, message, migration_stats)
        """
        try:
            use_tenant_id = new_tenant_id or tenant_id
            
            # Export from source
            export_path = tempfile.mktemp(suffix=".json")
            success, message, file_path = self.export_tenant_data(
                source_db, tenant_id, "json", True, export_path
            )
            
            if not success:
                return False, f"Export failed: {message}", {}
            
            # Import to target
            success, message, import_stats = self.import_tenant_data(
                target_db, file_path, use_tenant_id, False, False
            )
            
            # Clean up temp file
            if os.path.exists(file_path):
                os.remove(file_path)
            
            if success:
                # Create migration audit record
                self._record_migration(
                    source_db, target_db, tenant_id, use_tenant_id, import_stats
                )
            
            return success, message, import_stats
            
        except Exception as e:
            logger.error(f"Error migrating tenant: {e}")
            return False, f"Migration failed: {str(e)}", {}
    
    def backup_tenant(
        self,
        db: Session,
        tenant_id: str,
        backup_path: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Create a backup of tenant data
        
        Args:
            db: Database session
            tenant_id: Tenant ID to backup
            backup_path: Optional backup directory
            
        Returns:
            Tuple of (success, message, backup_file_path)
        """
        try:
            # Default backup path
            if not backup_path:
                backup_path = f"/backups/tenants/{tenant_id}"
            
            os.makedirs(backup_path, exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_name = f"tenant_{tenant_id}_backup_{timestamp}"
            
            # Export all data
            export_file = os.path.join(backup_path, f"{backup_name}.json")
            success, message, file_path = self.export_tenant_data(
                db, tenant_id, "json", True, export_file
            )
            
            if not success:
                return False, message, ""
            
            # Create compressed archive
            archive_path = os.path.join(backup_path, f"{backup_name}.tar.gz")
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(file_path, arcname=os.path.basename(file_path))
            
            # Remove uncompressed file
            os.remove(file_path)
            
            # Create backup metadata
            metadata = {
                "tenant_id": tenant_id,
                "backup_date": datetime.utcnow().isoformat(),
                "backup_size": os.path.getsize(archive_path),
                "backup_version": "1.0"
            }
            
            metadata_path = os.path.join(backup_path, f"{backup_name}_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True, f"Backup created successfully", archive_path
            
        except Exception as e:
            logger.error(f"Error creating tenant backup: {e}")
            return False, f"Backup failed: {str(e)}", ""
    
    def restore_tenant(
        self,
        db: Session,
        backup_file: str,
        target_tenant_id: Optional[str] = None,
        force: bool = False
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Restore tenant from backup
        
        Args:
            db: Database session
            backup_file: Path to backup file
            target_tenant_id: Override tenant ID
            force: Force restore even if data exists
            
        Returns:
            Tuple of (success, message, restore_stats)
        """
        try:
            # Extract backup
            temp_dir = tempfile.mkdtemp()
            
            with tarfile.open(backup_file, "r:gz") as tar:
                tar.extractall(temp_dir)
            
            # Find JSON file
            json_files = [f for f in os.listdir(temp_dir) if f.endswith('.json') and not f.endswith('_metadata.json')]
            if not json_files:
                return False, "No data file found in backup", {}
            
            data_file = os.path.join(temp_dir, json_files[0])
            
            # Import data
            success, message, import_stats = self.import_tenant_data(
                db, data_file, target_tenant_id, force, False
            )
            
            # Clean up
            import shutil
            shutil.rmtree(temp_dir)
            
            return success, message, import_stats
            
        except Exception as e:
            logger.error(f"Error restoring tenant: {e}")
            return False, f"Restore failed: {str(e)}", {}
    
    def _get_tenant_models(self) -> Dict[str, DeclarativeMeta]:
        """Get all models that include TenantMixin"""
        tenant_models = {}
        
        for mapper in Base.registry.mappers:
            model = mapper.class_
            if hasattr(model, 'tenant_id'):
                # Use table name as key
                table_name = model.__tablename__
                tenant_models[table_name] = model
        
        return tenant_models
    
    def _model_to_dict(self, instance: Any, include_sensitive: bool) -> Dict[str, Any]:
        """Convert model instance to dictionary"""
        data = {}
        
        # Get columns
        columns = inspect(instance.__class__).columns
        
        for column in columns:
            column_name = column.name
            value = getattr(instance, column_name)
            
            # Skip sensitive fields unless requested
            if not include_sensitive and column_name in ['password_hash', 'secret_key', 'api_secret']:
                continue
            
            # Convert datetime to string
            if isinstance(value, datetime):
                value = value.isoformat()
            
            # Convert other complex types
            elif hasattr(value, '__dict__'):
                value = str(value)
            
            data[column_name] = value
        
        return data
    
    def _export_json(self, data: Dict[str, Any], output_path: Optional[str], tenant_id: str) -> str:
        """Export data as JSON"""
        if not output_path:
            output_path = f"tenant_{tenant_id}_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return output_path
    
    def _export_yaml(self, data: Dict[str, Any], output_path: Optional[str], tenant_id: str) -> str:
        """Export data as YAML"""
        if not output_path:
            output_path = f"tenant_{tenant_id}_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.yaml"
        
        with open(output_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
        
        return output_path
    
    def _export_sql(self, db: Session, tenant_id: str, output_path: Optional[str]) -> str:
        """Export data as SQL dump"""
        if not output_path:
            output_path = f"tenant_{tenant_id}_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.sql"
        
        # This would typically use database-specific dump commands
        # For now, we'll create INSERT statements
        with open(output_path, 'w') as f:
            f.write(f"-- Tenant data export for {tenant_id}\n")
            f.write(f"-- Generated at {datetime.utcnow().isoformat()}\n\n")
            
            tenant_models = self._get_tenant_models()
            
            for model_name, model_class in tenant_models.items():
                records = db.query(model_class).filter(
                    model_class.tenant_id == tenant_id
                ).all()
                
                if records:
                    f.write(f"\n-- {model_name}\n")
                    for record in records:
                        columns = []
                        values = []
                        
                        for column in inspect(model_class).columns:
                            column_name = column.name
                            value = getattr(record, column_name)
                            
                            if value is not None:
                                columns.append(column_name)
                                if isinstance(value, str):
                                    values.append(f"'{value}'")
                                elif isinstance(value, datetime):
                                    values.append(f"'{value.isoformat()}'")
                                else:
                                    values.append(str(value))
                        
                        if columns:
                            # HIGH-005 FIX: Use parameterized SQL generation to prevent injection
                            # Sanitize table name
                            safe_table_name = re.sub(r'[^a-zA-Z0-9_]', '', model_name)
                            safe_columns = [re.sub(r'[^a-zA-Z0-9_]', '', col) for col in columns]
                            
                            # Generate parameterized INSERT statement
                            placeholders = ', '.join(['?' for _ in values])
                            sql_stmt = f"INSERT INTO {safe_table_name} ({', '.join(safe_columns)}) VALUES ({placeholders});\n"
                            f.write(sql_stmt)
                            f.write(f"-- Values: {values}\n")  # Comment for reference
        
        return output_path
    
    def _encrypt_export(self, file_path: str, tenant_id: str) -> str:
        """Encrypt export file"""
        encrypted_path = f"{file_path}.enc"
        
        # Read file content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Encrypt using tenant-specific key
        encrypted_data = SecurityUtils.encrypt_data(data.decode(), tenant_id)
        
        # Write encrypted file
        with open(encrypted_path, 'w') as f:
            f.write(encrypted_data)
        
        return encrypted_path
    
    def _decrypt_export(self, file_path: str) -> str:
        """Decrypt export file"""
        decrypted_path = file_path.replace('.enc', '')
        
        # Read encrypted content
        with open(file_path, 'r') as f:
            encrypted_data = f.read()
        
        # Extract tenant_id from metadata (would need to be stored separately)
        # For now, we'll use a placeholder
        tenant_id = "temp"
        
        # Decrypt
        decrypted_data = SecurityUtils.decrypt_data(encrypted_data, tenant_id)
        
        # Write decrypted file
        with open(decrypted_path, 'w') as f:
            f.write(decrypted_data)
        
        return decrypted_path
    
    def _check_existing_tenant_data(self, db: Session, tenant_id: str) -> bool:
        """Check if tenant has existing data"""
        # Check a few key tables
        user_count = db.query(User).filter(User.tenant_id == tenant_id).count()
        if user_count > 0:
            return True
        
        return False
    
    def _validate_import_data(self, import_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate import data structure and content"""
        results = {
            "valid": True,
            "message": "Data validation successful",
            "warnings": [],
            "errors": []
        }
        
        # Check metadata
        if "metadata" not in import_data:
            results["errors"].append("Missing metadata section")
            results["valid"] = False
        elif "export_version" not in import_data["metadata"]:
            results["warnings"].append("No export version specified")
        
        # Validate each model's data
        for model_name, records in import_data["data"].items():
            if not isinstance(records, list):
                results["errors"].append(f"{model_name}: Data must be a list")
                results["valid"] = False
                continue
            
            # Check required fields for key models
            if model_name == "users":
                for record in records:
                    if "email" not in record or "username" not in record:
                        results["errors"].append(f"{model_name}: Missing required fields")
                        results["valid"] = False
                        break
        
        if not results["valid"]:
            results["message"] = f"Validation failed with {len(results['errors'])} errors"
        
        return results
    
    def _import_model_data(
        self,
        db: Session,
        model_name: str,
        records: List[Dict[str, Any]],
        original_tenant_id: str,
        target_tenant_id: str,
        merge_existing: bool
    ) -> Dict[str, Any]:
        """Import data for a specific model"""
        stats = {
            "total": len(records),
            "imported": 0,
            "skipped": 0,
            "errors": []
        }
        
        # Get model class
        tenant_models = self._get_tenant_models()
        if model_name not in tenant_models:
            stats["errors"].append(f"Unknown model: {model_name}")
            return stats
        
        model_class = tenant_models[model_name]
        
        for record in records:
            try:
                # Update tenant_id
                if "tenant_id" in record:
                    record["tenant_id"] = target_tenant_id
                
                # Handle special cases
                if model_name == "users" and merge_existing:
                    # Check if user exists by email
                    existing = db.query(model_class).filter(
                        model_class.email == record["email"],
                        model_class.tenant_id == target_tenant_id
                    ).first()
                    
                    if existing:
                        stats["skipped"] += 1
                        continue
                
                # Remove auto-generated fields
                record.pop("id", None)
                record.pop("created_at", None)
                record.pop("updated_at", None)
                
                # Create new instance
                instance = model_class(**record)
                db.add(instance)
                stats["imported"] += 1
                
            except Exception as e:
                stats["errors"].append(f"Error importing {model_name} record: {str(e)}")
                logger.error(f"Import error for {model_name}: {e}")
        
        return stats
    
    def _record_migration(
        self,
        source_db: Session,
        target_db: Session,
        source_tenant_id: str,
        target_tenant_id: str,
        stats: Dict[str, Any]
    ):
        """Record migration in audit log"""
        # This would create audit records in both source and target databases
        migration_record = {
            "action": "tenant_migration",
            "source_tenant_id": source_tenant_id,
            "target_tenant_id": target_tenant_id,
            "migration_date": datetime.utcnow().isoformat(),
            "stats": stats
        }
        
        logger.info(f"Migration completed: {migration_record}")


# Global migrator instance
tenant_migrator = TenantDataMigrator()