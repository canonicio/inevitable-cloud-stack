from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from modules.core.database import Base, TimestampMixin, TenantMixin


class AdminRole(Base, TimestampMixin, TenantMixin):
    """Model for admin roles and permissions"""
    __tablename__ = "admin_roles"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255))
    permissions = Column(JSON, nullable=False)  # JSON array of permissions
    
    # Relationships
    user_roles = relationship("AdminUserRole", back_populates="role")


class AdminUserRole(Base, TimestampMixin, TenantMixin):
    """Model for user-role assignments"""
    __tablename__ = "admin_user_roles"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("admin_roles.id"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    role = relationship("AdminRole", back_populates="user_roles")


class SystemSetting(Base, TimestampMixin, TenantMixin):
    """Model for system-wide settings"""
    __tablename__ = "system_settings"
    
    id = Column(Integer, primary_key=True)
    key = Column(String(255), nullable=False, unique=True)
    value = Column(Text, nullable=False)
    description = Column(String(255))
    is_encrypted = Column(Boolean, default=False)
    modified_by = Column(Integer, ForeignKey("users.id"), nullable=True)


class MaintenanceMode(Base, TimestampMixin, TenantMixin):
    """Model for maintenance mode settings"""
    __tablename__ = "maintenance_mode"
    
    id = Column(Integer, primary_key=True)
    is_enabled = Column(Boolean, default=False)
    message = Column(Text, nullable=True)
    allowed_ips = Column(JSON, nullable=True)  # JSON array of allowed IPs
    enabled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    enabled_at = Column(DateTime(timezone=True), nullable=True)
    scheduled_end = Column(DateTime(timezone=True), nullable=True)


class APIKey(Base, TimestampMixin, TenantMixin):
    """Model for API keys"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    prefix = Column(String(20), nullable=False)  # First few chars for identification
    permissions = Column(JSON, nullable=False)  # JSON array of permissions
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)


class FeatureFlag(Base, TimestampMixin, TenantMixin):
    """Model for feature flags"""
    __tablename__ = "feature_flags"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(String(255))
    is_enabled = Column(Boolean, default=False)
    rollout_percentage = Column(Integer, default=0)  # 0-100
    config = Column(JSON, nullable=True)  # Additional configuration
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    enabled_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    enabled_at = Column(DateTime(timezone=True), nullable=True)


class BackupJob(Base, TimestampMixin, TenantMixin):
    """Model for backup jobs"""
    __tablename__ = "backup_jobs"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)  # database, files, etc.
    status = Column(String(50), nullable=False)  # scheduled, running, completed, failed
    schedule = Column(String(255), nullable=True)  # cron expression
    last_run = Column(DateTime(timezone=True), nullable=True)
    next_run = Column(DateTime(timezone=True), nullable=True)
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    retention_days = Column(Integer, default=30)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)