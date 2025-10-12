"""
Telemetry data models
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Boolean, Integer, ForeignKey, Index
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field, ConfigDict
from enum import Enum

from modules.core.database import Base, TimestampMixin, TenantMixin


class TelemetryMode(str, Enum):
    """Telemetry collection modes"""
    CALLBACK = "callback"      # Real-time callbacks to control center
    WEBHOOK = "webhook"        # Webhook-based event delivery
    EXPORT = "export"          # Export for airgapped environments
    NONE = "none"              # No telemetry


class EventType(str, Enum):
    """Types of telemetry events"""
    DEPLOYMENT_START = "deployment_start"
    DEPLOYMENT_STOP = "deployment_stop"
    USAGE_METRICS = "usage_metrics"
    FEATURE_USAGE = "feature_usage"
    ERROR = "error"
    LICENSE_CHECK = "license_check"
    HEALTH_CHECK = "health_check"
    SECURITY_EVENT = "security_event"


# SQLAlchemy Models (for collector service)
class TelemetryDeployment(Base, TimestampMixin):
    """Track deployments across all environments"""
    __tablename__ = "telemetry_deployments"
    
    id = Column(String, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    deployment_type = Column(String)  # saas, docker, k8s, hybrid
    version = Column(String)
    status = Column(String)  # active, inactive, expired
    last_seen = Column(DateTime, default=datetime.utcnow)
    deployment_extra_metadata = Column(JSON)
    
    # Relationships
    events = relationship("TelemetryEventRecord", back_populates="deployment")
    
    # Indexes for performance
    __table_args__ = (
        Index("ix_telemetry_deployments_customer", "customer_id"),
        Index("ix_telemetry_deployments_status", "status"),
    )


class TelemetryEventRecord(Base, TimestampMixin):
    """Store telemetry events"""
    __tablename__ = "telemetry_events"
    
    id = Column(Integer, primary_key=True)
    deployment_id = Column(String, ForeignKey("telemetry_deployments.id"), nullable=False)
    event_type = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    data = Column(JSON)
    
    # Privacy fields
    anonymized = Column(Boolean, default=False)
    privacy_mode = Column(String)
    
    # Relationships
    deployment = relationship("TelemetryDeployment", back_populates="events")
    
    # Indexes
    __table_args__ = (
        Index("ix_telemetry_events_deployment", "deployment_id"),
        Index("ix_telemetry_events_type", "event_type"),
        Index("ix_telemetry_events_timestamp", "timestamp"),
    )


# Pydantic Models (for API)
class TelemetryConfig(BaseModel):
    """Configuration for telemetry client"""
    model_config = ConfigDict(from_attributes=True)
    
    enabled: bool = True
    mode: TelemetryMode = TelemetryMode.CALLBACK
    endpoint: Optional[str] = None
    api_key: Optional[str] = None
    privacy_mode: str = "standard"
    batch_size: int = 100
    flush_interval: int = 300  # seconds
    
    # Privacy settings
    anonymize_users: bool = False
    aggregate_metrics: bool = True
    retention_days: int = 90
    
    # Export settings (for airgapped)
    export_path: Optional[str] = None
    export_schedule: str = "daily"
    export_encryption: Optional[str] = "pgp"


class TelemetryEvent(BaseModel):
    """Individual telemetry event"""
    model_config = ConfigDict(from_attributes=True)
    
    deployment_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = Field(default_factory=dict)
    
    # Optional fields
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    

class TelemetryBatch(BaseModel):
    """Batch of telemetry events"""
    model_config = ConfigDict(from_attributes=True)
    
    events: List[TelemetryEvent]
    deployment_id: str
    api_key: str


class UsageMetrics(BaseModel):
    """Standard usage metrics"""
    model_config = ConfigDict(from_attributes=True)
    
    active_users: int = 0
    total_users: int = 0
    api_requests: int = 0
    api_errors: int = 0
    database_size_mb: float = 0
    storage_used_mb: float = 0
    compute_hours: float = 0
    
    # Feature-specific metrics
    feature_usage: Dict[str, int] = Field(default_factory=dict)
    
    # Performance metrics
    avg_response_time_ms: float = 0
    p95_response_time_ms: float = 0
    error_rate: float = 0


class LicenseValidation(BaseModel):
    """License validation request/response"""
    model_config = ConfigDict(from_attributes=True)
    
    deployment_id: str
    api_key: str
    version: str
    
    # Response fields
    valid: Optional[bool] = None
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None
    features: Optional[List[str]] = None
    limits: Optional[Dict[str, Any]] = None


class AlertConfiguration(BaseModel):
    """Alert configuration for deployments"""
    model_config = ConfigDict(from_attributes=True)
    
    deployment_id: Optional[str] = None  # None means all deployments
    alert_type: str  # usage_spike, error_rate, license_expiry, etc.
    threshold: Dict[str, Any]
    notification_channels: List[str]  # email, slack, webhook
    enabled: bool = True