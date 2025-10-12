"""
MCP Authentication Models
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, ForeignKey, Enum as SQLEnum
# from sqlalchemy.dialects.postgresql import UUID  # Disabled for SQLite compatibility
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
import enum
from modules.core.database import Base


class MCPPermissionType(str, enum.Enum):
    """MCP Permission Types"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"


class MCPResourceType(str, enum.Enum):
    """MCP Resource Types"""
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"
    SAMPLING = "sampling"
    ALL = "*"


class MCPAccessLevel(str, enum.Enum):
    """MCP Access Levels"""
    NONE = "none"
    LIMITED = "limited"
    STANDARD = "standard"
    ELEVATED = "elevated"
    FULL = "full"


class MCPPolicy(Base):
    """MCP Access Policy"""
    __tablename__ = "mcp_policies"
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID as string for SQLite
    name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Policy rules
    resource_type = Column(SQLEnum(MCPResourceType), nullable=False)
    resource_pattern = Column(String(255), nullable=False)  # e.g., "tool:*", "resource:database/*"
    permissions = Column(JSON, nullable=False)  # List of permissions
    conditions = Column(JSON)  # Additional conditions (time-based, IP-based, etc.)
    
    # Access control
    access_level = Column(SQLEnum(MCPAccessLevel), default=MCPAccessLevel.STANDARD)
    require_mfa = Column(Boolean, default=True)
    require_approval = Column(Boolean, default=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.id"))
    is_active = Column(Boolean, default=True)
    
    # Relationships
    sessions = relationship("MCPSession", back_populates="policy")
    audit_logs = relationship("MCPAuditLog", back_populates="policy")


class MCPSession(Base):
    """MCP Authentication Session"""
    __tablename__ = "mcp_sessions"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID as string for SQLite
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    policy_id = Column(Integer, ForeignKey("mcp_policies.id"), nullable=False)
    
    # Session details
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True, nullable=False)
    
    # Session metadata
    client_id = Column(String(100))  # MCP client identifier
    client_version = Column(String(50))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Session lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime)
    revoked_reason = Column(String(255))
    
    # MFA verification
    mfa_verified = Column(Boolean, default=False)
    mfa_verified_at = Column(DateTime)
    
    # Relationships
    policy = relationship("MCPPolicy", back_populates="sessions")
    audit_logs = relationship("MCPAuditLog", back_populates="session")
    user = relationship("User", back_populates="mcp_sessions")


class MCPAuditLog(Base):
    """MCP Access Audit Log"""
    __tablename__ = "mcp_audit_logs"
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID as string for SQLite
    session_id = Column(String(36), ForeignKey("mcp_sessions.id"), nullable=False)
    policy_id = Column(Integer, ForeignKey("mcp_policies.id"))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Action details
    action = Column(String(50), nullable=False)  # e.g., "tool.execute", "resource.read"
    resource_type = Column(SQLEnum(MCPResourceType), nullable=False)
    resource_name = Column(String(255), nullable=False)
    
    # Request/Response
    request_data = Column(JSON)  # Sanitized request data
    response_status = Column(String(20))  # success, denied, error
    response_data = Column(JSON)  # Sanitized response data
    error_message = Column(Text)
    
    # Performance metrics
    duration_ms = Column(Integer)  # Request duration in milliseconds
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    session = relationship("MCPSession", back_populates="audit_logs")
    policy = relationship("MCPPolicy", back_populates="audit_logs")
    user = relationship("User")


class MCPRoleMapping(Base):
    """Maps Platform Forge roles to MCP policies"""
    __tablename__ = "mcp_role_mappings"
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID as string for SQLite
    role_name = Column(String(50), nullable=False)  # Platform Forge role
    policy_ids = Column(JSON, nullable=False)  # List of MCP policy IDs
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MCPRateLimitRule(Base):
    """Rate limiting rules for MCP access"""
    __tablename__ = "mcp_rate_limit_rules"
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)  # UUID as string for SQLite
    policy_id = Column(Integer, ForeignKey("mcp_policies.id"))
    
    # Rate limit configuration
    resource_pattern = Column(String(255), nullable=False)
    max_requests = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    
    # Burst allowance
    burst_size = Column(Integer, default=0)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)