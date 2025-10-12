from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, UniqueConstraint, Table, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property
from modules.core.database import Base, TimestampMixin, TenantMixin
from modules.core.security import CryptoUtils

# Many-to-many association table for users and roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), server_default=func.now()),
    Column('granted_by', Integer, ForeignKey('users.id'), nullable=True),
    Column('tenant_id', String(255), nullable=False)
)


class User(Base, TimestampMixin, TenantMixin):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    first_name = Column(String(100))
    last_name = Column(String(100))
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime(timezone=True), nullable=True)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), server_default=func.now())
    token_version = Column(Integer, default=1, nullable=False)  # For session invalidation
    
    # MFA fields with automatic encryption
    mfa_enabled = Column(Boolean, default=False)
    _mfa_secret_encrypted = Column("mfa_secret_encrypted", Text, nullable=True)
    _backup_codes_encrypted = Column("backup_codes_encrypted", Text, nullable=True)
    mfa_methods = Column(JSON, nullable=True)  # Additional MFA methods (email, SMS)
    phone_number = Column(String(20), nullable=True)  # For SMS MFA
    
    # Lazy-loaded crypto utils instance
    _crypto_utils = None
    
    @property
    def crypto_utils(self):
        """Get crypto utils instance lazily"""
        if not self._crypto_utils:
            self._crypto_utils = CryptoUtils()
        return self._crypto_utils
    
    @hybrid_property
    def mfa_secret(self):
        """Decrypt MFA secret on access"""
        if not self._mfa_secret_encrypted or not self.tenant_id:
            return None
        return self.crypto_utils.decrypt_field(self._mfa_secret_encrypted, self.tenant_id)
    
    @mfa_secret.setter
    def mfa_secret(self, value):
        """Encrypt MFA secret on assignment"""
        if not value:
            self._mfa_secret_encrypted = None
            return
        if not self.tenant_id:
            raise ValueError("Cannot encrypt MFA secret without tenant_id")
        self._mfa_secret_encrypted = self.crypto_utils.encrypt_field(value, self.tenant_id)
    
    @hybrid_property
    def backup_codes(self):
        """Decrypt backup codes on access"""
        if not self._backup_codes_encrypted or not self.tenant_id:
            return None
        return self.crypto_utils.decrypt_field(self._backup_codes_encrypted, self.tenant_id)
    
    @backup_codes.setter
    def backup_codes(self, value):
        """Encrypt backup codes on assignment"""
        if not value:
            self._backup_codes_encrypted = None
            return
        if not self.tenant_id:
            raise ValueError("Cannot encrypt backup codes without tenant_id")
        self._backup_codes_encrypted = self.crypto_utils.encrypt_field(value, self.tenant_id)
    
    # Relationships
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    # audit_logs = relationship("AuditLog", back_populates="user")  # Moved to core.audit_logger
    roles = relationship("Role", secondary="user_roles", back_populates="users",
                        primaryjoin="User.id==user_roles.c.user_id",
                        secondaryjoin="Role.id==user_roles.c.role_id")
    mcp_sessions = relationship("MCPSession", back_populates="user")
    consents = relationship("Consent", back_populates="user")
    data_requests = relationship("DataRequest", back_populates="user", foreign_keys="DataRequest.user_id")
    # web3_accounts = relationship("Web3User", back_populates="user")  # Only enabled if web3_auth module is included
    
    # Unique constraints per tenant
    __table_args__ = (
        UniqueConstraint('email', 'tenant_id', name='_email_tenant_uc'),
        UniqueConstraint('username', 'tenant_id', name='_username_tenant_uc'),
    )


class RefreshToken(Base, TimestampMixin, TenantMixin):
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True)
    token = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="refresh_tokens")


# AuditLog moved to modules.core.audit_logger for comprehensive tamper-proof implementation
# class AuditLog(Base, TimestampMixin, TenantMixin):
#     __tablename__ = "audit_logs"
#     
#     id = Column(Integer, primary_key=True)
#     user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
#     action = Column(String(255), nullable=False)
#     resource_type = Column(String(100), nullable=True)
#     resource_id = Column(String(255), nullable=True)
#     ip_address = Column(String(45), nullable=True)
#     user_agent = Column(Text, nullable=True)
#     details = Column(Text, nullable=True)
#     
#     # Relationships
#     user = relationship("User", back_populates="audit_logs")


class Role(Base, TimestampMixin, TenantMixin):
    """Role model for RBAC system"""
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    is_system_role = Column(Boolean, default=False)  # System roles like super_admin
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles",
                        primaryjoin="Role.id==user_roles.c.role_id",
                        secondaryjoin="User.id==user_roles.c.user_id")
    permissions = relationship("Permission", back_populates="role", cascade="all, delete-orphan")
    
    # Unique constraint per tenant
    __table_args__ = (
        UniqueConstraint('name', 'tenant_id', name='_role_name_tenant_uc'),
    )


class Permission(Base, TimestampMixin, TenantMixin):
    """Permission model for RBAC system"""
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)  # e.g., "users:read", "billing:write"
    resource = Column(String(100), nullable=False)  # e.g., "users", "billing"
    action = Column(String(50), nullable=False)  # e.g., "read", "write", "delete"
    description = Column(String(255), nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    
    # Relationships
    role = relationship("Role", back_populates="permissions")
    
    # Unique constraint per role
    __table_args__ = (
        UniqueConstraint('name', 'role_id', name='_permission_name_role_uc'),
    )
