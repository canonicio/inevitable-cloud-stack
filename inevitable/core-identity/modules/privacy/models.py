"""
Privacy/GDPR database models
"""
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Enum, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from datetime import datetime
from modules.core.database import Base, TimestampMixin, TenantMixin


class ConsentType(enum.Enum):
    """Types of consent that can be granted."""
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    THIRD_PARTY = "third_party"
    COOKIES = "cookies"
    DATA_PROCESSING = "data_processing"
    COMMUNICATIONS = "communications"


class DataRequestType(enum.Enum):
    """Types of data requests under GDPR."""
    ACCESS = "access"  # Right to access
    PORTABILITY = "portability"  # Right to data portability
    RECTIFICATION = "rectification"  # Right to rectification
    DELETION = "deletion"  # Right to erasure (right to be forgotten)
    RESTRICTION = "restriction"  # Right to restriction of processing
    OBJECTION = "objection"  # Right to object


class DataRequestStatus(enum.Enum):
    """Status of data requests."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Consent(Base, TimestampMixin, TenantMixin):
    """User consent records for GDPR compliance."""
    __tablename__ = "privacy_consents"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    consent_type = Column(Enum(ConsentType), nullable=False)
    granted = Column(Boolean, default=False, nullable=False)
    
    # Consent details
    purpose = Column(Text, nullable=False)
    description = Column(Text)
    version = Column(String(50), nullable=False)
    
    # Legal basis (for GDPR Article 6)
    legal_basis = Column(String(100))
    
    # Consent timestamps
    granted_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))
    
    # Consent method
    consent_method = Column(String(50))  # e.g., "checkbox", "explicit_action", "opt_in_form"
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="consents")
    
    # Indexes
    __table_args__ = (
        Index('idx_user_consent', 'user_id', 'consent_type'),
    )
    
    def is_valid(self):
        """Check if consent is currently valid."""
        if not self.granted or self.revoked_at:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True


class DataRequest(Base, TimestampMixin, TenantMixin):
    """Data requests from users (GDPR rights)."""
    __tablename__ = "privacy_data_requests"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    request_type = Column(Enum(DataRequestType), nullable=False)
    status = Column(Enum(DataRequestStatus), default=DataRequestStatus.PENDING, nullable=False)
    
    # Request details
    description = Column(Text)
    reason = Column(Text)
    
    # Processing details
    processed_by = Column(Integer, ForeignKey("users.id"))
    processed_at = Column(DateTime(timezone=True))
    processing_notes = Column(Text)
    
    # For data export requests
    export_format = Column(String(20))  # json, csv, pdf
    export_url = Column(Text)
    export_expires_at = Column(DateTime(timezone=True))
    
    # Verification
    verification_token = Column(String(255), unique=True)
    verified_at = Column(DateTime(timezone=True))
    
    # Legal compliance
    legal_deadline = Column(DateTime(timezone=True))  # GDPR requires response within 30 days
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="data_requests")
    processor = relationship("User", foreign_keys=[processed_by])


class PrivacyPolicy(Base, TimestampMixin):
    """Privacy policy versions."""
    __tablename__ = "privacy_policies"
    
    id = Column(Integer, primary_key=True)
    version = Column(String(50), unique=True, nullable=False)
    content = Column(Text, nullable=False)
    
    # Policy details
    effective_date = Column(DateTime(timezone=True), nullable=False)
    summary_of_changes = Column(Text)
    
    # Compliance info
    languages = Column(JSON)  # {"en": "content", "de": "inhalt", ...}
    requires_consent = Column(Boolean, default=True)
    
    # Publishing info
    published_by = Column(Integer, ForeignKey("users.id"))
    published_at = Column(DateTime(timezone=True), default=func.now())
    is_active = Column(Boolean, default=False)
    
    # Relationships
    publisher = relationship("User")
    acceptances = relationship("PrivacyPolicyAcceptance", back_populates="policy")


class PrivacyPolicyAcceptance(Base, TimestampMixin, TenantMixin):
    """User acceptances of privacy policies."""
    __tablename__ = "privacy_policy_acceptances"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    policy_id = Column(Integer, ForeignKey("privacy_policies.id"), nullable=False)
    
    # Acceptance details
    accepted_at = Column(DateTime(timezone=True), default=func.now())
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Relationships
    user = relationship("User")
    policy = relationship("PrivacyPolicy", back_populates="acceptances")
    
    # Unique constraint
    __table_args__ = (
        Index('idx_user_policy', 'user_id', 'policy_id', unique=True),
    )


class DataRetention(Base, TimestampMixin, TenantMixin):
    """Data retention policies for different data types."""
    __tablename__ = "privacy_data_retention"
    
    id = Column(Integer, primary_key=True)
    data_type = Column(String(100), unique=True, nullable=False)
    retention_days = Column(Integer, nullable=False)
    
    # Policy details
    description = Column(Text)
    legal_basis = Column(Text)
    auto_delete = Column(Boolean, default=True)
    
    # Exceptions
    exceptions = Column(JSON)  # {"condition": "rule", ...}


class DataProcessingActivity(Base, TimestampMixin, TenantMixin):
    """Record of processing activities (GDPR Article 30)."""
    __tablename__ = "privacy_processing_activities"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    
    # Processing details
    purposes = Column(JSON, nullable=False)  # List of purposes
    legal_basis = Column(String(100), nullable=False)
    data_categories = Column(JSON, nullable=False)  # List of data categories
    data_subjects = Column(JSON, nullable=False)  # List of data subject types
    
    # Recipients
    recipients = Column(JSON)  # List of recipients or categories
    third_country_transfers = Column(JSON)  # Details of transfers outside EU
    
    # Security and retention
    security_measures = Column(Text)
    retention_period = Column(String(255))
    
    # Compliance
    dpia_required = Column(Boolean, default=False)  # Data Protection Impact Assessment
    dpia_completed = Column(Boolean, default=False)
    dpia_document_url = Column(Text)
    
    # Ownership
    controller = Column(String(255))
    processor = Column(String(255))
    dpo_contact = Column(String(255))  # Data Protection Officer