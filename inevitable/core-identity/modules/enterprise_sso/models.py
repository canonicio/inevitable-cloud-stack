"""
Database models for enterprise sso
"""
from sqlalchemy import Column, Integer, String, Text, JSON, Boolean, DateTime
from sqlalchemy.orm import relationship

from ..core.database import Base, TimestampMixin, TenantMixin


# Stub models - to be implemented


class SSOProvider(Base, TimestampMixin, TenantMixin):
    """SSOProvider model"""
    __tablename__ = "ssoproviders"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    description = Column(Text)
    config = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)


class SSOSession(Base, TimestampMixin, TenantMixin):
    """SSOSession model"""
    __tablename__ = "ssosessions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    description = Column(Text)
    config = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)


class SSOMapping(Base, TimestampMixin, TenantMixin):
    """SSOMapping model"""
    __tablename__ = "ssomappings"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    description = Column(Text)
    config = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
