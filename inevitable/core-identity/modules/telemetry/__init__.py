"""
Platform Forge Telemetry Module

Provides enterprise-grade telemetry and tracking capabilities for distributed deployments.
Supports multiple privacy modes and deployment types (SaaS, Docker, K8s, Airgapped).
"""

from .client import TelemetryClient
from .models import TelemetryEvent, TelemetryConfig
from .privacy import PrivacyMode, PrivacyEngine

__all__ = [
    "TelemetryClient",
    "TelemetryEvent", 
    "TelemetryConfig",
    "PrivacyMode",
    "PrivacyEngine"
]