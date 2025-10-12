"""
Telemetry Client SDK for Platform Forge applications
"""
import os
import sys
import json
import platform
import asyncio
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import httpx
from cryptography.fernet import Fernet
import logging

from .models import TelemetryEvent, EventType, TelemetryConfig, UsageMetrics
from .privacy import PrivacyEngine, PrivacyMode

logger = logging.getLogger(__name__)


class TelemetryClient:
    """
    Client SDK included in generated applications for telemetry collection.
    
    Supports multiple modes:
    - callback: Real-time callbacks to control center
    - webhook: Event-based delivery
    - export: For airgapped environments
    - none: Disabled
    """
    
    def __init__(self, config: Optional[TelemetryConfig] = None):
        """Initialize telemetry client with configuration"""
        self.config = config or self._load_config_from_env()
        self.privacy_engine = PrivacyEngine(PrivacyMode(self.config.privacy_mode))
        self._buffer: List[TelemetryEvent] = []
        self._client = httpx.AsyncClient(timeout=10.0) if self.config.endpoint else None
        self._deployment_id = self._get_or_generate_deployment_id()
        self._running = False
        
        # Start background tasks if enabled
        if self.config.enabled and self.config.mode != "none":
            self._running = True
            if self.config.mode == "callback":
                asyncio.create_task(self._periodic_flush())
    
    def _load_config_from_env(self) -> TelemetryConfig:
        """Load configuration from environment variables"""
        return TelemetryConfig(
            enabled=os.getenv("TELEMETRY_ENABLED", "true").lower() == "true",
            mode=os.getenv("TELEMETRY_MODE", "callback"),
            endpoint=os.getenv("TELEMETRY_ENDPOINT"),
            api_key=os.getenv("TELEMETRY_API_KEY"),
            privacy_mode=os.getenv("TELEMETRY_PRIVACY_MODE", "standard"),
            batch_size=int(os.getenv("TELEMETRY_BATCH_SIZE", "100")),
            flush_interval=int(os.getenv("TELEMETRY_FLUSH_INTERVAL", "300"))
        )
    
    def _get_or_generate_deployment_id(self) -> str:
        """Get deployment ID from env or generate one"""
        deployment_id = os.getenv("DEPLOYMENT_ID")
        if not deployment_id:
            # Generate stable ID based on machine info
            machine_id = f"{platform.node()}-{platform.machine()}"
            deployment_id = hashlib.sha256(machine_id.encode()).hexdigest()[:16]
        return deployment_id
    
    async def track_deployment(self) -> None:
        """Track deployment start event"""
        if not self._should_track():
            return
        
        event = TelemetryEvent(
            deployment_id=self._deployment_id,
            event_type=EventType.DEPLOYMENT_START,
            data={
                "version": self._get_app_version(),
                "deployment_type": os.getenv("DEPLOYMENT_TYPE", "unknown"),
                "python_version": sys.version,
                "os": platform.system(),
                "architecture": platform.machine(),
                "modules": self._get_enabled_modules()
            }
        )
        
        await self._send_event(event)
    
    async def track_usage(self, metrics: UsageMetrics) -> None:
        """Track usage metrics"""
        if not self._should_track():
            return
        
        # Apply privacy filters
        filtered_metrics = self.privacy_engine.filter_metrics(metrics.model_dump())
        
        event = TelemetryEvent(
            deployment_id=self._deployment_id,
            event_type=EventType.USAGE_METRICS,
            data=filtered_metrics
        )
        
        await self._send_event(event)
    
    async def track_feature(self, feature_name: str, metadata: Optional[Dict] = None) -> None:
        """Track feature usage"""
        if not self._should_track() or self.config.privacy_mode == "maximum":
            return
        
        # Hash feature name in enhanced privacy mode
        if self.config.privacy_mode == "enhanced":
            feature_name = hashlib.sha256(feature_name.encode()).hexdigest()[:8]
        
        event = TelemetryEvent(
            deployment_id=self._deployment_id,
            event_type=EventType.FEATURE_USAGE,
            data={
                "feature": feature_name,
                "metadata": metadata or {}
            }
        )
        
        await self._send_event(event)
    
    async def track_error(self, error_type: str, error_code: Optional[str] = None) -> None:
        """Track error events (no sensitive data)"""
        if not self._should_track() or self.config.privacy_mode == "maximum":
            return
        
        event = TelemetryEvent(
            deployment_id=self._deployment_id,
            event_type=EventType.ERROR,
            data={
                "error_type": error_type,
                "error_code": error_code
            }
        )
        
        await self._send_event(event)
    
    async def validate_license(self) -> Dict[str, Any]:
        """Validate license with control center"""
        if not self.config.endpoint:
            return {"valid": True, "offline_mode": True}
        
        try:
            response = await self._client.post(
                f"{self.config.endpoint}/license/validate",
                json={
                    "deployment_id": self._deployment_id,
                    "api_key": self.config.api_key,
                    "version": self._get_app_version()
                }
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"License validation failed: {e}")
            # Fail open - don't break the app
            return {"valid": True, "offline_mode": True}
    
    async def export_telemetry(self, output_path: Optional[str] = None) -> str:
        """Export telemetry for airgapped environments"""
        if self.config.mode != "export":
            raise ValueError("Export only available in export mode")
        
        output_path = output_path or self.config.export_path
        if not output_path:
            raise ValueError("No export path specified")
        
        # Prepare export data
        export_data = {
            "deployment_id": self._deployment_id,
            "export_date": datetime.utcnow().isoformat(),
            "version": self._get_app_version(),
            "events": [event.model_dump() for event in self._buffer]
        }
        
        # Encrypt if configured
        if self.config.export_encryption:
            encrypted = self._encrypt_data(export_data)
            
            export_file = f"{output_path}/telemetry_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.enc"
            with open(export_file, 'wb') as f:
                f.write(encrypted)
        else:
            export_file = f"{output_path}/telemetry_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        # Clear buffer after export
        self._buffer.clear()
        
        return export_file
    
    async def shutdown(self) -> None:
        """Gracefully shutdown telemetry client"""
        self._running = False
        
        # Flush any remaining events
        if self._buffer and self.config.mode == "callback":
            await self._flush()
        
        # Close HTTP client
        if self._client:
            await self._client.aclose()
    
    # Private methods
    
    def _should_track(self) -> bool:
        """Check if tracking is enabled"""
        if not self.config.enabled:
            return False
        if self.config.mode == "none":
            return False
        if os.getenv("DO_NOT_TRACK", "0") == "1":
            return False
        return True
    
    async def _send_event(self, event: TelemetryEvent) -> None:
        """Send or buffer event based on mode"""
        if self.config.mode == "export":
            self._buffer.append(event)
            return
        
        if self.config.mode == "webhook":
            await self._send_immediate(event)
        else:  # callback mode
            self._buffer.append(event)
            if len(self._buffer) >= self.config.batch_size:
                await self._flush()
    
    async def _send_immediate(self, event: TelemetryEvent) -> None:
        """Send event immediately (webhook mode)"""
        if not self.config.endpoint:
            return
        
        try:
            await self._client.post(
                f"{self.config.endpoint}/events",
                json=event.model_dump(mode='json'),
                headers={"Authorization": f"Bearer {self.config.api_key}"}
            )
        except Exception as e:
            logger.error(f"Failed to send telemetry event: {e}")
    
    async def _flush(self) -> None:
        """Flush buffered events"""
        if not self._buffer or not self.config.endpoint:
            return
        
        events = self._buffer.copy()
        self._buffer.clear()
        
        try:
            await self._client.post(
                f"{self.config.endpoint}/events/batch",
                json={
                    "events": [e.model_dump(mode='json') for e in events],
                    "deployment_id": self._deployment_id,
                    "api_key": self.config.api_key
                }
            )
        except Exception as e:
            logger.error(f"Failed to flush telemetry: {e}")
            # Re-add events to buffer
            self._buffer.extend(events)
    
    async def _periodic_flush(self) -> None:
        """Periodically flush events"""
        while self._running:
            await asyncio.sleep(self.config.flush_interval)
            if self._buffer:
                await self._flush()
    
    def _get_app_version(self) -> str:
        """Get application version"""
        return os.getenv("APP_VERSION", "unknown")
    
    def _get_enabled_modules(self) -> List[str]:
        """Get list of enabled modules"""
        modules = []
        if os.getenv("MODULE_AUTH_ENABLED", "true") == "true":
            modules.append("auth")
        if os.getenv("MODULE_BILLING_ENABLED", "false") == "true":
            modules.append("billing")
        if os.getenv("MODULE_ADMIN_ENABLED", "false") == "true":
            modules.append("admin")
        if os.getenv("MODULE_OBSERVABILITY_ENABLED", "false") == "true":
            modules.append("observability")
        if os.getenv("MODULE_PRIVACY_ENABLED", "false") == "true":
            modules.append("privacy")
        return modules
    
    def _encrypt_data(self, data: Dict[str, Any]) -> bytes:
        """Encrypt data for export"""
        key = os.getenv("TELEMETRY_ENCRYPTION_KEY")
        if not key:
            key = Fernet.generate_key()
            logger.warning("No encryption key found, using generated key")
        
        f = Fernet(key)
        return f.encrypt(json.dumps(data, default=str).encode())