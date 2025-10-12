"""
Tests for telemetry module
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from modules.telemetry.client import TelemetryClient
from modules.telemetry.models import TelemetryConfig, TelemetryMode, EventType, UsageMetrics
from modules.telemetry.privacy import PrivacyEngine, PrivacyMode


class TestTelemetryClient:
    """Test telemetry client functionality"""
    
    @pytest.fixture
    def config(self):
        """Create test config"""
        return TelemetryConfig(
            enabled=True,
            mode=TelemetryMode.CALLBACK,
            endpoint="https://telemetry.example.com",
            api_key="test-api-key",
            privacy_mode="standard"
        )
    
    @pytest.fixture
    def client(self, config):
        """Create test client"""
        with patch("modules.telemetry.client.httpx.AsyncClient"):
            return TelemetryClient(config)
    
    @pytest.mark.asyncio
    async def test_track_deployment(self, client):
        """Test deployment tracking"""
        with patch.object(client, "_send_event") as mock_send:
            await client.track_deployment()
            
            # Verify event was sent
            mock_send.assert_called_once()
            event = mock_send.call_args[0][0]
            assert event.event_type == EventType.DEPLOYMENT_START
            assert event.deployment_id == client._deployment_id
    
    @pytest.mark.asyncio
    async def test_track_usage_with_privacy(self, client):
        """Test usage tracking with privacy filters"""
        metrics = UsageMetrics(
            active_users=100,
            total_users=500,
            api_requests=10000,
            database_size_mb=250.5
        )
        
        with patch.object(client, "_send_event") as mock_send:
            await client.track_usage(metrics)
            
            # Verify event was sent
            mock_send.assert_called_once()
            event = mock_send.call_args[0][0]
            assert event.event_type == EventType.USAGE_METRICS
            assert "active_users" in event.data
    
    @pytest.mark.asyncio
    async def test_privacy_mode_maximum(self, config):
        """Test maximum privacy mode"""
        config.privacy_mode = "maximum"
        client = TelemetryClient(config)
        
        # Feature tracking should be disabled
        with patch.object(client, "_send_event") as mock_send:
            await client.track_feature("test_feature")
            mock_send.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_export_mode(self):
        """Test export mode for airgapped environments"""
        config = TelemetryConfig(
            enabled=True,
            mode=TelemetryMode.EXPORT,
            export_path="/tmp/test_telemetry"
        )
        
        client = TelemetryClient(config)
        
        # Track some events
        await client.track_deployment()
        await client.track_error("test_error", "E001")
        
        # Export should work
        with patch("builtins.open", create=True) as mock_open:
            export_file = await client.export_telemetry("/tmp/test_telemetry")
            assert export_file.startswith("/tmp/test_telemetry/telemetry_")
            assert len(client._buffer) == 0  # Buffer should be cleared


class TestPrivacyEngine:
    """Test privacy engine functionality"""
    
    def test_minimal_privacy(self):
        """Test minimal privacy mode"""
        engine = PrivacyEngine(PrivacyMode.MINIMAL)
        
        data = {
            "deployment_id": "test-123",
            "version": "1.0.0",
            "user_id": "user-456",
            "api_requests": 1000,
            "timestamp": "2024-01-01T00:00:00"
        }
        
        filtered = engine.filter_event(data)
        
        # Should only include minimal fields
        assert "deployment_id" in filtered
        assert "version" in filtered
        assert "timestamp" in filtered
        assert "user_id" not in filtered
        assert "api_requests" not in filtered
    
    def test_standard_privacy(self):
        """Test standard privacy mode"""
        engine = PrivacyEngine(PrivacyMode.STANDARD)
        
        data = {
            "deployment_id": "test-123",
            "user_id": "user-456",
            "email": "test@example.com",
            "api_requests": 1000
        }
        
        filtered = engine.filter_event(data)
        
        # Should remove PII
        assert "deployment_id" in filtered
        assert "api_requests" in filtered
        assert "email" not in filtered
        assert "user_id" not in filtered
    
    def test_enhanced_privacy(self):
        """Test enhanced privacy mode"""
        engine = PrivacyEngine(PrivacyMode.ENHANCED)
        
        data = {
            "deployment_id": "test-123",
            "customer_id": "cust-789",
            "feature_usage": {"feature1": 10, "feature2": 20}
        }
        
        filtered = engine.filter_event(data)
        
        # Should hash identifiers
        assert filtered["deployment_id"] == "test-123"  # deployment_id not hashed
        assert "customer_id" in filtered
        assert filtered["customer_id"] != "cust-789"  # Should be hashed
    
    def test_ip_anonymization(self):
        """Test IP address anonymization"""
        engine = PrivacyEngine(PrivacyMode.STANDARD)
        
        # IPv4
        assert engine._anonymize_ip("192.168.1.100") == "192.168.1.0"
        
        # IPv6
        assert engine._anonymize_ip("2001:db8::1") == "2001:db8::0"
        
        # Maximum privacy
        engine.mode = PrivacyMode.MAXIMUM
        assert engine._anonymize_ip("192.168.1.100") == "0.0.0.0"


class TestTelemetryIntegration:
    """Integration tests for telemetry"""
    
    @pytest.mark.asyncio
    async def test_telemetry_disabled(self):
        """Test that telemetry respects disabled state"""
        config = TelemetryConfig(enabled=False)
        client = TelemetryClient(config)
        
        with patch.object(client, "_send_event") as mock_send:
            await client.track_deployment()
            await client.track_usage(UsageMetrics())
            await client.track_feature("test")
            
            # Nothing should be sent
            mock_send.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_do_not_track(self):
        """Test DO_NOT_TRACK environment variable"""
        config = TelemetryConfig(enabled=True)
        
        with patch.dict("os.environ", {"DO_NOT_TRACK": "1"}):
            client = TelemetryClient(config)
            
            with patch.object(client, "_send_event") as mock_send:
                await client.track_deployment()
                mock_send.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_license_validation(self, client):
        """Test license validation"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "valid": True,
            "expires_at": "2024-12-31T00:00:00",
            "features": ["telemetry", "advanced_analytics"]
        }
        
        with patch.object(client._client, "post", return_value=mock_response) as mock_post:
            result = await client.validate_license()
            
            assert result["valid"] is True
            assert "expires_at" in result
            mock_post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_batch_sending(self, config):
        """Test batch sending of events"""
        config.batch_size = 2
        client = TelemetryClient(config)
        
        with patch.object(client, "_flush") as mock_flush:
            # First event - should not flush
            await client.track_error("error1")
            mock_flush.assert_not_called()
            
            # Second event - should trigger flush
            await client.track_error("error2")
            mock_flush.assert_called_once()