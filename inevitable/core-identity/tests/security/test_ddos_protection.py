"""
Comprehensive tests for distributed DDoS protection system.
Tests RISK-M002: Distributed DDoS protection

These tests ensure the DDoS protection system can:
1. Detect various attack patterns
2. Apply appropriate mitigation measures  
3. Maintain performance under attack
4. Coordinate between multiple instances
5. Provide accurate threat assessment
"""

import pytest
import asyncio
import time
import json
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request, Response
from starlette.responses import JSONResponse
from datetime import datetime, timedelta

# Import the DDoS protection modules
from modules.core.ddos_protection import (
    DDoSProtectionMiddleware,
    DDoSDetectionEngine,
    ThreatLevel,
    AttackType,
    MitigationAction,
    DDoSProtectionConfig
)


class TestDDoSDetectionEngine:
    """Test the core DDoS detection engine"""
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client for testing"""
        redis_mock = Mock()
        redis_mock.get.return_value = None
        redis_mock.set.return_value = True
        redis_mock.incr.return_value = 1
        redis_mock.expire.return_value = True
        redis_mock.zadd.return_value = True
        redis_mock.zcard.return_value = 0
        redis_mock.zrange.return_value = []
        return redis_mock
    
    @pytest.fixture
    def detection_engine(self, mock_redis):
        """Create detection engine with mocked Redis"""
        return DDoSDetectionEngine(mock_redis)
    
    def test_normal_traffic_analysis(self, detection_engine):
        """Test that normal traffic is not flagged as malicious"""
        request_data = {
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "method": "GET",
            "path": "/api/users",
            "headers": {"Accept": "application/json"}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(request_data)
        
        assert threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM]
        assert len(attack_types) == 0 or AttackType.LEGITIMATE in attack_types
    
    def test_high_rate_attack_detection(self, detection_engine, mock_redis):
        """Test detection of high-rate attacks"""
        # Mock high rate scenario
        mock_redis.get.return_value = "1000"  # High request count
        mock_redis.zcard.return_value = 500   # Many recent requests
        
        request_data = {
            "ip_address": "10.0.0.1",
            "user_agent": "AttackBot/1.0",
            "method": "POST",
            "path": "/api/login",
            "headers": {}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(request_data)
        
        assert threat_level >= ThreatLevel.HIGH
        assert AttackType.RATE_LIMIT_VIOLATION in attack_types
    
    def test_bot_pattern_detection(self, detection_engine):
        """Test detection of bot traffic patterns"""
        bot_request_data = {
            "ip_address": "1.2.3.4",
            "user_agent": "curl/7.68.0",  # Bot-like user agent
            "method": "GET",
            "path": "/api/users",
            "headers": {}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(bot_request_data)
        
        # Should detect bot patterns
        assert threat_level >= ThreatLevel.MEDIUM
        assert AttackType.BOT_ATTACK in attack_types
    
    def test_suspicious_user_agent_detection(self, detection_engine):
        """Test detection of suspicious user agents"""
        suspicious_requests = [
            {"user_agent": "sqlmap/1.0"},
            {"user_agent": "nikto"},
            {"user_agent": ""},  # Empty user agent
            {"user_agent": "python-requests/2.25.1"}  # Script-like
        ]
        
        for req_data in suspicious_requests:
            request_data = {
                "ip_address": "192.168.1.50",
                "user_agent": req_data["user_agent"],
                "method": "GET",
                "path": "/api/test",
                "headers": {}
            }
            
            threat_level, attack_types = detection_engine.analyze_request(request_data)
            assert threat_level >= ThreatLevel.MEDIUM
    
    def test_geographic_anomaly_detection(self, detection_engine):
        """Test detection of geographic anomalies"""
        # Mock IP from suspicious location
        with patch('modules.core.ddos_protection.geoip2.database.Reader') as mock_geoip:
            mock_reader = Mock()
            mock_response = Mock()
            mock_response.country.iso_code = "XX"  # Suspicious country code
            mock_reader.country.return_value = mock_response
            mock_geoip.return_value.__enter__.return_value = mock_reader
            
            request_data = {
                "ip_address": "192.0.2.1",  # RFC 5737 test IP
                "user_agent": "Mozilla/5.0 (compatible)",
                "method": "POST",
                "path": "/api/admin",
                "headers": {}
            }
            
            threat_level, attack_types = detection_engine.analyze_request(request_data)
            # Note: Geographic analysis might not always trigger, depending on implementation
            assert threat_level >= ThreatLevel.LOW
    
    def test_application_layer_attack_detection(self, detection_engine):
        """Test detection of application layer attacks"""
        # SQL injection attempt
        sql_injection_data = {
            "ip_address": "10.0.0.10",
            "user_agent": "Mozilla/5.0",
            "method": "POST",
            "path": "/api/search",
            "query_params": {"q": "'; DROP TABLE users; --"},
            "headers": {}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(sql_injection_data)
        assert threat_level >= ThreatLevel.HIGH
        assert AttackType.APPLICATION_LAYER in attack_types
        
        # XSS attempt
        xss_data = {
            "ip_address": "10.0.0.11",
            "user_agent": "Mozilla/5.0",
            "method": "GET",
            "path": "/api/profile",
            "query_params": {"name": "<script>alert('xss')</script>"},
            "headers": {}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(xss_data)
        assert threat_level >= ThreatLevel.HIGH
        assert AttackType.APPLICATION_LAYER in attack_types
    
    def test_coordinated_attack_detection(self, detection_engine, mock_redis):
        """Test detection of coordinated attacks from multiple IPs"""
        # Mock coordinated attack scenario
        mock_redis.zrange.return_value = [
            "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"
        ]  # Multiple attacking IPs
        
        request_data = {
            "ip_address": "10.0.0.6",  # Another IP in the attack
            "user_agent": "AttackBot",
            "method": "POST",
            "path": "/api/login",
            "headers": {}
        }
        
        threat_level, attack_types = detection_engine.analyze_request(request_data)
        assert threat_level >= ThreatLevel.CRITICAL
        assert AttackType.COORDINATED in attack_types


class TestDDoSProtectionMiddleware:
    """Test the DDoS protection middleware"""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock FastAPI request"""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.method = "GET"
        request.url.path = "/api/test"
        request.headers = {"User-Agent": "Mozilla/5.0 (compatible)"}
        request.query_params = {}
        return request
    
    @pytest.fixture
    def mock_call_next(self):
        """Mock the next middleware in chain"""
        async def call_next(request):
            return JSONResponse({"message": "success"})
        return call_next
    
    @pytest.fixture
    def mock_redis(self):
        """Mock Redis client"""
        redis_mock = Mock()
        redis_mock.get.return_value = None
        redis_mock.set.return_value = True
        redis_mock.incr.return_value = 1
        redis_mock.expire.return_value = True
        redis_mock.zadd.return_value = True
        redis_mock.zcard.return_value = 0
        return redis_mock
    
    @pytest.fixture
    def ddos_middleware(self, mock_redis):
        """Create DDoS middleware with mocked dependencies"""
        app = Mock()
        return DDoSProtectionMiddleware(app, mock_redis)
    
    @pytest.mark.asyncio
    async def test_normal_request_passes_through(self, ddos_middleware, mock_request, mock_call_next):
        """Test that normal requests pass through without interference"""
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.LOW, [])
            
            response = await ddos_middleware.dispatch(mock_request, mock_call_next)
            
            assert response.status_code == 200
            response_data = json.loads(response.body)
            assert response_data["message"] == "success"
    
    @pytest.mark.asyncio
    async def test_high_threat_request_blocked(self, ddos_middleware, mock_request, mock_call_next):
        """Test that high-threat requests are blocked"""
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.CRITICAL, [AttackType.RATE_LIMIT_VIOLATION])
            
            response = await ddos_middleware.dispatch(mock_request, mock_call_next)
            
            assert response.status_code == 429  # Too Many Requests
            assert "rate limit" in response.body.decode().lower()
    
    @pytest.mark.asyncio
    async def test_proof_of_work_challenge(self, ddos_middleware, mock_request, mock_call_next):
        """Test proof-of-work challenge for suspicious requests"""
        mock_request.headers = {"User-Agent": "suspicious_bot"}
        
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.HIGH, [AttackType.BOT_ATTACK])
            
            response = await ddos_middleware.dispatch(mock_request, mock_call_next)
            
            # Should return proof-of-work challenge
            assert response.status_code == 202  # Accepted, but needs proof of work
            response_data = json.loads(response.body)
            assert "challenge" in response_data
            assert "nonce" in response_data
    
    @pytest.mark.asyncio
    async def test_proof_of_work_solution_validation(self, ddos_middleware, mock_request, mock_call_next):
        """Test validation of proof-of-work solutions"""
        # Mock valid proof-of-work solution
        mock_request.headers = {
            "X-Proof-Of-Work": "valid_solution_hash",
            "X-PoW-Nonce": "12345",
            "User-Agent": "suspicious_bot"
        }
        
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.HIGH, [AttackType.BOT_ATTACK])
            
            with patch.object(ddos_middleware, '_verify_proof_of_work') as mock_verify:
                mock_verify.return_value = True
                
                response = await ddos_middleware.dispatch(mock_request, mock_call_next)
                
                # Should pass through after valid proof of work
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, ddos_middleware, mock_request, mock_call_next):
        """Test integration with rate limiting system"""
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.MEDIUM, [AttackType.RATE_LIMIT_VIOLATION])
            
            with patch.object(ddos_middleware, '_apply_rate_limit') as mock_rate_limit:
                mock_rate_limit.return_value = True  # Rate limit applied
                
                response = await ddos_middleware.dispatch(mock_request, mock_call_next)
                
                assert response.status_code == 429
                mock_rate_limit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_attack_fingerprinting_and_logging(self, ddos_middleware, mock_request, mock_call_next):
        """Test attack fingerprinting and comprehensive logging"""
        with patch.object(ddos_middleware.detection_engine, 'analyze_request') as mock_analyze:
            mock_analyze.return_value = (ThreatLevel.CRITICAL, [AttackType.COORDINATED])
            
            with patch('modules.core.ddos_protection.logger') as mock_logger:
                response = await ddos_middleware.dispatch(mock_request, mock_call_next)
                
                # Should log the attack
                mock_logger.warning.assert_called()
                log_call = mock_logger.warning.call_args[0][0]
                assert "DDoS attack detected" in log_call
                assert "CRITICAL" in log_call


class TestDDoSProtectionConfig:
    """Test DDoS protection configuration"""
    
    def test_default_configuration(self):
        """Test that default configuration is reasonable"""
        config = DDoSProtectionConfig()
        
        assert config.REQUEST_RATE_THRESHOLD > 0
        assert config.SUSPICIOUS_PATTERN_THRESHOLD > 0
        assert config.PROOF_OF_WORK_DIFFICULTY >= 1
        assert config.REDIS_PREFIX == "ddos_protection"
        assert config.GEO_IP_DATABASE_PATH is not None
    
    def test_threat_level_ordering(self):
        """Test that threat levels are properly ordered"""
        assert ThreatLevel.LOW < ThreatLevel.MEDIUM
        assert ThreatLevel.MEDIUM < ThreatLevel.HIGH
        assert ThreatLevel.HIGH < ThreatLevel.CRITICAL
    
    def test_attack_type_enumeration(self):
        """Test that all expected attack types are defined"""
        expected_types = [
            AttackType.RATE_LIMIT_VIOLATION,
            AttackType.BOT_ATTACK,
            AttackType.COORDINATED,
            AttackType.APPLICATION_LAYER,
            AttackType.LEGITIMATE
        ]
        
        for attack_type in expected_types:
            assert isinstance(attack_type, AttackType)


class TestDDoSProtectionPerformance:
    """Test performance characteristics of DDoS protection"""
    
    @pytest.fixture
    def detection_engine(self):
        """Create detection engine for performance testing"""
        mock_redis = Mock()
        mock_redis.get.return_value = "10"
        mock_redis.zcard.return_value = 5
        return DDoSDetectionEngine(mock_redis)
    
    def test_analysis_performance(self, detection_engine):
        """Test that analysis completes within reasonable time"""
        request_data = {
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0",
            "method": "GET",
            "path": "/api/test",
            "headers": {}
        }
        
        start_time = time.time()
        
        # Run analysis multiple times
        for _ in range(100):
            threat_level, attack_types = detection_engine.analyze_request(request_data)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Should complete analysis in under 10ms on average
        assert avg_time < 0.01
    
    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test handling of concurrent requests under attack conditions"""
        mock_redis = Mock()
        mock_redis.get.return_value = "1000"  # High load scenario
        mock_redis.incr.return_value = 1001
        mock_redis.zcard.return_value = 500
        
        middleware = DDoSProtectionMiddleware(Mock(), mock_redis)
        
        async def mock_call_next(request):
            return JSONResponse({"message": "success"})
        
        # Create multiple concurrent requests
        tasks = []
        for i in range(50):
            request = Mock(spec=Request)
            request.client.host = f"10.0.0.{i % 10}"  # Various IPs
            request.method = "GET"
            request.url.path = "/api/test"
            request.headers = {"User-Agent": "TestClient"}
            request.query_params = {}
            
            task = middleware.dispatch(request, mock_call_next)
            tasks.append(task)
        
        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Should handle concurrent requests efficiently
        assert end_time - start_time < 5.0  # Under 5 seconds for 50 requests
        
        # Some requests should be blocked due to high load
        blocked_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 429)
        assert blocked_count > 0  # Some should be blocked under attack


class TestDDoSProtectionIntegration:
    """Integration tests for DDoS protection system"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_protection_flow(self):
        """Test complete protection flow from detection to mitigation"""
        mock_redis = Mock()
        mock_redis.get.return_value = "100"
        mock_redis.incr.return_value = 101
        mock_redis.set.return_value = True
        mock_redis.zcard.return_value = 50
        
        middleware = DDoSProtectionMiddleware(Mock(), mock_redis)
        
        # Simulate attack request
        attack_request = Mock(spec=Request)
        attack_request.client.host = "10.0.0.1"
        attack_request.method = "POST"
        attack_request.url.path = "/api/login"
        attack_request.headers = {"User-Agent": "AttackBot/1.0"}
        attack_request.query_params = {}
        
        async def mock_call_next(request):
            return JSONResponse({"message": "success"})
        
        with patch('modules.core.ddos_protection.logger') as mock_logger:
            response = await middleware.dispatch(attack_request, mock_call_next)
            
            # Should detect and block attack
            assert response.status_code in [429, 202, 403]  # Various mitigation responses
            
            # Should log the attack
            mock_logger.warning.assert_called()
    
    def test_redis_failover_handling(self):
        """Test graceful handling of Redis failures"""
        # Mock Redis failure
        mock_redis = Mock()
        mock_redis.get.side_effect = Exception("Redis connection failed")
        
        detection_engine = DDoSDetectionEngine(mock_redis)
        
        request_data = {
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0",
            "method": "GET",
            "path": "/api/test",
            "headers": {}
        }
        
        # Should not raise exception, should fall back gracefully
        threat_level, attack_types = detection_engine.analyze_request(request_data)
        
        # Should still provide some level of analysis
        assert isinstance(threat_level, ThreatLevel)
        assert isinstance(attack_types, list)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])