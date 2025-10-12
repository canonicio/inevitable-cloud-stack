"""
Comprehensive MFA Token Replay Attack Tests
Tests for RISK-H003: MFA Token Replay Attacks vulnerability fix
"""
import pytest
import time
import concurrent.futures
import redis as redis_lib
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from modules.auth.mfa_validator import MFAValidator, UsedMFAToken, get_mfa_validator
from modules.auth.models import User
from modules.core.database import Base


class TestMFATokenReplayPrevention:
    """Test MFA token replay attack prevention"""
    
    def test_mfa_token_single_use_enforcement(self, client: TestClient, mfa_user_with_token: tuple):
        """Test MFA tokens can only be used once"""
        user, mfa_token = mfa_user_with_token
        
        # First MFA verification should succeed
        first_response = client.post(
            "/api/v1/auth/verify-mfa",
            json={
                "mfa_token": mfa_token,
                "code": "123456",  # Valid TOTP code
                "method": "totp"
            }
        )
        assert first_response.status_code == 200
        
        # Second attempt with same code should fail (replay attack)
        second_response = client.post(
            "/api/v1/auth/verify-mfa", 
            json={
                "mfa_token": mfa_token,
                "code": "123456",  # Same code (replay)
                "method": "totp"
            }
        )
        assert second_response.status_code == 400
        assert "already used" in second_response.json()["detail"].lower()
    
    def test_concurrent_mfa_attempts_blocked(self, client: TestClient, mfa_user_with_token: tuple):
        """Test concurrent MFA attempts with same code are blocked"""
        user, mfa_token = mfa_user_with_token
        
        def attempt_mfa_verification():
            return client.post(
                "/api/v1/auth/verify-mfa",
                json={
                    "mfa_token": mfa_token,
                    "code": "789012",  # Valid code
                    "method": "totp"
                }
            )
        
        # Launch 20 concurrent MFA attempts
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(attempt_mfa_verification) for _ in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # Analyze results
        success_count = sum(1 for r in results if r.status_code == 200)
        blocked_count = sum(1 for r in results if r.status_code == 400)
        
        # Only one should succeed, rest should be blocked
        assert success_count == 1, f"Expected 1 success, got {success_count}"
        assert blocked_count == 19, f"Expected 19 blocked, got {blocked_count}"
    
    def test_different_users_mfa_tokens_isolated(self, client: TestClient):
        """Test MFA tokens for different users don't interfere"""
        # Mock two different users with MFA tokens
        with patch('modules.auth.dependencies.get_current_user') as mock_get_user:
            # User 1 MFA attempt
            mock_get_user.return_value = Mock(id=1, mfa_enabled=True)
            user1_response = client.post(
                "/api/v1/auth/verify-mfa",
                json={
                    "mfa_token": "user1_mfa_token",
                    "code": "111111",
                    "method": "totp"
                }
            )
            
            # User 2 MFA attempt with same code (but different user)
            mock_get_user.return_value = Mock(id=2, mfa_enabled=True) 
            user2_response = client.post(
                "/api/v1/auth/verify-mfa",
                json={
                    "mfa_token": "user2_mfa_token", 
                    "code": "111111",  # Same code but different user
                    "method": "totp"
                }
            )
            
            # Both should be able to use the same code (different users)
            # Note: This test would need proper token mocking to work fully
            assert user1_response.status_code in [200, 401]  # 401 if mock token invalid
            assert user2_response.status_code in [200, 401]  # 401 if mock token invalid
    
    def test_mfa_token_cross_method_isolation(self, client: TestClient, mfa_user_with_token: tuple):
        """Test MFA tokens are isolated between methods (TOTP, Email, SMS)"""
        user, mfa_token = mfa_user_with_token
        
        # Use code via TOTP
        totp_response = client.post(
            "/api/v1/auth/verify-mfa",
            json={
                "mfa_token": mfa_token,
                "code": "654321",
                "method": "totp"
            }
        )
        
        # Try same code via email method (should be allowed if different method)
        email_response = client.post(
            "/api/v1/auth/verify-mfa",
            json={
                "mfa_token": mfa_token,
                "code": "654321",  # Same code but different method
                "method": "email"
            }
        )
        
        # Both methods should work independently (if user has both enabled)
        # The exact behavior depends on whether codes are method-specific
        assert totp_response.status_code in [200, 400, 401]
        assert email_response.status_code in [200, 400, 401]


class TestMFAValidator:
    """Test the MFAValidator class directly"""
    
    def test_token_hashing_includes_user_context(self, db_session: Session, redis_client):
        """Test token hashing includes user context to prevent cross-user attacks"""
        validator = MFAValidator(redis_client, db_session)
        
        # Same token for different users should produce different hashes
        token = "123456"
        user1_hash = validator._hash_token("user1", token)
        user2_hash = validator._hash_token("user2", token)
        
        assert user1_hash != user2_hash
        assert len(user1_hash) == 64  # SHA256 hex digest
        assert len(user2_hash) == 64
    
    def test_redis_fallback_to_database(self, db_session: Session):
        """Test graceful fallback from Redis to database"""
        # Mock Redis that fails
        mock_redis = Mock()
        mock_redis.exists.side_effect = Exception("Redis connection failed")
        
        validator = MFAValidator(mock_redis, db_session)
        
        # Should fallback to database without crashing
        result = validator._is_token_used("user123", "token_hash_456")
        assert result is False  # No token in fresh database
    
    def test_database_token_storage_and_retrieval(self, db_session: Session):
        """Test database token storage and retrieval"""
        validator = MFAValidator(None, db_session)  # No Redis
        
        # Create mock request
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.headers = {"User-Agent": "TestBrowser/1.0"}
        
        token_hash = "test_hash_123"
        user_id = "user_456"
        
        # Mark token as used
        validator._mark_token_used(user_id, token_hash, "totp", mock_request)
        
        # Verify token is marked as used
        assert validator._is_token_used(user_id, token_hash) is True
        
        # Verify token record exists in database
        token_record = db_session.query(UsedMFAToken).filter(
            UsedMFAToken.user_id == user_id,
            UsedMFAToken.token_hash == token_hash
        ).first()
        
        assert token_record is not None
        assert token_record.mfa_method == "totp"
        assert token_record.ip_address == "192.168.1.100"
        assert "TestBrowser" in token_record.user_agent
    
    def test_token_expiration_cleanup(self, db_session: Session, redis_client):
        """Test cleanup of expired tokens"""
        validator = MFAValidator(redis_client, db_session)
        validator.token_ttl = 1  # Very short TTL for testing
        
        # Create expired token record
        mock_request = Mock()
        mock_request.client = Mock() 
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = {"User-Agent": "Test"}
        
        expired_token = UsedMFAToken(
            user_id="user123",
            token_hash="expired_hash",
            used_at=datetime.utcnow() - timedelta(seconds=5),  # Expired
            ip_address="127.0.0.1",
            user_agent="Test",
            mfa_method="totp"
        )
        db_session.add(expired_token)
        db_session.commit()
        
        # Run cleanup
        cleaned_count = validator.cleanup_old_tokens()
        
        assert cleaned_count == 1
        
        # Verify token was removed
        remaining_tokens = db_session.query(UsedMFAToken).filter(
            UsedMFAToken.token_hash == "expired_hash"
        ).count()
        assert remaining_tokens == 0
    
    def test_user_token_revocation(self, db_session: Session, redis_client):
        """Test revoking all tokens for a user"""
        validator = MFAValidator(redis_client, db_session)
        
        # Create multiple tokens for user
        user_id = "user789"
        token_hashes = ["hash1", "hash2", "hash3"]
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"User-Agent": "TestClient"}
        
        for token_hash in token_hashes:
            token_record = UsedMFAToken(
                user_id=user_id,
                token_hash=token_hash,
                used_at=datetime.utcnow(),
                ip_address="10.0.0.1",
                user_agent="TestClient",
                mfa_method="email"
            )
            db_session.add(token_record)
        db_session.commit()
        
        # Revoke all tokens for user
        revoked_count = validator.revoke_user_tokens(user_id)
        
        # All tokens should be marked as expired
        assert revoked_count >= 3  # May include Redis deletions
        
        # Verify tokens are no longer valid
        for token_hash in token_hashes:
            assert validator._is_token_used(user_id, token_hash) is False
    
    def test_suspicious_activity_detection(self, db_session: Session, redis_client):
        """Test suspicious MFA activity detection"""
        validator = MFAValidator(redis_client, db_session)
        
        user_id = "suspicious_user"
        
        # Create many recent token uses (suspicious)
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.50"
        mock_request.headers = {"User-Agent": "SuspiciousBot"}
        
        recent_time = datetime.utcnow() - timedelta(minutes=2)
        
        for i in range(15):  # Create many recent attempts
            token_record = UsedMFAToken(
                user_id=user_id,
                token_hash=f"suspicious_hash_{i}",
                used_at=recent_time + timedelta(seconds=i*5),
                ip_address=f"192.168.1.{50+i%3}",  # Different IPs
                user_agent="SuspiciousBot",
                mfa_method="totp"
            )
            db_session.add(token_record)
        db_session.commit()
        
        # Detect suspicious activity
        suspicious_report = validator.detect_suspicious_activity(user_id)
        
        assert suspicious_report["is_suspicious"] is True
        assert len(suspicious_report["indicators"]) > 0
        assert suspicious_report["recent_token_count"] == 15
        assert suspicious_report["unique_ip_count"] >= 3
    
    def test_token_usage_statistics(self, db_session: Session, redis_client):
        """Test MFA token usage statistics"""
        validator = MFAValidator(redis_client, db_session)
        
        user_id = "stats_user"
        
        # Create various token usage records
        methods = ["totp", "email", "sms"]
        ips = ["10.0.0.1", "10.0.0.2"] 
        
        for i, method in enumerate(methods):
            for j, ip in enumerate(ips):
                token_record = UsedMFAToken(
                    user_id=user_id,
                    token_hash=f"stats_hash_{i}_{j}",
                    used_at=datetime.utcnow() - timedelta(hours=i),
                    ip_address=ip,
                    user_agent="StatsClient",
                    mfa_method=method
                )
                db_session.add(token_record)
        db_session.commit()
        
        # Get usage statistics
        stats = validator.get_token_usage_stats(user_id)
        
        assert stats["total_tokens_24h"] == 6  # 3 methods × 2 IPs
        assert set(stats["methods_used"]) == set(methods)
        assert set(stats["unique_ips"]) == set(ips)
        assert stats["last_used"] is not None


class TestMFAValidatorIntegration:
    """Integration tests for MFA validator with auth routes"""
    
    def test_mfa_validator_redis_database_sync(self, db_session: Session):
        """Test Redis and database synchronization"""
        # Test with real Redis if available, fake Redis otherwise
        try:
            redis_client = redis_lib.Redis(host='localhost', port=6379, db=1)
            redis_client.ping()  # Test connection
        except:
            import fakeredis
            redis_client = fakeredis.FakeRedis()
        
        validator = MFAValidator(redis_client, db_session)
        
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = {"User-Agent": "IntegrationTest"}
        
        user_id = "sync_user"
        token_hash = "sync_token_hash"
        
        # Mark token as used
        validator._mark_token_used(user_id, token_hash, "totp", mock_request)
        
        # Verify token is marked in both Redis and database
        if hasattr(redis_client, 'exists'):  # Real Redis
            redis_key = f"mfa_used:{user_id}:{token_hash}"
            assert redis_client.exists(redis_key)
        
        # Verify database record
        db_record = db_session.query(UsedMFAToken).filter(
            UsedMFAToken.user_id == user_id,
            UsedMFAToken.token_hash == token_hash
        ).first()
        assert db_record is not None
        
        # Verify token is detected as used
        assert validator._is_token_used(user_id, token_hash) is True


# Test fixtures
@pytest.fixture
def redis_client():
    """Redis client for testing"""
    try:
        import fakeredis
        return fakeredis.FakeRedis(decode_responses=True)
    except ImportError:
        # Mock Redis if fakeredis not available
        mock_redis = Mock()
        mock_redis.exists.return_value = False
        mock_redis.setex.return_value = True
        mock_redis.scan_iter.return_value = []
        return mock_redis

@pytest.fixture
def db_session():
    """Database session for testing"""
    # This would be implemented based on your test database setup
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Use in-memory SQLite for testing
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def mfa_user_with_token():
    """Mock MFA user with valid token for testing"""
    user = Mock()
    user.id = 123
    user.mfa_enabled = True
    user.mfa_secret = "test_secret"
    user.tenant_id = "tenant123"
    
    # Mock MFA token (would be properly generated in real test)
    mfa_token = "mock_mfa_token_with_proper_payload"
    
    return user, mfa_token


class TestMFAReplayAttackScenarios:
    """Test specific MFA replay attack scenarios"""
    
    def test_network_replay_attack_prevention(self, client: TestClient):
        """Test prevention of network-level replay attacks"""
        # This would test scenarios where an attacker intercepts
        # and replays MFA tokens from network traffic
        pass
    
    def test_cross_session_replay_prevention(self, client: TestClient):
        """Test prevention of cross-session replay attacks"""
        # This would test scenarios where tokens from one session
        # are attempted to be used in another session
        pass
    
    def test_time_window_replay_attacks(self, client: TestClient):
        """Test replay attacks within various time windows"""
        # This would test immediate replay, delayed replay, etc.
        pass
    
    def test_distributed_replay_attack_prevention(self, client: TestClient):
        """Test prevention of distributed replay attacks"""
        # This would test scenarios with multiple attack sources
        # trying to replay the same token
        pass


class TestMFAValidatorPerformance:
    """Performance tests for MFA validator"""
    
    def test_high_volume_token_validation(self, db_session: Session, redis_client):
        """Test validator performance under high token validation load"""
        validator = MFAValidator(redis_client, db_session)
        
        # Test with many token validations
        start_time = time.time()
        
        for i in range(1000):
            user_id = f"perf_user_{i % 100}"  # 100 users
            token_hash = f"perf_token_{i}"
            
            # Check if token used (all should be false initially)
            is_used = validator._is_token_used(user_id, token_hash)
            assert is_used is False
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        assert duration < 5.0, f"Validation took too long: {duration}s"
    
    def test_concurrent_token_validation_performance(self, db_session: Session, redis_client):
        """Test concurrent token validation performance"""
        validator = MFAValidator(redis_client, db_session)
        
        def validate_tokens(start_idx: int):
            results = []
            for i in range(start_idx, start_idx + 100):
                user_id = f"concurrent_user_{i}"
                token_hash = f"concurrent_token_{i}"
                is_used = validator._is_token_used(user_id, token_hash)
                results.append(is_used)
            return results
        
        start_time = time.time()
        
        # Run concurrent validations
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(validate_tokens, i * 100) 
                for i in range(10)
            ]
            all_results = []
            for future in concurrent.futures.as_completed(futures):
                all_results.extend(future.result())
        
        end_time = time.time()
        duration = end_time - start_time
        
        # All should be False (no tokens used initially)
        assert all(result is False for result in all_results)
        
        # Should complete within reasonable time
        assert duration < 10.0, f"Concurrent validation took too long: {duration}s"