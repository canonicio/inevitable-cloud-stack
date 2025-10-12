"""
Comprehensive Session Hijacking Protection
Addresses RISK-M001: Session Hijacking protection
"""
import hashlib
import json
import logging
import time
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
import redis
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, Index

from ..core.database import Base
from ..core.config import settings
from .jwt_security import get_jwt_service

logger = logging.getLogger(__name__)


class SuspicionLevel(Enum):
    """Levels of suspicion for session anomaly detection"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class SessionAnomalyType(Enum):
    """Types of session anomalies that could indicate hijacking"""
    IP_CHANGE = "ip_change"
    USER_AGENT_CHANGE = "user_agent_change"
    GEOLOCATION_CHANGE = "geolocation_change"
    DEVICE_FINGERPRINT_CHANGE = "device_fingerprint_change"
    TIMING_ANOMALY = "timing_anomaly"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    CONCURRENT_SESSIONS = "concurrent_sessions"
    IMPOSSIBLE_TRAVEL = "impossible_travel"


class SessionSecurityEvent(Base):
    """Track session security events for analysis"""
    __tablename__ = "session_security_events"
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(255), nullable=False, index=True)
    user_id = Column(String(36), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    suspicion_level = Column(String(20), nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(64))
    geolocation = Column(Text)  # JSON with lat/lng/city/country
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    risk_score = Column(Integer, default=0)
    action_taken = Column(String(100))  # revoke, challenge, monitor, etc.
    additional_data = Column(Text)  # JSON with extra context
    
    # Indexes for efficient querying
    __table_args__ = (
        Index('idx_session_events', 'session_id', 'created_at'),
        Index('idx_user_events', 'user_id', 'created_at'),
        Index('idx_event_type', 'event_type', 'suspicion_level'),
    )


class SessionHijackingProtector:
    """
    Comprehensive session hijacking protection system
    
    Features:
    - Device fingerprinting with anomaly detection
    - IP address and geolocation monitoring
    - User agent consistency tracking
    - Behavioral pattern analysis
    - Impossible travel detection
    - Concurrent session limits
    - Risk-based session challenges
    """
    
    def __init__(self, redis_client: redis.Redis, db: Session):
        self.redis = redis_client
        self.db = db
        self.jwt_service = get_jwt_service()
        
        # Configuration
        self.config = {
            "max_concurrent_sessions": 3,
            "ip_change_threshold": SuspicionLevel.MEDIUM,
            "user_agent_change_threshold": SuspicionLevel.HIGH,
            "geolocation_change_threshold": SuspicionLevel.MEDIUM,
            "device_fingerprint_threshold": SuspicionLevel.CRITICAL,
            "impossible_travel_speed_kmh": 1000,  # Faster than commercial flights
            "challenge_high_risk": True,
            "revoke_critical_risk": True,
            "monitoring_window_hours": 24,
        }
    
    def generate_device_fingerprint(self, request: Request) -> str:
        """
        Generate comprehensive device fingerprint
        
        Combines multiple browser/device characteristics to create
        a unique identifier that's resistant to minor changes
        """
        # Extract browser/device characteristics
        user_agent = request.headers.get("User-Agent", "")
        accept = request.headers.get("Accept", "")
        accept_language = request.headers.get("Accept-Language", "")
        accept_encoding = request.headers.get("Accept-Encoding", "")
        
        # Get additional headers that help identify the client
        additional_headers = {
            "sec-ch-ua": request.headers.get("Sec-CH-UA", ""),
            "sec-ch-ua-mobile": request.headers.get("Sec-CH-UA-Mobile", ""),
            "sec-ch-ua-platform": request.headers.get("Sec-CH-UA-Platform", ""),
            "dnt": request.headers.get("DNT", ""),
            "upgrade-insecure-requests": request.headers.get("Upgrade-Insecure-Requests", ""),
        }
        
        # Create fingerprint data
        fingerprint_data = {
            "user_agent": user_agent[:200],  # Truncate to prevent overflow
            "accept": accept[:100],
            "accept_language": accept_language[:50],
            "accept_encoding": accept_encoding[:50],
            **additional_headers
        }
        
        # Create stable hash of fingerprint
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
        
        return fingerprint_hash
    
    def extract_session_context(self, request: Request) -> Dict[str, Any]:
        """Extract comprehensive session context from request"""
        return {
            "ip_address": self._get_client_ip(request),
            "user_agent": request.headers.get("User-Agent", "")[:500],
            "device_fingerprint": self.generate_device_fingerprint(request),
            "timestamp": datetime.utcnow().isoformat(),
            "request_headers": {
                k: v[:200] for k, v in request.headers.items()
                if k.lower() not in ["authorization", "cookie", "x-api-key"]
            }
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address considering proxies"""
        # Check various headers for the real IP
        headers_to_check = [
            "X-Forwarded-For",
            "X-Real-IP", 
            "X-Client-IP",
            "CF-Connecting-IP",  # Cloudflare
            "X-Forwarded"
        ]
        
        for header in headers_to_check:
            ip = request.headers.get(header)
            if ip:
                # X-Forwarded-For can contain multiple IPs, take the first
                return ip.split(',')[0].strip()
        
        # Fallback to direct client IP
        return getattr(request.client, 'host', 'unknown') if hasattr(request, 'client') else 'unknown'
    
    def validate_session_security(
        self, 
        session_id: str,
        user_id: str,
        request: Request
    ) -> Dict[str, Any]:
        """
        Comprehensive session security validation
        
        Returns validation result with risk score and recommended actions
        """
        current_context = self.extract_session_context(request)
        
        # Get stored session context
        stored_context = self._get_stored_session_context(session_id)
        
        if not stored_context:
            # First time seeing this session, store context
            self._store_session_context(session_id, user_id, current_context)
            return {
                "valid": True,
                "risk_score": 0,
                "suspicion_level": SuspicionLevel.NONE,
                "anomalies": [],
                "action": "monitor"
            }
        
        # Analyze for anomalies
        anomalies = self._detect_session_anomalies(
            session_id, user_id, stored_context, current_context
        )
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(anomalies)
        suspicion_level = self._get_suspicion_level(risk_score)
        
        # Determine action based on risk
        action = self._determine_security_action(suspicion_level, anomalies)
        
        # Log security event
        self._log_security_event(
            session_id, user_id, anomalies, suspicion_level, 
            risk_score, action, current_context
        )
        
        # Update stored context with current data
        self._update_session_context(session_id, current_context)
        
        return {
            "valid": action != "revoke",
            "risk_score": risk_score,
            "suspicion_level": suspicion_level,
            "anomalies": [a.value for a in anomalies],
            "action": action,
            "context": current_context
        }
    
    def _detect_session_anomalies(
        self,
        session_id: str,
        user_id: str, 
        stored_context: Dict[str, Any],
        current_context: Dict[str, Any]
    ) -> List[SessionAnomalyType]:
        """Detect various types of session anomalies"""
        anomalies = []
        
        # Check IP address changes
        if self._ip_changed_significantly(stored_context, current_context):
            anomalies.append(SessionAnomalyType.IP_CHANGE)
        
        # Check User-Agent changes
        if self._user_agent_changed(stored_context, current_context):
            anomalies.append(SessionAnomalyType.USER_AGENT_CHANGE)
        
        # Check device fingerprint
        if self._device_fingerprint_changed(stored_context, current_context):
            anomalies.append(SessionAnomalyType.DEVICE_FINGERPRINT_CHANGE)
        
        # Check for impossible travel
        if self._detect_impossible_travel(stored_context, current_context):
            anomalies.append(SessionAnomalyType.IMPOSSIBLE_TRAVEL)
        
        # Check concurrent sessions
        if self._check_concurrent_sessions(user_id):
            anomalies.append(SessionAnomalyType.CONCURRENT_SESSIONS)
        
        # Check timing anomalies
        if self._detect_timing_anomalies(session_id, stored_context, current_context):
            anomalies.append(SessionAnomalyType.TIMING_ANOMALY)
        
        return anomalies
    
    def _ip_changed_significantly(
        self, 
        stored_context: Dict[str, Any], 
        current_context: Dict[str, Any]
    ) -> bool:
        """Check if IP address changed significantly"""
        stored_ip = stored_context.get("ip_address", "")
        current_ip = current_context.get("ip_address", "")
        
        if stored_ip == current_ip:
            return False
        
        # Allow changes within the same /24 network (common for NAT)
        try:
            import ipaddress
            stored_network = ipaddress.IPv4Network(f"{stored_ip}/24", strict=False)
            current_addr = ipaddress.IPv4Address(current_ip)
            
            # If within same network, not suspicious
            if current_addr in stored_network:
                return False
        except (ipaddress.AddressValueError, ValueError):
            # If we can't parse IPs, treat as suspicious
            pass
        
        return True
    
    def _user_agent_changed(
        self,
        stored_context: Dict[str, Any],
        current_context: Dict[str, Any]
    ) -> bool:
        """Check if User-Agent changed suspiciously"""
        stored_ua = stored_context.get("user_agent", "")
        current_ua = current_context.get("user_agent", "")
        
        if stored_ua == current_ua:
            return False
        
        # Allow minor version changes in browsers
        import re
        
        # Extract major browser info (ignore minor versions)
        def normalize_ua(ua):
            # Remove version numbers for common browsers
            ua = re.sub(r'Chrome/[\d.]+', 'Chrome/X', ua)
            ua = re.sub(r'Firefox/[\d.]+', 'Firefox/X', ua)  
            ua = re.sub(r'Safari/[\d.]+', 'Safari/X', ua)
            ua = re.sub(r'Edge/[\d.]+', 'Edge/X', ua)
            return ua
        
        normalized_stored = normalize_ua(stored_ua)
        normalized_current = normalize_ua(current_ua)
        
        return normalized_stored != normalized_current
    
    def _device_fingerprint_changed(
        self,
        stored_context: Dict[str, Any],
        current_context: Dict[str, Any]
    ) -> bool:
        """Check if device fingerprint changed"""
        stored_fp = stored_context.get("device_fingerprint", "")
        current_fp = current_context.get("device_fingerprint", "")
        
        return stored_fp != current_fp and stored_fp and current_fp
    
    def _detect_impossible_travel(
        self,
        stored_context: Dict[str, Any],
        current_context: Dict[str, Any]
    ) -> bool:
        """Detect impossible travel between IP locations"""
        # This would integrate with a geolocation service
        # For now, implement basic logic
        
        stored_ip = stored_context.get("ip_address", "")
        current_ip = current_context.get("ip_address", "")
        
        if stored_ip == current_ip:
            return False
        
        # Get timestamps
        stored_time = stored_context.get("timestamp", "")
        current_time = current_context.get("timestamp", "")
        
        try:
            stored_dt = datetime.fromisoformat(stored_time.replace('Z', '+00:00'))
            current_dt = datetime.fromisoformat(current_time.replace('Z', '+00:00'))
            
            time_diff_hours = (current_dt - stored_dt).total_seconds() / 3600
            
            # If less than 1 hour, check if IPs are geographically distant
            if time_diff_hours < 1:
                # Simplified: different first two octets = potentially distant
                try:
                    stored_parts = stored_ip.split('.')[:2]
                    current_parts = current_ip.split('.')[:2]
                    
                    if stored_parts != current_parts:
                        return True  # Potentially impossible travel
                except:
                    pass
        
        except (ValueError, AttributeError):
            pass
        
        return False
    
    def _check_concurrent_sessions(self, user_id: str) -> bool:
        """Check if user has too many concurrent sessions"""
        pattern = f"session_context:*:user:{user_id}"
        session_keys = list(self.redis.scan_iter(match=pattern))
        
        return len(session_keys) > self.config["max_concurrent_sessions"]
    
    def _detect_timing_anomalies(
        self,
        session_id: str,
        stored_context: Dict[str, Any],
        current_context: Dict[str, Any]
    ) -> bool:
        """Detect suspicious timing patterns"""
        # Check request frequency patterns
        pattern = f"session_activity:{session_id}:*"
        recent_activities = list(self.redis.scan_iter(match=pattern))
        
        # If too many requests in a short time (bot-like behavior)
        if len(recent_activities) > 100:  # Configurable threshold
            return True
        
        return False
    
    def _calculate_risk_score(self, anomalies: List[SessionAnomalyType]) -> int:
        """Calculate risk score based on detected anomalies"""
        scores = {
            SessionAnomalyType.IP_CHANGE: 25,
            SessionAnomalyType.USER_AGENT_CHANGE: 40,
            SessionAnomalyType.GEOLOCATION_CHANGE: 30,
            SessionAnomalyType.DEVICE_FINGERPRINT_CHANGE: 70,
            SessionAnomalyType.TIMING_ANOMALY: 20,
            SessionAnomalyType.BEHAVIOR_ANOMALY: 35,
            SessionAnomalyType.CONCURRENT_SESSIONS: 15,
            SessionAnomalyType.IMPOSSIBLE_TRAVEL: 80,
        }
        
        total_score = sum(scores.get(anomaly, 0) for anomaly in anomalies)
        
        # Apply diminishing returns for multiple anomalies
        if len(anomalies) > 1:
            multiplier = 1 + (len(anomalies) - 1) * 0.3
            total_score = int(total_score * multiplier)
        
        return min(total_score, 100)  # Cap at 100
    
    def _get_suspicion_level(self, risk_score: int) -> SuspicionLevel:
        """Convert risk score to suspicion level"""
        if risk_score >= 80:
            return SuspicionLevel.CRITICAL
        elif risk_score >= 60:
            return SuspicionLevel.HIGH
        elif risk_score >= 30:
            return SuspicionLevel.MEDIUM
        elif risk_score >= 10:
            return SuspicionLevel.LOW
        else:
            return SuspicionLevel.NONE
    
    def _determine_security_action(
        self,
        suspicion_level: SuspicionLevel,
        anomalies: List[SessionAnomalyType]
    ) -> str:
        """Determine what security action to take"""
        if suspicion_level == SuspicionLevel.CRITICAL:
            if self.config["revoke_critical_risk"]:
                return "revoke"
            else:
                return "challenge"
        
        elif suspicion_level == SuspicionLevel.HIGH:
            if SessionAnomalyType.DEVICE_FINGERPRINT_CHANGE in anomalies:
                return "challenge"
            elif self.config["challenge_high_risk"]:
                return "challenge"
            else:
                return "monitor"
        
        elif suspicion_level == SuspicionLevel.MEDIUM:
            if SessionAnomalyType.IMPOSSIBLE_TRAVEL in anomalies:
                return "challenge"
            else:
                return "monitor"
        
        else:
            return "allow"
    
    def _get_stored_session_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get stored session context from Redis"""
        key = f"session_context:{session_id}"
        data = self.redis.get(key)
        
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                logger.error(f"Invalid session context data for {session_id}")
        
        return None
    
    def _store_session_context(
        self, 
        session_id: str, 
        user_id: str,
        context: Dict[str, Any]
    ) -> None:
        """Store session context in Redis with appropriate TTL"""
        key = f"session_context:{session_id}"
        user_key = f"session_context:{session_id}:user:{user_id}"
        
        # Store for 24 hours
        ttl = 24 * 60 * 60
        
        context_data = {
            **context,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat()
        }
        
        self.redis.setex(key, ttl, json.dumps(context_data))
        self.redis.setex(user_key, ttl, session_id)  # For user session tracking
    
    def _update_session_context(self, session_id: str, context: Dict[str, Any]) -> None:
        """Update stored session context with new data"""
        stored = self._get_stored_session_context(session_id)
        if stored:
            stored.update(context)
            stored["last_updated"] = datetime.utcnow().isoformat()
            
            key = f"session_context:{session_id}"
            ttl = self.redis.ttl(key)
            if ttl > 0:
                self.redis.setex(key, ttl, json.dumps(stored))
    
    def _log_security_event(
        self,
        session_id: str,
        user_id: str,
        anomalies: List[SessionAnomalyType],
        suspicion_level: SuspicionLevel,
        risk_score: int,
        action: str,
        context: Dict[str, Any]
    ) -> None:
        """Log security event to database and logger"""
        try:
            # Log to database
            for anomaly in anomalies:
                event = SessionSecurityEvent(
                    session_id=session_id,
                    user_id=user_id,
                    event_type=anomaly.value,
                    suspicion_level=suspicion_level.name,
                    ip_address=context.get("ip_address", ""),
                    user_agent=context.get("user_agent", "")[:1000],
                    device_fingerprint=context.get("device_fingerprint", ""),
                    risk_score=risk_score,
                    action_taken=action,
                    additional_data=json.dumps({
                        "all_anomalies": [a.value for a in anomalies],
                        "context_snapshot": context
                    })
                )
                self.db.add(event)
            
            self.db.commit()
            
            # Log to application logger
            logger.warning(
                f"Session security event: user={user_id}, session={session_id[:8]}..., "
                f"risk={risk_score}, level={suspicion_level.name}, "
                f"anomalies={[a.value for a in anomalies]}, action={action}"
            )
        
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
            try:
                self.db.rollback()
            except:
                pass
    
    def challenge_session(self, session_id: str, user_id: str) -> Dict[str, Any]:
        """
        Issue session challenge (e.g., require re-authentication or MFA)
        """
        challenge_id = secrets.token_urlsafe(32)
        challenge_data = {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=15)).isoformat(),
            "type": "security_challenge",
            "attempts": 0
        }
        
        # Store challenge in Redis
        key = f"session_challenge:{challenge_id}"
        self.redis.setex(key, 15 * 60, json.dumps(challenge_data))  # 15 min expiry
        
        logger.info(f"Issued security challenge for session {session_id[:8]}...")
        
        return {
            "challenge_required": True,
            "challenge_id": challenge_id,
            "message": "Additional verification required for security",
            "type": "mfa_required"  # Or "re_auth_required"
        }
    
    def revoke_session(self, session_id: str, reason: str = "security_violation") -> bool:
        """
        Revoke session due to security concerns
        """
        try:
            # Remove from Redis
            keys_to_delete = [
                f"session_context:{session_id}",
                f"session:{session_id}",
                f"session_challenge:{session_id}"
            ]
            
            for key in keys_to_delete:
                self.redis.delete(key)
            
            # If session is JWT-based, add to revocation list
            # This would need the actual JWT token, not just session ID
            
            logger.warning(f"Revoked session {session_id[:8]}... due to {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke session {session_id}: {e}")
            return False
    
    def get_user_security_summary(self, user_id: str) -> Dict[str, Any]:
        """Get security summary for user's sessions"""
        try:
            # Get recent security events
            recent_events = self.db.query(SessionSecurityEvent).filter(
                SessionSecurityEvent.user_id == user_id,
                SessionSecurityEvent.created_at >= datetime.utcnow() - timedelta(hours=24)
            ).all()
            
            # Count events by type and severity
            events_by_type = {}
            events_by_severity = {}
            
            for event in recent_events:
                events_by_type[event.event_type] = events_by_type.get(event.event_type, 0) + 1
                events_by_severity[event.suspicion_level] = events_by_severity.get(event.suspicion_level, 0) + 1
            
            # Find active sessions
            pattern = f"session_context:*:user:{user_id}"
            active_sessions = len(list(self.redis.scan_iter(match=pattern)))
            
            return {
                "user_id": user_id,
                "active_sessions": active_sessions,
                "security_events_24h": len(recent_events),
                "events_by_type": events_by_type,
                "events_by_severity": events_by_severity,
                "high_risk_events": len([e for e in recent_events if e.suspicion_level in ["HIGH", "CRITICAL"]]),
                "last_security_event": recent_events[-1].created_at.isoformat() if recent_events else None
            }
        
        except Exception as e:
            logger.error(f"Failed to get security summary for user {user_id}: {e}")
            return {"error": str(e)}


# Global instance
_session_protector = None

def get_session_hijacking_protector(redis_client: redis.Redis, db: Session) -> SessionHijackingProtector:
    """Get session hijacking protector instance"""
    global _session_protector
    
    if _session_protector is None:
        _session_protector = SessionHijackingProtector(redis_client, db)
    
    return _session_protector


def session_security_middleware(
    session_id: str,
    user_id: str, 
    request: Request,
    redis_client: redis.Redis,
    db: Session
) -> Dict[str, Any]:
    """
    Middleware function for session security validation
    
    Call this from your FastAPI dependencies or middleware
    """
    protector = get_session_hijacking_protector(redis_client, db)
    
    result = protector.validate_session_security(session_id, user_id, request)
    
    if result["action"] == "revoke":
        protector.revoke_session(session_id, "security_violation")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session terminated due to security concerns"
        )
    elif result["action"] == "challenge":
        challenge_info = protector.challenge_session(session_id, user_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=challenge_info
        )
    
    return result