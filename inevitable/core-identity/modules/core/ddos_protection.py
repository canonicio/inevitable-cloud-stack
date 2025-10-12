"""
Advanced Distributed DDoS Protection System
Addresses RISK-M002: Distributed DDoS protection
"""
import asyncio
import hashlib
import json
import logging
import time
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
import redis
from redis.exceptions import RedisError
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, DateTime, Integer, Text, Boolean, Float, Index

from ..core.database import Base
from ..core.config import settings

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """DDoS threat severity levels"""
    NORMAL = 0
    ELEVATED = 1
    HIGH = 2
    SEVERE = 3
    EMERGENCY = 4


class AttackType(Enum):
    """Types of DDoS attacks"""
    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    SLOWLORIS = "slowloris"
    AMPLIFICATION = "amplification"
    BOTNET = "botnet"
    LAYER7 = "layer7"
    RATE_BASED = "rate_based"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class DDoSEvent(Base):
    """Database model for DDoS attack events"""
    __tablename__ = "ddos_events"
    
    id = Column(Integer, primary_key=True)
    attack_id = Column(String(64), nullable=False, index=True)
    attack_type = Column(String(50), nullable=False)
    threat_level = Column(String(20), nullable=False)
    source_ip = Column(String(45), index=True)
    source_network = Column(String(20))  # CIDR block
    user_agent = Column(Text)
    target_endpoint = Column(String(255), index=True)
    request_rate = Column(Float)  # Requests per second
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime)
    duration_seconds = Column(Integer)
    total_requests = Column(Integer, default=0)
    blocked_requests = Column(Integer, default=0)
    mitigation_actions = Column(Text)  # JSON array of actions taken
    geolocation = Column(Text)  # JSON with geo data
    fingerprint = Column(String(64), index=True)  # Attack fingerprint
    is_active = Column(Boolean, default=True, nullable=False)
    severity_score = Column(Integer, default=0)
    
    __table_args__ = (
        Index('idx_ddos_active', 'is_active', 'started_at'),
        Index('idx_ddos_source', 'source_ip', 'started_at'),
        Index('idx_ddos_type', 'attack_type', 'threat_level'),
    )


class DDoSProtectionConfig:
    """Configuration for DDoS protection system"""
    
    # Request rate thresholds (requests per second)
    NORMAL_RATE_THRESHOLD = 10
    ELEVATED_RATE_THRESHOLD = 50
    HIGH_RATE_THRESHOLD = 100
    SEVERE_RATE_THRESHOLD = 200
    EMERGENCY_RATE_THRESHOLD = 500
    
    # Time windows for analysis (seconds)
    ANALYSIS_WINDOWS = {
        "short": 60,    # 1 minute
        "medium": 300,  # 5 minutes
        "long": 900     # 15 minutes
    }
    
    # Pattern detection thresholds
    PATTERN_DETECTION = {
        "identical_requests_threshold": 50,  # Same request repeated
        "user_agent_diversity_threshold": 0.1,  # Low UA diversity indicates bot
        "request_timing_variance_threshold": 0.05,  # Very regular timing
        "error_rate_threshold": 0.8,  # High error rate
        "geographic_concentration_threshold": 0.9  # Requests from single geo region
    }
    
    # Mitigation thresholds
    MITIGATION_THRESHOLDS = {
        ThreatLevel.ELEVATED: {
            "rate_limit_factor": 0.5,  # Reduce rate limits by 50%
            "challenge_probability": 0.1  # Challenge 10% of requests
        },
        ThreatLevel.HIGH: {
            "rate_limit_factor": 0.3,  # Reduce rate limits by 70%
            "challenge_probability": 0.3,  # Challenge 30% of requests
            "block_suspicious_ips": True
        },
        ThreatLevel.SEVERE: {
            "rate_limit_factor": 0.1,  # Reduce rate limits by 90%
            "challenge_probability": 0.7,  # Challenge 70% of requests
            "block_suspicious_ips": True,
            "enable_proof_of_work": True
        },
        ThreatLevel.EMERGENCY: {
            "rate_limit_factor": 0.05,  # Reduce rate limits by 95%
            "challenge_probability": 0.9,  # Challenge 90% of requests
            "block_suspicious_ips": True,
            "enable_proof_of_work": True,
            "emergency_mode": True
        }
    }
    
    # IP reputation and blocking
    REPUTATION_THRESHOLDS = {
        "malicious_score": 80,  # Block IPs with score > 80
        "suspicious_score": 60,  # Challenge IPs with score > 60
        "reputation_decay": 0.95  # Daily decay factor
    }
    
    # Geographic filtering (optional)
    GEOGRAPHIC_FILTERING = {
        "enable_geo_blocking": False,
        "blocked_countries": [],  # ISO country codes
        "allowed_countries": [],  # If set, only allow these
        "suspicious_countries": []  # Challenge requests from these
    }
    
    # Advanced detection parameters
    ADVANCED_DETECTION = {
        "entropy_threshold": 3.5,  # Minimum entropy in request patterns
        "clustering_threshold": 0.8,  # Similarity threshold for clustering
        "anomaly_detection_window": 300,  # 5 minutes
        "baseline_learning_period": 3600,  # 1 hour to establish baseline
        "false_positive_tolerance": 0.05  # 5% false positive tolerance
    }


class AttackSignature:
    """Represents the signature/fingerprint of a DDoS attack"""
    
    def __init__(self):
        self.request_patterns = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.source_ips = set()
        self.target_endpoints = defaultdict(int)
        self.timing_intervals = []
        self.http_methods = defaultdict(int)
        self.payload_hashes = defaultdict(int)
        self.geographic_sources = defaultdict(int)
        
    def add_request(self, request_data: Dict[str, Any]) -> None:
        """Add request data to the attack signature"""
        # Build pattern from request
        pattern = self._create_pattern(request_data)
        self.request_patterns[pattern] += 1
        
        # Track user agent
        ua = request_data.get("user_agent", "")
        self.user_agents[ua[:100]] += 1  # Limit length
        
        # Track source IP
        ip = request_data.get("ip_address", "")
        self.source_ips.add(ip)
        
        # Track target endpoint
        endpoint = request_data.get("endpoint", "")
        self.target_endpoints[endpoint] += 1
        
        # Track timing
        timestamp = request_data.get("timestamp", time.time())
        self.timing_intervals.append(timestamp)
        
        # Track HTTP method
        method = request_data.get("method", "GET")
        self.http_methods[method] += 1
        
        # Track payload hash (for POST requests)
        payload = request_data.get("payload", "")
        if payload:
            payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()[:16]
            self.payload_hashes[payload_hash] += 1
        
        # Track geographic source
        geo = request_data.get("country", "unknown")
        self.geographic_sources[geo] += 1
    
    def _create_pattern(self, request_data: Dict[str, Any]) -> str:
        """Create a pattern string from request data"""
        pattern_elements = [
            request_data.get("method", "GET"),
            request_data.get("endpoint", "/"),
            str(len(request_data.get("query_params", {}))),
            str(len(request_data.get("headers", {}))),
            request_data.get("content_type", "")[:20]
        ]
        return "|".join(pattern_elements)
    
    def calculate_entropy(self) -> float:
        """Calculate entropy of request patterns"""
        if not self.request_patterns:
            return 0.0
        
        total_requests = sum(self.request_patterns.values())
        entropy = 0.0
        
        for count in self.request_patterns.values():
            probability = count / total_requests
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Modified entropy formula
        
        return entropy
    
    def get_fingerprint(self) -> str:
        """Generate a unique fingerprint for this attack signature"""
        fingerprint_data = {
            "top_patterns": sorted(self.request_patterns.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_user_agents": sorted(self.user_agents.items(), key=lambda x: x[1], reverse=True)[:3],
            "ip_count": len(self.source_ips),
            "top_endpoints": sorted(self.target_endpoints.items(), key=lambda x: x[1], reverse=True)[:3],
            "method_distribution": dict(self.http_methods),
            "entropy": self.calculate_entropy()
        }
        
        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()


class DDoSDetectionEngine:
    """Advanced DDoS attack detection engine"""
    
    def __init__(self, redis_client: redis.Redis, db: Session):
        self.redis = redis_client
        self.db = db
        self.config = DDoSProtectionConfig()
        self.request_buffer = deque(maxlen=1000)  # Recent requests for analysis
        self.active_attacks = {}  # attack_id -> AttackSignature
        self.ip_reputation = {}  # ip -> reputation_score
        self.baseline_metrics = {}  # normal traffic patterns
        
    def analyze_request(self, request_data: Dict[str, Any]) -> Tuple[ThreatLevel, List[AttackType]]:
        """
        Analyze incoming request for DDoS attack indicators
        Returns threat level and list of detected attack types
        """
        # Add to request buffer
        self.request_buffer.append({
            **request_data,
            "timestamp": time.time()
        })
        
        # Perform various analyses
        threat_indicators = []
        
        # 1. Rate-based analysis
        current_rate = self._calculate_current_rate()
        if current_rate > self.config.EMERGENCY_RATE_THRESHOLD:
            threat_indicators.append((AttackType.VOLUMETRIC, ThreatLevel.EMERGENCY))
        elif current_rate > self.config.SEVERE_RATE_THRESHOLD:
            threat_indicators.append((AttackType.VOLUMETRIC, ThreatLevel.SEVERE))
        elif current_rate > self.config.HIGH_RATE_THRESHOLD:
            threat_indicators.append((AttackType.VOLUMETRIC, ThreatLevel.HIGH))
        elif current_rate > self.config.ELEVATED_RATE_THRESHOLD:
            threat_indicators.append((AttackType.VOLUMETRIC, ThreatLevel.ELEVATED))
        
        # 2. Pattern-based analysis
        pattern_threats = self._analyze_patterns()
        threat_indicators.extend(pattern_threats)
        
        # 3. Source-based analysis
        source_threats = self._analyze_sources(request_data.get("ip_address", ""))
        threat_indicators.extend(source_threats)
        
        # 4. Application-layer analysis
        app_threats = self._analyze_application_layer(request_data)
        threat_indicators.extend(app_threats)
        
        # Determine overall threat level
        if not threat_indicators:
            return ThreatLevel.NORMAL, []
        
        max_threat_level = max(threat[1] for threat in threat_indicators)
        detected_attack_types = list(set(threat[0] for threat in threat_indicators))
        
        return max_threat_level, detected_attack_types
    
    def _calculate_current_rate(self) -> float:
        """Calculate current request rate from buffer"""
        if len(self.request_buffer) < 2:
            return 0.0
        
        now = time.time()
        recent_requests = [r for r in self.request_buffer if now - r["timestamp"] <= 60]
        
        return len(recent_requests) / 60.0  # Requests per second over last minute
    
    def _analyze_patterns(self) -> List[Tuple[AttackType, ThreatLevel]]:
        """Analyze request patterns for attack indicators"""
        threats = []
        
        if len(self.request_buffer) < 20:  # Need minimum data
            return threats
        
        recent_requests = list(self.request_buffer)[-50:]  # Analyze last 50 requests
        
        # Check for identical requests (replay attacks)
        request_hashes = defaultdict(int)
        for req in recent_requests:
            req_hash = self._hash_request(req)
            request_hashes[req_hash] += 1
        
        max_identical = max(request_hashes.values()) if request_hashes else 0
        if max_identical > self.config.PATTERN_DETECTION["identical_requests_threshold"]:
            threats.append((AttackType.APPLICATION, ThreatLevel.HIGH))
        
        # Check user agent diversity
        user_agents = set(req.get("user_agent", "") for req in recent_requests)
        ua_diversity = len(user_agents) / len(recent_requests) if recent_requests else 1.0
        
        if ua_diversity < self.config.PATTERN_DETECTION["user_agent_diversity_threshold"]:
            threats.append((AttackType.BOTNET, ThreatLevel.HIGH))
        
        # Check request timing regularity (bot-like behavior)
        timestamps = [req["timestamp"] for req in recent_requests if "timestamp" in req]
        if len(timestamps) > 5:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if intervals:
                timing_variance = statistics.stdev(intervals) if len(intervals) > 1 else 0
                avg_interval = statistics.mean(intervals)
                
                if avg_interval > 0 and timing_variance / avg_interval < self.config.PATTERN_DETECTION["request_timing_variance_threshold"]:
                    threats.append((AttackType.BOTNET, ThreatLevel.ELEVATED))
        
        # Check error rate (potential application-layer attack)
        error_responses = sum(1 for req in recent_requests if req.get("status_code", 200) >= 400)
        error_rate = error_responses / len(recent_requests) if recent_requests else 0.0
        
        if error_rate > self.config.PATTERN_DETECTION["error_rate_threshold"]:
            threats.append((AttackType.APPLICATION, ThreatLevel.ELEVATED))
        
        return threats
    
    def _analyze_sources(self, current_ip: str) -> List[Tuple[AttackType, ThreatLevel]]:
        """Analyze request sources for attack indicators"""
        threats = []
        
        # Analyze IP reputation
        if current_ip:
            reputation = self.ip_reputation.get(current_ip, 50)  # Default neutral score
            
            if reputation > self.config.REPUTATION_THRESHOLDS["malicious_score"]:
                threats.append((AttackType.BOTNET, ThreatLevel.SEVERE))
            elif reputation > self.config.REPUTATION_THRESHOLDS["suspicious_score"]:
                threats.append((AttackType.BOTNET, ThreatLevel.ELEVATED))
        
        # Analyze geographic distribution
        if len(self.request_buffer) >= 20:
            countries = defaultdict(int)
            for req in list(self.request_buffer)[-50:]:
                country = req.get("country", "unknown")
                countries[country] += 1
            
            total_requests = sum(countries.values())
            if total_requests > 0:
                max_country_fraction = max(countries.values()) / total_requests
                
                if max_country_fraction > self.config.PATTERN_DETECTION["geographic_concentration_threshold"]:
                    threats.append((AttackType.VOLUMETRIC, ThreatLevel.ELEVATED))
        
        return threats
    
    def _analyze_application_layer(self, request_data: Dict[str, Any]) -> List[Tuple[AttackType, ThreatLevel]]:
        """Analyze application-layer attack indicators"""
        threats = []
        
        endpoint = request_data.get("endpoint", "")
        method = request_data.get("method", "GET")
        
        # Check for slowloris-type attacks (slow connections)
        connection_time = request_data.get("connection_duration", 0)
        if connection_time > 30:  # Connections held open > 30 seconds
            threats.append((AttackType.SLOWLORIS, ThreatLevel.HIGH))
        
        # Check for resource-intensive endpoints being targeted
        resource_intensive_patterns = [
            "/api/search", "/api/export", "/api/reports", 
            "/api/admin/analytics", "/api/bulk"
        ]
        
        if any(pattern in endpoint for pattern in resource_intensive_patterns):
            recent_same_endpoint = sum(
                1 for req in list(self.request_buffer)[-20:] 
                if req.get("endpoint", "") == endpoint
            )
            
            if recent_same_endpoint > 10:  # Many requests to resource-intensive endpoint
                threats.append((AttackType.RESOURCE_EXHAUSTION, ThreatLevel.HIGH))
        
        # Check for potential amplification attacks (large response expected)
        if method in ["GET", "HEAD"] and any(param in endpoint for param in ["export", "download", "backup"]):
            threats.append((AttackType.AMPLIFICATION, ThreatLevel.ELEVATED))
        
        return threats
    
    def _hash_request(self, request_data: Dict[str, Any]) -> str:
        """Create hash of request for similarity detection"""
        hash_elements = [
            request_data.get("method", ""),
            request_data.get("endpoint", ""),
            str(request_data.get("query_params", {})),
            request_data.get("user_agent", "")[:50]  # Limit length
        ]
        hash_string = "|".join(hash_elements)
        return hashlib.sha256(hash_string.encode()).hexdigest()[:16]
    
    def update_ip_reputation(self, ip_address: str, behavior_score: int) -> None:
        """Update IP reputation based on behavior"""
        current_score = self.ip_reputation.get(ip_address, 50)
        
        # Weighted update: 20% current behavior, 80% historical
        new_score = int(0.8 * current_score + 0.2 * behavior_score)
        new_score = max(0, min(100, new_score))  # Clamp to 0-100
        
        self.ip_reputation[ip_address] = new_score
        
        # Store in Redis for persistence
        if self.redis:
            try:
                key = f"ip_reputation:{ip_address}"
                self.redis.setex(key, 86400, new_score)  # 24 hour TTL
            except RedisError as e:
                logger.warning(f"Failed to store IP reputation: {e}")
    
    def get_mitigation_actions(self, threat_level: ThreatLevel, attack_types: List[AttackType]) -> Dict[str, Any]:
        """Determine appropriate mitigation actions based on threat assessment"""
        if threat_level == ThreatLevel.NORMAL:
            return {"action": "allow"}
        
        config = self.config.MITIGATION_THRESHOLDS.get(threat_level, {})
        
        actions = {
            "action": "mitigate",
            "threat_level": threat_level.name,
            "attack_types": [at.value for at in attack_types],
            "rate_limit_factor": config.get("rate_limit_factor", 1.0),
            "challenge_probability": config.get("challenge_probability", 0.0),
            "block_suspicious_ips": config.get("block_suspicious_ips", False),
            "enable_proof_of_work": config.get("enable_proof_of_work", False),
            "emergency_mode": config.get("emergency_mode", False)
        }
        
        return actions


class DDoSProtectionMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive DDoS protection middleware
    
    Features:
    - Real-time attack detection
    - Adaptive rate limiting
    - Proof-of-work challenges
    - IP reputation tracking
    - Geographic filtering
    - Attack fingerprinting
    - Coordinated defense
    """
    
    def __init__(self, app, redis_url: Optional[str] = None, db_session_factory=None):
        super().__init__(app)
        self.redis_url = redis_url or settings.REDIS_URL or "redis://localhost:6379"
        self.db_session_factory = db_session_factory
        self.redis_client = None
        self.detection_engine = None
        self._connect_services()
        
        # In-memory fallbacks
        self.blocked_ips = set()
        self.rate_limits = defaultdict(list)
        
    def _connect_services(self):
        """Connect to Redis and initialize detection engine"""
        try:
            self.redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            self.redis_client.ping()
            logger.info("DDoS protection connected to Redis")
        except Exception as e:
            logger.warning(f"DDoS protection Redis connection failed: {e}")
            self.redis_client = None
        
        # Initialize detection engine when first request comes in
        # (needs database session which we get from request context)
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request through DDoS protection pipeline"""
        start_time = time.time()
        
        # Extract request data for analysis
        request_data = await self._extract_request_data(request)
        
        # Initialize detection engine if needed (with DB session from request)
        if not self.detection_engine and self.db_session_factory:
            try:
                db = next(self.db_session_factory())
                self.detection_engine = DDoSDetectionEngine(self.redis_client, db)
            except Exception as e:
                logger.error(f"Failed to initialize DDoS detection engine: {e}")
        
        # Quick IP block check
        client_ip = request_data.get("ip_address", "")
        if self._is_ip_blocked(client_ip):
            logger.warning(f"Blocked DDoS request from {client_ip}")
            return Response(
                content=json.dumps({"error": "Request blocked due to security policies"}),
                status_code=403,
                media_type="application/json"
            )
        
        # Perform DDoS analysis
        if self.detection_engine:
            try:
                threat_level, attack_types = self.detection_engine.analyze_request(request_data)
                
                if threat_level != ThreatLevel.NORMAL:
                    # Get mitigation actions
                    mitigation = self.detection_engine.get_mitigation_actions(threat_level, attack_types)
                    
                    # Apply mitigation
                    mitigation_response = await self._apply_mitigation(request, mitigation, request_data)
                    if mitigation_response:
                        return mitigation_response
                    
                    # Log attack event
                    await self._log_attack_event(threat_level, attack_types, request_data, mitigation)
                
            except Exception as e:
                logger.error(f"DDoS analysis failed: {e}")
                # Continue processing request despite analysis failure
        
        # Process request normally
        try:
            response = await call_next(request)
            
            # Update request data with response info
            request_data["status_code"] = response.status_code
            request_data["response_time"] = time.time() - start_time
            
            # Update IP reputation based on behavior
            if self.detection_engine:
                behavior_score = self._calculate_behavior_score(request_data, response)
                self.detection_engine.update_ip_reputation(client_ip, behavior_score)
            
            return response
            
        except Exception as e:
            logger.error(f"Request processing failed: {e}")
            # Update IP reputation negatively for errors
            if self.detection_engine:
                self.detection_engine.update_ip_reputation(client_ip, 20)  # Poor score
            raise
    
    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant data from request for analysis"""
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Extract basic request info
        request_data = {
            "ip_address": client_ip,
            "method": request.method,
            "endpoint": str(request.url.path),
            "user_agent": request.headers.get("User-Agent", ""),
            "content_type": request.headers.get("Content-Type", ""),
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "timestamp": time.time(),
        }
        
        # Add geographic info if available (would integrate with GeoIP service)
        request_data["country"] = self._get_country_from_ip(client_ip)
        
        return request_data
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP considering proxies"""
        # Check various headers for the real IP
        headers_to_check = [
            "CF-Connecting-IP",  # Cloudflare
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
        ]
        
        for header in headers_to_check:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        return getattr(request.client, 'host', 'unknown') if hasattr(request, 'client') else 'unknown'
    
    def _get_country_from_ip(self, ip_address: str) -> str:
        """Get country from IP address (placeholder for GeoIP integration)"""
        # This would integrate with a real GeoIP service
        # For now, return unknown
        return "unknown"
    
    def _is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is currently blocked"""
        if not ip_address or ip_address == "unknown":
            return False
        
        # Check Redis blocklist
        if self.redis_client:
            try:
                key = f"blocked_ip:{ip_address}"
                return bool(self.redis_client.exists(key))
            except RedisError:
                pass
        
        # Fallback to in-memory blocklist
        return ip_address in self.blocked_ips
    
    async def _apply_mitigation(self, request: Request, mitigation: Dict[str, Any], request_data: Dict[str, Any]) -> Optional[Response]:
        """Apply mitigation actions based on threat assessment"""
        threat_level = mitigation.get("threat_level", "NORMAL")
        
        # Emergency mode - block most requests
        if mitigation.get("emergency_mode", False):
            return Response(
                content=json.dumps({
                    "error": "Service temporarily unavailable due to high load",
                    "retry_after": 300
                }),
                status_code=503,
                headers={"Retry-After": "300"},
                media_type="application/json"
            )
        
        # Block suspicious IPs
        if mitigation.get("block_suspicious_ips", False):
            ip_address = request_data.get("ip_address", "")
            await self._block_ip(ip_address, duration=3600)  # Block for 1 hour
            
            return Response(
                content=json.dumps({"error": "Access denied"}),
                status_code=403,
                media_type="application/json"
            )
        
        # Proof-of-work challenge
        if mitigation.get("enable_proof_of_work", False):
            return await self._issue_proof_of_work_challenge(request, request_data)
        
        # Probabilistic challenge
        challenge_prob = mitigation.get("challenge_probability", 0.0)
        if challenge_prob > 0:
            import random
            if random.random() < challenge_prob:
                return await self._issue_security_challenge(request, request_data)
        
        # If we reach here, allow request to proceed with modified rate limits
        return None
    
    async def _block_ip(self, ip_address: str, duration: int = 3600) -> None:
        """Block IP address for specified duration"""
        if not ip_address or ip_address == "unknown":
            return
        
        if self.redis_client:
            try:
                key = f"blocked_ip:{ip_address}"
                self.redis_client.setex(key, duration, "blocked")
                logger.warning(f"Blocked IP {ip_address} for {duration} seconds")
            except RedisError:
                # Fallback to in-memory blocking
                self.blocked_ips.add(ip_address)
        else:
            self.blocked_ips.add(ip_address)
    
    async def _issue_proof_of_work_challenge(self, request: Request, request_data: Dict[str, Any]) -> Response:
        """Issue proof-of-work challenge to verify client legitimacy"""
        import secrets
        
        # Generate challenge
        challenge = secrets.token_hex(16)
        difficulty = 4  # Number of leading zeros required in hash
        
        challenge_data = {
            "challenge": challenge,
            "difficulty": difficulty,
            "algorithm": "sha256",
            "expires_at": int(time.time()) + 300  # 5 minutes
        }
        
        # Store challenge
        if self.redis_client:
            try:
                key = f"pow_challenge:{challenge}"
                self.redis_client.setex(key, 300, json.dumps(challenge_data))
            except RedisError:
                pass
        
        return Response(
            content=json.dumps({
                "error": "Proof of work required",
                "challenge": challenge_data,
                "instructions": f"Find nonce where sha256(challenge + nonce) starts with {difficulty} zeros"
            }),
            status_code=429,
            headers={"Retry-After": "60"},
            media_type="application/json"
        )
    
    async def _issue_security_challenge(self, request: Request, request_data: Dict[str, Any]) -> Response:
        """Issue security challenge (CAPTCHA-like)"""
        return Response(
            content=json.dumps({
                "error": "Security verification required",
                "challenge_type": "captcha",
                "message": "Please verify you are not a robot"
            }),
            status_code=429,
            headers={"Retry-After": "30"},
            media_type="application/json"
        )
    
    async def _log_attack_event(self, threat_level: ThreatLevel, attack_types: List[AttackType], request_data: Dict[str, Any], mitigation: Dict[str, Any]) -> None:
        """Log DDoS attack event to database"""
        if not self.db_session_factory:
            return
        
        try:
            db = next(self.db_session_factory())
            
            # Create attack signature
            signature = AttackSignature()
            signature.add_request(request_data)
            fingerprint = signature.get_fingerprint()
            
            # Check if this is part of an ongoing attack
            existing_attack = db.query(DDoSEvent).filter(
                DDoSEvent.fingerprint == fingerprint,
                DDoSEvent.is_active == True
            ).first()
            
            if existing_attack:
                # Update existing attack
                existing_attack.total_requests += 1
                existing_attack.ended_at = datetime.utcnow()
                existing_attack.duration_seconds = int(
                    (existing_attack.ended_at - existing_attack.started_at).total_seconds()
                )
            else:
                # Create new attack event
                attack_event = DDoSEvent(
                    attack_id=secrets.token_hex(16),
                    attack_type=attack_types[0].value if attack_types else "unknown",
                    threat_level=threat_level.name,
                    source_ip=request_data.get("ip_address", ""),
                    user_agent=request_data.get("user_agent", "")[:500],
                    target_endpoint=request_data.get("endpoint", ""),
                    request_rate=self._calculate_current_rate() if hasattr(self, 'detection_engine') else 0,
                    total_requests=1,
                    blocked_requests=1 if mitigation.get("action") == "block" else 0,
                    mitigation_actions=json.dumps(mitigation),
                    fingerprint=fingerprint,
                    severity_score=threat_level.value * 20
                )
                db.add(attack_event)
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to log DDoS attack event: {e}")
            try:
                db.rollback()
            except:
                pass
    
    def _calculate_current_rate(self) -> float:
        """Calculate current request rate"""
        if hasattr(self, 'detection_engine') and self.detection_engine:
            return self.detection_engine._calculate_current_rate()
        return 0.0
    
    def _calculate_behavior_score(self, request_data: Dict[str, Any], response: Response) -> int:
        """Calculate behavior score for IP reputation"""
        score = 50  # Neutral starting point
        
        # Adjust based on response status
        status_code = response.status_code
        if status_code == 200:
            score += 10  # Good request
        elif 400 <= status_code < 500:
            score -= 20  # Client error
        elif status_code >= 500:
            score -= 10  # Server error (less penalty)
        
        # Adjust based on response time
        response_time = request_data.get("response_time", 0)
        if response_time > 10:  # Very slow request
            score -= 15
        elif response_time < 0.1:  # Very fast (potential attack)
            score -= 5
        
        # Adjust based on request characteristics
        if request_data.get("method") in ["POST", "PUT", "DELETE"]:
            score += 5  # State-changing requests are more legitimate
        
        return max(0, min(100, score))