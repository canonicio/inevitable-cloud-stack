"""
Enhanced Webhook Security with IP Allowlisting
Addresses HIGH-001: Billing Webhook Access Control Bypass
Addresses MEDIUM-002: Missing Webhook Retry Protection
"""
import hmac
import hashlib
import time
import logging
import ipaddress
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timedelta
import redis
from fastapi import Request, HTTPException, status

from modules.core.config import settings

logger = logging.getLogger(__name__)


class EnhancedWebhookSecurity:
    """
    Enhanced webhook security with IP allowlisting and replay protection.
    Addresses HIGH-001: Billing Webhook Access Control Bypass
    """
    
    # Stripe's webhook IP ranges (as of 2025)
    # In production, these should be fetched from Stripe's API or updated regularly
    STRIPE_IP_RANGES = [
        "3.18.12.32/27",
        "3.130.192.128/26", 
        "13.235.14.128/26",
        "13.235.122.96/27",
        "18.211.135.32/27",
        "35.154.171.0/26",
        "52.15.183.0/27",
        "54.88.130.0/27",
        "54.88.130.128/26",
        "54.187.174.128/26",
        "54.187.205.192/27",
        "54.187.216.0/26"
    ]
    
    def __init__(
        self,
        webhook_secret: str,
        redis_client: Optional[redis.Redis] = None,
        enable_ip_validation: bool = True,
        timestamp_tolerance: int = 300  # 5 minutes
    ):
        self.webhook_secret = webhook_secret
        self.redis_client = redis_client or redis.Redis.from_url(
            settings.REDIS_URL or "redis://localhost:6379"
        )
        self.enable_ip_validation = enable_ip_validation
        self.timestamp_tolerance = timestamp_tolerance
        
        # Parse IP ranges for validation
        self.allowed_networks = []
        for ip_range in self.STRIPE_IP_RANGES:
            try:
                self.allowed_networks.append(ipaddress.ip_network(ip_range))
            except ValueError as e:
                logger.error(f"Invalid IP range {ip_range}: {e}")
    
    def validate_webhook_request(
        self,
        request: Request,
        payload: bytes,
        signature_header: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive webhook validation including IP and signature.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # HIGH-001 FIX: Validate source IP address
        if self.enable_ip_validation:
            is_valid_ip, ip_error = self._validate_source_ip(request)
            if not is_valid_ip:
                return False, ip_error
        
        # Validate signature
        is_valid_sig, sig_error = self._validate_signature(payload, signature_header)
        if not is_valid_sig:
            return False, sig_error
        
        # Check for replay attacks
        is_valid_replay, replay_error = self._check_replay_protection(signature_header)
        if not is_valid_replay:
            return False, replay_error
        
        return True, None
    
    def _validate_source_ip(self, request: Request) -> Tuple[bool, Optional[str]]:
        """
        Validate that webhook comes from allowed IP ranges.
        Addresses HIGH-001: Billing Webhook Access Control Bypass
        """
        # Get client IP (handle proxies)
        client_ip = request.client.host
        forwarded_for = request.headers.get("X-Forwarded-For")
        
        if forwarded_for:
            # Take the first IP from X-Forwarded-For
            client_ip = forwarded_for.split(",")[0].strip()
        
        try:
            ip_addr = ipaddress.ip_address(client_ip)
            
            # Check if IP is in allowed ranges
            for network in self.allowed_networks:
                if ip_addr in network:
                    logger.debug(f"Webhook from allowed IP: {client_ip}")
                    return True, None
            
            logger.warning(f"Webhook from unauthorized IP: {client_ip}")
            return False, f"Unauthorized source IP: {client_ip}"
            
        except ValueError as e:
            logger.error(f"Invalid IP address format: {client_ip} - {e}")
            return False, f"Invalid IP address: {client_ip}"
    
    def _validate_signature(self, payload: bytes, signature_header: str) -> Tuple[bool, Optional[str]]:
        """
        Validate webhook signature using HMAC.
        """
        if not signature_header:
            return False, "Missing signature header"
        
        # Parse Stripe signature header format: t=timestamp,v1=signature
        elements = {}
        for element in signature_header.split(','):
            key_value = element.split('=', 1)
            if len(key_value) == 2:
                elements[key_value[0]] = key_value[1]
        
        timestamp = elements.get('t')
        signature = elements.get('v1')
        
        if not timestamp or not signature:
            return False, "Invalid signature header format"
        
        # Check timestamp to prevent replay attacks
        try:
            timestamp_int = int(timestamp)
            current_time = int(time.time())
            
            if abs(current_time - timestamp_int) > self.timestamp_tolerance:
                return False, f"Timestamp outside tolerance window ({self.timestamp_tolerance}s)"
        except ValueError:
            return False, "Invalid timestamp in signature"
        
        # Compute expected signature
        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected_signature = hmac.new(
            self.webhook_secret.encode('utf-8'),
            signed_payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(expected_signature, signature):
            return False, "Invalid signature"
        
        return True, None
    
    def _check_replay_protection(self, signature_header: str) -> Tuple[bool, Optional[str]]:
        """
        Check for replay attacks using signature uniqueness.
        Addresses MEDIUM-002: Missing Webhook Retry Protection
        """
        # Use signature as unique identifier
        cache_key = f"webhook:sig:{hashlib.sha256(signature_header.encode()).hexdigest()}"
        
        # Check if we've seen this signature before
        if self.redis_client.exists(cache_key):
            logger.warning(f"Replay attack detected - duplicate signature")
            return False, "Duplicate webhook (possible replay attack)"
        
        # Store signature with expiration
        self.redis_client.setex(cache_key, self.timestamp_tolerance * 2, "1")
        
        return True, None
    
    def record_retry(self, webhook_id: str, retry_count: int) -> bool:
        """
        Record webhook retry attempt.
        Addresses MEDIUM-002: Missing Webhook Retry Protection
        """
        retry_key = f"webhook:retry:{webhook_id}"
        
        # Increment retry counter
        current_retries = self.redis_client.incr(retry_key)
        
        # Set expiration if this is the first retry
        if current_retries == 1:
            self.redis_client.expire(retry_key, 3600)  # 1 hour expiration
        
        # Check if we've exceeded max retries
        max_retries = 5  # Stripe typically retries up to 3 times
        if current_retries > max_retries:
            logger.warning(f"Webhook {webhook_id} exceeded max retries: {current_retries}")
            return False
        
        return True
    
    def validate_idempotency_key(self, idempotency_key: str) -> bool:
        """
        Validate and record idempotency key to prevent duplicate processing.
        Addresses MEDIUM-002: Missing Webhook Retry Protection
        """
        if not idempotency_key:
            return True  # No idempotency key provided
        
        cache_key = f"webhook:idempotency:{idempotency_key}"
        
        # Try to set with NX (only if not exists)
        result = self.redis_client.set(
            cache_key,
            "1",
            ex=86400,  # 24 hour expiration
            nx=True    # Only set if not exists
        )
        
        if not result:
            logger.info(f"Idempotent request already processed: {idempotency_key}")
            return False
        
        return True


class WebhookRateLimiter:
    """
    Rate limiting for webhook endpoints to prevent abuse.
    """
    
    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        max_requests_per_minute: int = 100,
        max_requests_per_hour: int = 1000
    ):
        self.redis_client = redis_client or redis.Redis.from_url(
            settings.REDIS_URL or "redis://localhost:6379"
        )
        self.max_requests_per_minute = max_requests_per_minute
        self.max_requests_per_hour = max_requests_per_hour
    
    def check_rate_limit(self, identifier: str) -> Tuple[bool, Optional[Dict[str, int]]]:
        """
        Check if identifier has exceeded rate limits.
        
        Returns:
            Tuple of (is_allowed, limits_info)
        """
        now = int(time.time())
        
        # Check per-minute limit
        minute_key = f"webhook:rate:minute:{identifier}:{now // 60}"
        minute_count = self.redis_client.incr(minute_key)
        if minute_count == 1:
            self.redis_client.expire(minute_key, 60)
        
        # Check per-hour limit
        hour_key = f"webhook:rate:hour:{identifier}:{now // 3600}"
        hour_count = self.redis_client.incr(hour_key)
        if hour_count == 1:
            self.redis_client.expire(hour_key, 3600)
        
        # Check if limits exceeded
        if minute_count > self.max_requests_per_minute:
            return False, {
                "minute_count": minute_count,
                "minute_limit": self.max_requests_per_minute,
                "hour_count": hour_count,
                "hour_limit": self.max_requests_per_hour
            }
        
        if hour_count > self.max_requests_per_hour:
            return False, {
                "minute_count": minute_count,
                "minute_limit": self.max_requests_per_minute,
                "hour_count": hour_count,
                "hour_limit": self.max_requests_per_hour
            }
        
        return True, {
            "minute_count": minute_count,
            "minute_limit": self.max_requests_per_minute,
            "hour_count": hour_count,
            "hour_limit": self.max_requests_per_hour
        }