"""
Privacy controls for telemetry data
"""
import hashlib
import random
from typing import Dict, Any, List, Optional
from enum import Enum
from datetime import datetime


class PrivacyMode(str, Enum):
    """Privacy modes for telemetry collection"""
    MINIMAL = "minimal"      # Only essential data (deployment ID, version)
    STANDARD = "standard"    # Normal telemetry with PII removed
    ENHANCED = "enhanced"    # Anonymized/hashed identifiers
    MAXIMUM = "maximum"      # Minimal data, no user tracking


class PrivacyEngine:
    """
    Handles privacy controls for telemetry data.
    Applies different levels of anonymization based on privacy mode.
    """
    
    # Fields allowed in each privacy mode
    PRIVACY_FILTERS = {
        PrivacyMode.MINIMAL: [
            "deployment_id", "version", "timestamp", "event_type"
        ],
        PrivacyMode.STANDARD: [
            "deployment_id", "version", "timestamp", "event_type",
            "error_count", "api_requests", "active_users", "uptime",
            "feature_usage", "performance_metrics"
        ],
        PrivacyMode.ENHANCED: [
            # Same as standard but with anonymization
            "deployment_id", "version", "timestamp", "event_type",
            "error_count", "api_requests", "active_users", "uptime",
            "feature_usage", "performance_metrics"
        ],
        PrivacyMode.MAXIMUM: [
            "deployment_id", "version", "uptime", "error_count"
        ]
    }
    
    # Fields that should always be anonymized
    SENSITIVE_FIELDS = [
        "user_id", "email", "name", "ip_address", "phone",
        "address", "credit_card", "ssn", "date_of_birth"
    ]
    
    def __init__(self, mode: PrivacyMode = PrivacyMode.STANDARD):
        """Initialize privacy engine with specified mode"""
        self.mode = mode
        self._salt = self._generate_salt()
    
    def filter_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply privacy filters to telemetry event"""
        if self.mode == PrivacyMode.MINIMAL:
            return self._apply_minimal_filter(event_data)
        elif self.mode == PrivacyMode.STANDARD:
            return self._apply_standard_filter(event_data)
        elif self.mode == PrivacyMode.ENHANCED:
            return self._apply_enhanced_filter(event_data)
        elif self.mode == PrivacyMode.MAXIMUM:
            return self._apply_maximum_filter(event_data)
        
        return event_data
    
    def filter_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Apply privacy filters to usage metrics"""
        filtered = {}
        allowed_fields = self.PRIVACY_FILTERS.get(self.mode, [])
        
        for field, value in metrics.items():
            # Check if field is allowed
            if self._is_field_allowed(field, allowed_fields):
                # Apply anonymization if needed
                if self.mode == PrivacyMode.ENHANCED:
                    filtered[field] = self._anonymize_value(field, value)
                else:
                    filtered[field] = value
            
            # Handle nested dictionaries (like feature_usage)
            elif isinstance(value, dict) and field in allowed_fields:
                filtered[field] = self._filter_nested_dict(value)
        
        return filtered
    
    def anonymize_field(self, field_name: str, value: Any) -> Any:
        """Anonymize a specific field based on its type"""
        if field_name in ["user_id", "email", "name"]:
            return self._hash_value(str(value))
        elif field_name == "ip_address":
            return self._anonymize_ip(value)
        elif field_name == "location":
            return self._anonymize_location(value)
        elif isinstance(value, str) and field_name in self.SENSITIVE_FIELDS:
            return "REDACTED"
        else:
            return value
    
    def aggregate_metrics(self, metrics_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate metrics to preserve privacy"""
        if not metrics_list:
            return {}
        
        aggregated = {
            "count": len(metrics_list),
            "timestamp_range": {
                "start": min(m.get("timestamp", "") for m in metrics_list),
                "end": max(m.get("timestamp", "") for m in metrics_list)
            }
        }
        
        # Aggregate numeric fields
        numeric_fields = ["api_requests", "error_count", "active_users", "uptime"]
        for field in numeric_fields:
            values = [m.get(field, 0) for m in metrics_list if field in m]
            if values:
                aggregated[field] = {
                    "sum": sum(values),
                    "avg": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values)
                }
        
        return aggregated
    
    # Private methods
    
    def _apply_minimal_filter(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply minimal privacy filter - only essential data"""
        allowed = self.PRIVACY_FILTERS[PrivacyMode.MINIMAL]
        return {k: v for k, v in data.items() if k in allowed}
    
    def _apply_standard_filter(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply standard privacy filter - remove PII"""
        filtered = {}
        allowed = self.PRIVACY_FILTERS[PrivacyMode.STANDARD]
        
        for key, value in data.items():
            if key in self.SENSITIVE_FIELDS:
                continue  # Skip sensitive fields
            elif key in allowed or self._is_field_allowed(key, allowed):
                filtered[key] = value
        
        return filtered
    
    def _apply_enhanced_filter(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply enhanced privacy filter - anonymize identifiers"""
        filtered = self._apply_standard_filter(data)
        
        # Anonymize any remaining identifiers
        for key, value in filtered.items():
            if self._is_identifier(key):
                filtered[key] = self._hash_value(str(value))
        
        return filtered
    
    def _apply_maximum_filter(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply maximum privacy filter - minimal data only"""
        allowed = self.PRIVACY_FILTERS[PrivacyMode.MAXIMUM]
        filtered = {k: v for k, v in data.items() if k in allowed}
        
        # Round numeric values to reduce precision
        for key, value in filtered.items():
            if isinstance(value, (int, float)) and key != "deployment_id":
                filtered[key] = self._reduce_precision(value)
        
        return filtered
    
    def _is_field_allowed(self, field: str, allowed_fields: List[str]) -> bool:
        """Check if field is allowed based on prefix matching"""
        for allowed in allowed_fields:
            if field.startswith(allowed) or allowed == field:
                return True
        return False
    
    def _is_identifier(self, field_name: str) -> bool:
        """Check if field is likely an identifier"""
        identifier_patterns = ["_id", "_uuid", "_key", "user_", "customer_"]
        return any(pattern in field_name.lower() for pattern in identifier_patterns)
    
    def _hash_value(self, value: str) -> str:
        """Create consistent hash of value"""
        return hashlib.sha256(f"{value}{self._salt}".encode()).hexdigest()[:16]
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address"""
        if self.mode == PrivacyMode.MAXIMUM:
            return "0.0.0.0"
        
        # Zero out last octet for IPv4
        if "." in ip_address:
            parts = ip_address.split(".")
            parts[-1] = "0"
            return ".".join(parts)
        
        # Zero out last segment for IPv6
        if ":" in ip_address:
            parts = ip_address.split(":")
            parts[-1] = "0"
            return ":".join(parts)
        
        return "0.0.0.0"
    
    def _anonymize_location(self, location: Dict[str, Any]) -> Dict[str, Any]:
        """Anonymize location data"""
        if self.mode == PrivacyMode.MAXIMUM:
            return {"country": location.get("country", "Unknown")}
        
        return {
            "country": location.get("country"),
            "region": location.get("region", "Unknown"),
            "city": "REDACTED"
        }
    
    def _filter_nested_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter nested dictionary values"""
        filtered = {}
        for key, value in data.items():
            if not self._is_identifier(key):
                if isinstance(value, dict):
                    filtered[key] = self._filter_nested_dict(value)
                else:
                    filtered[key] = value
        return filtered
    
    def _reduce_precision(self, value: float) -> float:
        """Reduce precision of numeric values"""
        if isinstance(value, int):
            # Round to nearest 10
            return round(value, -1)
        else:
            # Round to 1 decimal place
            return round(value, 1)
    
    def _generate_salt(self) -> str:
        """Generate salt for hashing"""
        return hashlib.sha256(
            f"{datetime.utcnow().date()}-privacy-salt".encode()
        ).hexdigest()[:8]
    
    def add_differential_privacy_noise(self, value: float, epsilon: float = 1.0) -> float:
        """Add Laplace noise for differential privacy"""
        if self.mode != PrivacyMode.MAXIMUM:
            return value
        
        # Add Laplace noise
        scale = 1.0 / epsilon
        noise = random.laplace(0, scale)
        return value + noise


class ConsentManager:
    """Manage user consent for telemetry collection"""
    
    def __init__(self):
        self.consents = {}
    
    def has_consent(self, user_id: str, purpose: str = "telemetry") -> bool:
        """Check if user has given consent"""
        user_consent = self.consents.get(user_id, {})
        return user_consent.get(purpose, False)
    
    def record_consent(self, user_id: str, purpose: str, granted: bool) -> None:
        """Record user consent decision"""
        if user_id not in self.consents:
            self.consents[user_id] = {}
        self.consents[user_id][purpose] = granted
    
    def revoke_consent(self, user_id: str, purpose: Optional[str] = None) -> None:
        """Revoke user consent"""
        if purpose:
            if user_id in self.consents:
                self.consents[user_id][purpose] = False
        else:
            # Revoke all consent
            self.consents.pop(user_id, None)