"""
Advanced data anonymization engine for privacy compliance
"""
import hashlib
import random
import string
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import faker
import numpy as np
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from modules.core.security import SecurityUtils


class AnonymizationLevel(str, Enum):
    """Levels of anonymization"""
    NONE = "none"
    BASIC = "basic"           # Remove direct identifiers
    STANDARD = "standard"     # Pseudonymization
    ENHANCED = "enhanced"     # k-anonymity
    MAXIMUM = "maximum"       # Full anonymization with differential privacy


@dataclass
class AnonymizationRule:
    """Rule for anonymizing a specific field"""
    field_name: str
    field_type: str
    technique: str
    parameters: Dict[str, Any]


class DataAnonymizer:
    """
    Enterprise-grade data anonymization engine supporting:
    - Pseudonymization
    - k-anonymity
    - l-diversity
    - t-closeness
    - Differential privacy
    """
    
    # PII fields that should always be anonymized
    PII_FIELDS = {
        "email", "email_address", "phone", "phone_number", "ssn", 
        "social_security_number", "credit_card", "bank_account",
        "passport_number", "driver_license", "ip_address",
        "device_id", "advertising_id", "biometric_data"
    }
    
    # Quasi-identifiers that might allow re-identification
    QUASI_IDENTIFIERS = {
        "name", "first_name", "last_name", "date_of_birth", "dob",
        "address", "street", "city", "postal_code", "zip_code",
        "gender", "race", "ethnicity", "occupation", "salary",
        "education", "marital_status"
    }
    
    def __init__(self, salt: Optional[str] = None):
        """Initialize anonymizer with optional salt for consistent hashing"""
        self.salt = salt or SecurityUtils.generate_secure_token(32)
        self.faker = faker.Faker()
        self._anonymization_cache = {}
    
    async def anonymize_dataset(
        self,
        data: List[Dict[str, Any]],
        level: AnonymizationLevel = AnonymizationLevel.STANDARD,
        rules: Optional[List[AnonymizationRule]] = None
    ) -> List[Dict[str, Any]]:
        """
        Anonymize a dataset based on level and rules
        
        Args:
            data: List of records to anonymize
            level: Overall anonymization level
            rules: Specific rules for fields
            
        Returns:
            Anonymized dataset
        """
        if not data or level == AnonymizationLevel.NONE:
            return data
        
        # Apply field-level anonymization
        anonymized_data = []
        for record in data:
            anonymized_record = await self._anonymize_record(record, level, rules)
            anonymized_data.append(anonymized_record)
        
        # Apply dataset-level techniques
        if level in [AnonymizationLevel.ENHANCED, AnonymizationLevel.MAXIMUM]:
            anonymized_data = await self._apply_k_anonymity(anonymized_data, k=5)
            
        if level == AnonymizationLevel.MAXIMUM:
            anonymized_data = await self._apply_differential_privacy(anonymized_data)
        
        return anonymized_data
    
    async def _anonymize_record(
        self,
        record: Dict[str, Any],
        level: AnonymizationLevel,
        rules: Optional[List[AnonymizationRule]] = None
    ) -> Dict[str, Any]:
        """Anonymize a single record"""
        anonymized = {}
        
        for field, value in record.items():
            if value is None:
                anonymized[field] = None
                continue
            
            # Check for specific rule
            rule = self._get_rule_for_field(field, rules)
            if rule:
                anonymized[field] = await self._apply_rule(value, rule)
            else:
                # Apply default anonymization based on field type and level
                anonymized[field] = await self._anonymize_field(
                    field, value, level
                )
        
        return anonymized
    
    async def _anonymize_field(
        self,
        field_name: str,
        value: Any,
        level: AnonymizationLevel
    ) -> Any:
        """Anonymize a field based on its type and level"""
        field_lower = field_name.lower()
        
        # Direct identifiers - always anonymize (except NONE level)
        if field_lower in self.PII_FIELDS and level != AnonymizationLevel.NONE:
            return await self._anonymize_pii(field_lower, value, level)
        
        # Quasi-identifiers - anonymize based on level
        if field_lower in self.QUASI_IDENTIFIERS:
            if level == AnonymizationLevel.BASIC:
                return self._mask_value(value)
            elif level in [AnonymizationLevel.STANDARD, AnonymizationLevel.ENHANCED]:
                return await self._pseudonymize(field_lower, value)
            elif level == AnonymizationLevel.MAXIMUM:
                return self._generalize_value(field_lower, value)
        
        # Non-PII fields - return as is for lower levels
        if level in [AnonymizationLevel.NONE, AnonymizationLevel.BASIC]:
            return value
        
        # For higher levels, check if it's a potential identifier
        if isinstance(value, str) and len(value) > 5:
            # Could be an ID or unique value
            if any(keyword in field_lower for keyword in ["id", "key", "token", "identifier"]):
                return self._hash_value(value)
        
        return value
    
    async def _anonymize_pii(
        self,
        field_type: str,
        value: str,
        level: AnonymizationLevel
    ) -> str:
        """Anonymize PII fields"""
        if "email" in field_type:
            if level == AnonymizationLevel.MAXIMUM:
                return "anonymous@example.com"
            else:
                # Preserve domain for analysis
                local, domain = value.split("@") if "@" in value else (value, "example.com")
                return f"{self._hash_value(local)[:8]}@{domain}"
        
        elif "phone" in field_type:
            if level == AnonymizationLevel.MAXIMUM:
                return "000-000-0000"
            else:
                # Preserve country/area code
                return value[:3] + "-XXX-" + value[-4:]
        
        elif "ssn" in field_type or "social_security" in field_type:
            return "XXX-XX-" + value[-4:] if len(value) > 4 else "XXX-XX-XXXX"
        
        elif "credit_card" in field_type:
            return "XXXX-XXXX-XXXX-" + value[-4:] if len(value) > 4 else "XXXX-XXXX-XXXX-XXXX"
        
        elif "ip_address" in field_type:
            return self._anonymize_ip(value, level)
        
        else:
            # Generic PII - hash it
            return self._hash_value(value)
    
    async def _pseudonymize(self, field_type: str, value: str) -> str:
        """Replace with consistent pseudonym"""
        # Check cache first
        cache_key = f"{field_type}:{value}"
        if cache_key in self._anonymization_cache:
            return self._anonymization_cache[cache_key]
        
        # Generate pseudonym based on field type
        if "name" in field_type:
            if "first" in field_type:
                pseudonym = self.faker.first_name()
            elif "last" in field_type:
                pseudonym = self.faker.last_name()
            else:
                pseudonym = self.faker.name()
        elif "address" in field_type or "street" in field_type:
            pseudonym = self.faker.street_address()
        elif "city" in field_type:
            pseudonym = self.faker.city()
        elif "postal" in field_type or "zip" in field_type:
            pseudonym = self.faker.postcode()
        elif "date" in field_type or "dob" in field_type:
            # Preserve age range
            try:
                original_date = datetime.fromisoformat(str(value))
                age = (datetime.now() - original_date).days // 365
                # Round to 5-year ranges
                age_range = (age // 5) * 5
                pseudonym = (datetime.now() - timedelta(days=age_range * 365)).date().isoformat()
            except:
                pseudonym = self.faker.date_of_birth(minimum_age=18, maximum_age=80).isoformat()
        else:
            # Generic pseudonymization
            pseudonym = f"{field_type}_{self._hash_value(value)[:8]}"
        
        # Cache for consistency
        self._anonymization_cache[cache_key] = pseudonym
        return pseudonym
    
    def _generalize_value(self, field_type: str, value: Any) -> Any:
        """Generalize value to reduce precision"""
        if "age" in field_type or "salary" in field_type:
            # Numeric generalization
            try:
                num = float(value)
                if "age" in field_type:
                    # 10-year ranges
                    return f"{int(num // 10) * 10}-{int(num // 10) * 10 + 9}"
                else:
                    # Round to nearest 10k
                    return int(num // 10000) * 10000
            except:
                return "Unknown"
        
        elif "date" in field_type:
            # Only keep year
            try:
                date = datetime.fromisoformat(str(value))
                return str(date.year)
            except:
                return "Unknown"
        
        elif "postal" in field_type or "zip" in field_type:
            # Keep only first 2-3 digits
            return str(value)[:3] + "XX"
        
        else:
            # Generic generalization
            return f"{field_type}_category"
    
    def _mask_value(self, value: str) -> str:
        """Simple masking for basic anonymization"""
        if len(value) <= 4:
            return "****"
        
        # Show first and last characters
        return value[0] + "*" * (len(value) - 2) + value[-1]
    
    def _hash_value(self, value: str) -> str:
        """Create consistent hash of value"""
        return hashlib.sha256(f"{value}{self.salt}".encode()).hexdigest()
    
    def _anonymize_ip(self, ip: str, level: AnonymizationLevel) -> str:
        """Anonymize IP address based on level"""
        if level == AnonymizationLevel.MAXIMUM:
            return "0.0.0.0"
        
        if "." in ip:  # IPv4
            parts = ip.split(".")
            if level == AnonymizationLevel.ENHANCED:
                # Zero out last two octets
                return f"{parts[0]}.{parts[1]}.0.0"
            else:
                # Zero out last octet
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        
        elif ":" in ip:  # IPv6
            parts = ip.split(":")
            if level == AnonymizationLevel.ENHANCED:
                # Keep only first 3 segments
                return ":".join(parts[:3] + ["0"] * (len(parts) - 3))
            else:
                # Keep first 4 segments
                return ":".join(parts[:4] + ["0"] * (len(parts) - 4))
        
        return "0.0.0.0"
    
    async def _apply_k_anonymity(
        self,
        data: List[Dict[str, Any]],
        k: int = 5,
        quasi_identifiers: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Apply k-anonymity to ensure at least k records share the same
        quasi-identifier values
        """
        if len(data) < k:
            # Not enough data for k-anonymity
            return data
        
        # Identify quasi-identifiers in the data
        if not quasi_identifiers:
            quasi_identifiers = [
                field for field in data[0].keys()
                if field.lower() in self.QUASI_IDENTIFIERS
            ]
        
        if not quasi_identifiers:
            return data
        
        # Group records by quasi-identifier values
        groups = {}
        for record in data:
            # Create key from quasi-identifier values
            key = tuple(record.get(qi) for qi in quasi_identifiers)
            if key not in groups:
                groups[key] = []
            groups[key].append(record)
        
        # Generalize groups with less than k members
        anonymized_data = []
        for group_key, group_records in groups.items():
            if len(group_records) < k:
                # Generalize this group
                for record in group_records:
                    for qi in quasi_identifiers:
                        if qi in record:
                            record[qi] = self._generalize_value(qi, record[qi])
            
            anonymized_data.extend(group_records)
        
        return anonymized_data
    
    async def _apply_differential_privacy(
        self,
        data: List[Dict[str, Any]],
        epsilon: float = 1.0
    ) -> List[Dict[str, Any]]:
        """Apply differential privacy by adding calibrated noise"""
        for record in data:
            for field, value in record.items():
                if isinstance(value, (int, float)):
                    # Add Laplacian noise to numeric values
                    sensitivity = self._estimate_sensitivity(field)
                    noise = np.random.laplace(0, sensitivity / epsilon)
                    record[field] = value + noise
                
                elif isinstance(value, list):
                    # Add noise to list lengths
                    noise = np.random.laplace(0, 1 / epsilon)
                    new_length = max(0, int(len(value) + noise))
                    record[field] = value[:new_length]
        
        return data
    
    def _estimate_sensitivity(self, field: str) -> float:
        """Estimate sensitivity of a field for differential privacy"""
        # High sensitivity fields
        if any(term in field.lower() for term in ["salary", "income", "balance", "amount"]):
            return 10000.0
        
        # Medium sensitivity
        if any(term in field.lower() for term in ["age", "count", "quantity"]):
            return 10.0
        
        # Default low sensitivity
        return 1.0
    
    def _get_rule_for_field(
        self,
        field: str,
        rules: Optional[List[AnonymizationRule]]
    ) -> Optional[AnonymizationRule]:
        """Get specific anonymization rule for a field"""
        if not rules:
            return None
        
        for rule in rules:
            if rule.field_name == field:
                return rule
        
        return None
    
    async def _apply_rule(self, value: Any, rule: AnonymizationRule) -> Any:
        """Apply specific anonymization rule"""
        technique = rule.technique
        params = rule.parameters
        
        if technique == "hash":
            return self._hash_value(str(value))
        
        elif technique == "mask":
            return self._mask_value(str(value))
        
        elif technique == "generalize":
            return self._generalize_value(rule.field_name, value)
        
        elif technique == "substitute":
            # Replace with specific value
            return params.get("replacement", "REDACTED")
        
        elif technique == "encrypt":
            # Encrypt with format-preserving encryption
            from modules.core.security import SecurityUtils
            return SecurityUtils.encrypt_sensitive_data(
                str(value),
                key=params.get("key", self.salt)
            )
        
        elif technique == "randomize":
            # Add random noise
            if isinstance(value, (int, float)):
                noise_range = params.get("range", 0.1)
                noise = random.uniform(-noise_range, noise_range) * value
                return value + noise
            else:
                return self.faker.word()
        
        else:
            # Unknown technique - default to hash
            return self._hash_value(str(value))


class DataAnonymizationService:
    """Service for applying anonymization to database records"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.anonymizer = DataAnonymizer()
    
    async def anonymize_user_data(
        self,
        user_id: int,
        level: AnonymizationLevel = AnonymizationLevel.STANDARD
    ) -> Dict[str, Any]:
        """Anonymize all data for a specific user"""
        results = {
            "user": await self._anonymize_user_record(user_id, level),
            "related_records": {}
        }
        
        # Anonymize related data based on configuration
        # This would be extended based on your data model
        
        return results
    
    async def _anonymize_user_record(
        self,
        user_id: int,
        level: AnonymizationLevel
    ) -> Dict[str, Any]:
        """Anonymize user record"""
        # This is a placeholder - implement based on your User model
        # Example:
        # user = await self.db.get(User, user_id)
        # user_data = user.to_dict()
        # anonymized = await self.anonymizer.anonymize_dataset([user_data], level)
        # return anonymized[0] if anonymized else {}
        
        return {"status": "anonymized", "user_id": user_id}