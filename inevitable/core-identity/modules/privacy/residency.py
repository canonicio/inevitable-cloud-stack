"""
Data residency controller for multi-region compliance
"""
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import json

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession


class DataRegion(str, Enum):
    """Supported data regions"""
    US_EAST = "us-east"
    US_WEST = "us-west"
    EU_WEST = "eu-west"
    EU_CENTRAL = "eu-central"
    UK = "uk"
    CANADA = "canada"
    AUSTRALIA = "australia"
    SINGAPORE = "singapore"
    JAPAN = "japan"
    BRAZIL = "brazil"


class DataType(str, Enum):
    """Types of data for residency rules"""
    PERSONAL_DATA = "personal_data"
    SENSITIVE_DATA = "sensitive_data"
    FINANCIAL_DATA = "financial_data"
    HEALTH_DATA = "health_data"
    BIOMETRIC_DATA = "biometric_data"
    USAGE_DATA = "usage_data"
    TECHNICAL_DATA = "technical_data"
    ANONYMIZED_DATA = "anonymized_data"


class TransferMechanism(str, Enum):
    """Legal mechanisms for data transfer"""
    ADEQUACY_DECISION = "adequacy_decision"
    STANDARD_CONTRACTUAL_CLAUSES = "standard_contractual_clauses"
    BINDING_CORPORATE_RULES = "binding_corporate_rules"
    EXPLICIT_CONSENT = "explicit_consent"
    DEROGATION = "derogation"
    INTRA_JURISDICTION = "intra_jurisdiction"


@dataclass
class ResidencyRule:
    """Rule defining where data can be stored"""
    region: DataRegion
    countries: List[str]
    data_types: List[DataType]
    allowed_transfers: List[DataRegion]
    restrictions: Dict[str, Any]


@dataclass
class DataLocation:
    """Current location of data"""
    region: DataRegion
    country: str
    provider: str  # Cloud provider
    is_primary: bool
    last_verified: datetime


class DataResidencyController:
    """
    Controls where data can be stored and processed based on:
    - User location
    - Data type
    - Regulatory requirements
    - Organizational policies
    """
    
    # Pre-defined residency rules based on regulations
    REGULATORY_RULES = {
        # GDPR - EU data must stay in EU or adequate countries
        "gdpr": ResidencyRule(
            region=DataRegion.EU_WEST,
            countries=["DE", "FR", "IT", "ES", "NL", "BE", "PL", "SE", "FI", "DK", "AT", "IE"],
            data_types=[DataType.PERSONAL_DATA, DataType.SENSITIVE_DATA],
            allowed_transfers=[
                DataRegion.EU_WEST, DataRegion.EU_CENTRAL, 
                DataRegion.UK,  # Adequacy decision
                DataRegion.CANADA,  # Adequacy decision
                DataRegion.JAPAN  # Adequacy decision
            ],
            restrictions={
                "requires_mechanism": True,
                "default_mechanism": TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
            }
        ),
        
        # UK GDPR
        "uk_gdpr": ResidencyRule(
            region=DataRegion.UK,
            countries=["GB"],
            data_types=[DataType.PERSONAL_DATA, DataType.SENSITIVE_DATA],
            allowed_transfers=[
                DataRegion.UK, DataRegion.EU_WEST, DataRegion.EU_CENTRAL
            ],
            restrictions={
                "requires_mechanism": True,
                "default_mechanism": TransferMechanism.ADEQUACY_DECISION
            }
        ),
        
        # PIPEDA - Canadian data
        "pipeda": ResidencyRule(
            region=DataRegion.CANADA,
            countries=["CA"],
            data_types=[DataType.PERSONAL_DATA],
            allowed_transfers=[
                DataRegion.CANADA, DataRegion.US_EAST, DataRegion.US_WEST
            ],
            restrictions={
                "notification_required": True
            }
        ),
        
        # Russia data localization
        "russia_localization": ResidencyRule(
            region=DataRegion.EU_CENTRAL,  # Using closest region
            countries=["RU"],
            data_types=[DataType.PERSONAL_DATA],
            allowed_transfers=[],  # Must stay in Russia
            restrictions={
                "local_copy_required": True,
                "transfer_prohibited": True
            }
        ),
        
        # China data localization
        "china_localization": ResidencyRule(
            region=DataRegion.SINGAPORE,  # Using closest region
            countries=["CN"],
            data_types=[DataType.PERSONAL_DATA, DataType.SENSITIVE_DATA],
            allowed_transfers=[],  # Restricted transfers
            restrictions={
                "local_copy_required": True,
                "security_assessment_required": True
            }
        ),
        
        # Healthcare data (HIPAA)
        "hipaa": ResidencyRule(
            region=DataRegion.US_EAST,
            countries=["US"],
            data_types=[DataType.HEALTH_DATA],
            allowed_transfers=[DataRegion.US_EAST, DataRegion.US_WEST],
            restrictions={
                "baa_required": True,  # Business Associate Agreement
                "encryption_required": True
            }
        ),
        
        # Financial data (PCI DSS)
        "pci_dss": ResidencyRule(
            region=DataRegion.US_EAST,
            countries=["*"],  # Any country
            data_types=[DataType.FINANCIAL_DATA],
            allowed_transfers=[
                DataRegion.US_EAST, DataRegion.US_WEST,
                DataRegion.EU_WEST, DataRegion.EU_CENTRAL,
                DataRegion.UK, DataRegion.CANADA,
                DataRegion.AUSTRALIA, DataRegion.SINGAPORE,
                DataRegion.JAPAN
            ],
            restrictions={
                "pci_compliant_required": True,
                "tokenization_recommended": True
            }
        )
    }
    
    # Adequacy decisions (simplified)
    ADEQUACY_DECISIONS = {
        (DataRegion.EU_WEST, DataRegion.UK): True,
        (DataRegion.EU_WEST, DataRegion.CANADA): True,
        (DataRegion.EU_WEST, DataRegion.JAPAN): True,
        (DataRegion.EU_WEST, DataRegion.SINGAPORE): False,  # Requires SCCs
        (DataRegion.EU_WEST, DataRegion.US_EAST): False,  # Requires SCCs after Privacy Shield
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize with optional configuration"""
        self.config = config or {}
        self.custom_rules: List[ResidencyRule] = []
        self._load_custom_rules()
    
    def _load_custom_rules(self) -> None:
        """Load custom residency rules from configuration"""
        if "custom_rules" in self.config:
            for rule_config in self.config["custom_rules"]:
                rule = ResidencyRule(
                    region=DataRegion(rule_config["region"]),
                    countries=rule_config["countries"],
                    data_types=[DataType(dt) for dt in rule_config["data_types"]],
                    allowed_transfers=[DataRegion(r) for r in rule_config["allowed_transfers"]],
                    restrictions=rule_config.get("restrictions", {})
                )
                self.custom_rules.append(rule)
    
    async def get_allowed_regions(
        self,
        user_country: str,
        data_type: DataType,
        purpose: Optional[str] = None
    ) -> List[DataRegion]:
        """
        Get regions where data can be stored for a user
        
        Args:
            user_country: ISO country code
            data_type: Type of data
            purpose: Optional purpose for processing
            
        Returns:
            List of allowed regions
        """
        allowed_regions = set()
        
        # Check regulatory rules
        for rule_name, rule in self.REGULATORY_RULES.items():
            if user_country in rule.countries and data_type in rule.data_types:
                # Primary region is always allowed
                allowed_regions.add(rule.region)
                
                # Add allowed transfer regions
                allowed_regions.update(rule.allowed_transfers)
        
        # Check custom rules
        for rule in self.custom_rules:
            if user_country in rule.countries and data_type in rule.data_types:
                allowed_regions.add(rule.region)
                allowed_regions.update(rule.allowed_transfers)
        
        # If no specific rules, use default based on data type
        if not allowed_regions:
            if data_type == DataType.ANONYMIZED_DATA:
                # Anonymized data can go anywhere
                allowed_regions = set(DataRegion)
            else:
                # Default to user's region
                user_region = self._get_region_for_country(user_country)
                if user_region:
                    allowed_regions.add(user_region)
        
        return list(allowed_regions)
    
    async def validate_data_transfer(
        self,
        from_region: DataRegion,
        to_region: DataRegion,
        data_type: DataType,
        user_country: str
    ) -> Dict[str, Any]:
        """
        Validate if data transfer between regions is allowed
        
        Args:
            from_region: Source region
            to_region: Destination region
            data_type: Type of data being transferred
            user_country: User's country
            
        Returns:
            Validation result with requirements
        """
        # Same region is always allowed
        if from_region == to_region:
            return {
                "allowed": True,
                "mechanism": TransferMechanism.INTRA_JURISDICTION,
                "requirements": []
            }
        
        # Check if transfer is allowed
        allowed_regions = await self.get_allowed_regions(user_country, data_type)
        
        if to_region not in allowed_regions:
            return {
                "allowed": False,
                "reason": f"Data type {data_type} from {user_country} cannot be transferred to {to_region}",
                "allowed_regions": allowed_regions
            }
        
        # Determine required mechanism
        mechanism = await self._get_transfer_mechanism(
            from_region, to_region, data_type, user_country
        )
        
        if not mechanism:
            return {
                "allowed": False,
                "reason": f"No legal mechanism available for transfer from {from_region} to {to_region}"
            }
        
        # Get requirements
        requirements = await self._get_transfer_requirements(
            mechanism, from_region, to_region, data_type
        )
        
        return {
            "allowed": True,
            "mechanism": mechanism,
            "requirements": requirements,
            "documentation_required": mechanism != TransferMechanism.INTRA_JURISDICTION
        }
    
    async def get_data_location_policy(
        self,
        user_country: str,
        data_types: List[DataType]
    ) -> Dict[str, Any]:
        """
        Get complete data location policy for a user
        
        Args:
            user_country: User's country
            data_types: Types of data being processed
            
        Returns:
            Complete location policy
        """
        policy = {
            "user_country": user_country,
            "primary_region": self._get_region_for_country(user_country),
            "data_policies": {}
        }
        
        for data_type in data_types:
            allowed_regions = await self.get_allowed_regions(
                user_country, data_type
            )
            
            # Get applicable rules
            applicable_rules = []
            for rule_name, rule in self.REGULATORY_RULES.items():
                if user_country in rule.countries and data_type in rule.data_types:
                    applicable_rules.append({
                        "regulation": rule_name,
                        "restrictions": rule.restrictions
                    })
            
            policy["data_policies"][data_type.value] = {
                "allowed_regions": [r.value for r in allowed_regions],
                "primary_region": policy["primary_region"].value if policy["primary_region"] else None,
                "applicable_regulations": applicable_rules,
                "requires_local_copy": self._requires_local_copy(user_country, data_type),
                "transfer_restrictions": self._get_transfer_restrictions(user_country, data_type)
            }
        
        return policy
    
    async def select_optimal_region(
        self,
        user_country: str,
        data_type: DataType,
        preferred_regions: Optional[List[DataRegion]] = None,
        optimization_criteria: Optional[Dict[str, float]] = None
    ) -> DataRegion:
        """
        Select optimal region for data storage
        
        Args:
            user_country: User's country
            data_type: Type of data
            preferred_regions: Preferred regions in order
            optimization_criteria: Weights for optimization (latency, cost, compliance)
            
        Returns:
            Optimal region
        """
        allowed_regions = await self.get_allowed_regions(user_country, data_type)
        
        if not allowed_regions:
            raise ValueError(f"No allowed regions for {data_type} from {user_country}")
        
        # If only one allowed region, return it
        if len(allowed_regions) == 1:
            return allowed_regions[0]
        
        # Score each region
        scores = {}
        criteria = optimization_criteria or {
            "compliance": 0.4,
            "latency": 0.3,
            "cost": 0.2,
            "reliability": 0.1
        }
        
        user_region = self._get_region_for_country(user_country)
        
        for region in allowed_regions:
            score = 0.0
            
            # Compliance score (highest for home region)
            if region == user_region:
                score += criteria.get("compliance", 0) * 1.0
            else:
                score += criteria.get("compliance", 0) * 0.5
            
            # Latency score (based on distance)
            latency_score = self._calculate_latency_score(user_region, region)
            score += criteria.get("latency", 0) * latency_score
            
            # Cost score (varies by region)
            cost_score = self._calculate_cost_score(region)
            score += criteria.get("cost", 0) * cost_score
            
            # Reliability score
            reliability_score = self._calculate_reliability_score(region)
            score += criteria.get("reliability", 0) * reliability_score
            
            # Boost score if in preferred regions
            if preferred_regions and region in preferred_regions:
                boost = 0.2 * (len(preferred_regions) - preferred_regions.index(region)) / len(preferred_regions)
                score += boost
            
            scores[region] = score
        
        # Return region with highest score
        return max(scores.items(), key=lambda x: x[1])[0]
    
    def _get_region_for_country(self, country: str) -> Optional[DataRegion]:
        """Map country to primary region"""
        region_mapping = {
            # North America
            "US": DataRegion.US_EAST,
            "CA": DataRegion.CANADA,
            "MX": DataRegion.US_WEST,
            
            # Europe
            "DE": DataRegion.EU_CENTRAL,
            "FR": DataRegion.EU_WEST,
            "IT": DataRegion.EU_WEST,
            "ES": DataRegion.EU_WEST,
            "NL": DataRegion.EU_WEST,
            "BE": DataRegion.EU_WEST,
            "GB": DataRegion.UK,
            "IE": DataRegion.EU_WEST,
            
            # Asia Pacific
            "AU": DataRegion.AUSTRALIA,
            "NZ": DataRegion.AUSTRALIA,
            "SG": DataRegion.SINGAPORE,
            "MY": DataRegion.SINGAPORE,
            "JP": DataRegion.JAPAN,
            "KR": DataRegion.JAPAN,
            
            # South America
            "BR": DataRegion.BRAZIL,
            "AR": DataRegion.BRAZIL,
            "CL": DataRegion.BRAZIL,
        }
        
        return region_mapping.get(country, DataRegion.US_EAST)
    
    async def _get_transfer_mechanism(
        self,
        from_region: DataRegion,
        to_region: DataRegion,
        data_type: DataType,
        user_country: str
    ) -> Optional[TransferMechanism]:
        """Determine legal mechanism for transfer"""
        # Check for adequacy decision
        if self.ADEQUACY_DECISIONS.get((from_region, to_region), False):
            return TransferMechanism.ADEQUACY_DECISION
        
        # Check if SCCs are available
        if self.config.get("scc_implemented", True):
            return TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES
        
        # Check if BCRs are available
        if self.config.get("bcr_approved", False):
            return TransferMechanism.BINDING_CORPORATE_RULES
        
        # Explicit consent as last resort (not recommended for regular transfers)
        if data_type not in [DataType.SENSITIVE_DATA, DataType.HEALTH_DATA]:
            return TransferMechanism.EXPLICIT_CONSENT
        
        return None
    
    async def _get_transfer_requirements(
        self,
        mechanism: TransferMechanism,
        from_region: DataRegion,
        to_region: DataRegion,
        data_type: DataType
    ) -> List[str]:
        """Get requirements for data transfer"""
        requirements = []
        
        if mechanism == TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES:
            requirements.extend([
                "Execute Standard Contractual Clauses",
                "Implement supplementary measures",
                "Conduct transfer impact assessment",
                "Document safeguards"
            ])
        
        elif mechanism == TransferMechanism.BINDING_CORPORATE_RULES:
            requirements.extend([
                "BCRs must be approved by supervisory authority",
                "Ensure BCRs cover this data type",
                "Maintain BCR compliance"
            ])
        
        elif mechanism == TransferMechanism.EXPLICIT_CONSENT:
            requirements.extend([
                "Obtain explicit consent from data subject",
                "Inform about risks of transfer",
                "Document consent",
                "Provide opt-out mechanism"
            ])
        
        # Additional requirements for sensitive data
        if data_type in [DataType.SENSITIVE_DATA, DataType.HEALTH_DATA, DataType.FINANCIAL_DATA]:
            requirements.extend([
                "Encrypt data in transit and at rest",
                "Implement access controls",
                "Enable audit logging",
                "Regular security assessments"
            ])
        
        return requirements
    
    def _requires_local_copy(self, country: str, data_type: DataType) -> bool:
        """Check if local copy is required"""
        # Russia and China require local copies
        if country in ["RU", "CN"] and data_type == DataType.PERSONAL_DATA:
            return True
        
        # Check custom rules
        for rule in self.custom_rules:
            if country in rule.countries and data_type in rule.data_types:
                if rule.restrictions.get("local_copy_required", False):
                    return True
        
        return False
    
    def _get_transfer_restrictions(self, country: str, data_type: DataType) -> List[str]:
        """Get transfer restrictions for country/data type"""
        restrictions = []
        
        for rule_name, rule in self.REGULATORY_RULES.items():
            if country in rule.countries and data_type in rule.data_types:
                if rule.restrictions.get("transfer_prohibited", False):
                    restrictions.append(f"Transfer prohibited under {rule_name}")
                
                if rule.restrictions.get("security_assessment_required", False):
                    restrictions.append("Security assessment required before transfer")
                
                if rule.restrictions.get("notification_required", False):
                    restrictions.append("User notification required")
        
        return restrictions
    
    def _calculate_latency_score(
        self,
        user_region: Optional[DataRegion],
        data_region: DataRegion
    ) -> float:
        """Calculate latency score (0-1, higher is better)"""
        if not user_region:
            return 0.5
        
        if user_region == data_region:
            return 1.0
        
        # Simplified distance calculation
        # In production, use actual latency measurements
        same_continent = {
            DataRegion.US_EAST: {DataRegion.US_WEST, DataRegion.CANADA},
            DataRegion.EU_WEST: {DataRegion.EU_CENTRAL, DataRegion.UK},
            DataRegion.SINGAPORE: {DataRegion.JAPAN, DataRegion.AUSTRALIA}
        }
        
        if data_region in same_continent.get(user_region, set()):
            return 0.8
        
        return 0.3
    
    def _calculate_cost_score(self, region: DataRegion) -> float:
        """Calculate cost score (0-1, higher is better/cheaper)"""
        # Simplified cost model
        cost_tiers = {
            DataRegion.US_EAST: 0.9,
            DataRegion.US_WEST: 0.8,
            DataRegion.EU_WEST: 0.6,
            DataRegion.EU_CENTRAL: 0.6,
            DataRegion.UK: 0.5,
            DataRegion.CANADA: 0.7,
            DataRegion.SINGAPORE: 0.7,
            DataRegion.JAPAN: 0.4,
            DataRegion.AUSTRALIA: 0.5,
            DataRegion.BRAZIL: 0.6
        }
        
        return cost_tiers.get(region, 0.5)
    
    def _calculate_reliability_score(self, region: DataRegion) -> float:
        """Calculate reliability score (0-1, higher is better)"""
        # All regions should have high reliability
        # Could be based on actual SLA data
        return 0.95