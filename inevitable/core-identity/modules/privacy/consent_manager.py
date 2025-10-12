"""
Enhanced consent management system for GDPR/CCPA compliance
"""
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import json

from .models import (
    Consent, ConsentType, DataRequest, DataRequestType, 
    DataRequestStatus, PrivacyPolicy, PrivacyPolicyAcceptance
)
from modules.auth.models import User
from modules.core.security import SecurityUtils


class ConsentPurpose:
    """Standardized consent purposes"""
    ESSENTIAL = "essential"                    # Required for service
    ANALYTICS = "analytics"                    # Usage analytics
    MARKETING = "marketing"                    # Marketing communications
    PERSONALIZATION = "personalization"        # Personalized experience
    THIRD_PARTY = "third_party"               # Third-party sharing
    TELEMETRY = "telemetry"                   # Performance telemetry
    ADVERTISING = "advertising"               # Targeted advertising
    RESEARCH = "research"                     # Product research
    COMMUNICATIONS = "communications"         # Service communications


class ConsentManager:
    """
    Enterprise consent management system supporting:
    - Granular consent controls
    - Multi-jurisdiction compliance (GDPR, CCPA, etc.)
    - Consent versioning
    - Audit trails
    - Automated expiration
    """
    
    # Consent purposes that require explicit opt-in (GDPR)
    EXPLICIT_CONSENT_REQUIRED = {
        ConsentPurpose.MARKETING,
        ConsentPurpose.THIRD_PARTY,
        ConsentPurpose.ADVERTISING,
        ConsentPurpose.RESEARCH
    }
    
    # Default consent expiration periods (days)
    CONSENT_EXPIRATION = {
        ConsentPurpose.ESSENTIAL: None,          # No expiration
        ConsentPurpose.ANALYTICS: 365,           # 1 year
        ConsentPurpose.MARKETING: 365,           # 1 year
        ConsentPurpose.PERSONALIZATION: 730,     # 2 years
        ConsentPurpose.THIRD_PARTY: 180,        # 6 months
        ConsentPurpose.TELEMETRY: 365,          # 1 year
        ConsentPurpose.ADVERTISING: 180,        # 6 months
        ConsentPurpose.RESEARCH: 365,           # 1 year
        ConsentPurpose.COMMUNICATIONS: 730      # 2 years
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def request_consent(
        self,
        user_id: int,
        purposes: List[str],
        context: Dict[str, Any],
        tenant_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Request consent from user for specified purposes
        
        Args:
            user_id: User ID
            purposes: List of consent purposes
            context: Additional context (IP, user agent, etc.)
            tenant_id: Tenant ID for multi-tenant systems
            
        Returns:
            Consent request details
        """
        # Get current privacy policy
        policy = await self._get_active_privacy_policy()
        if not policy:
            raise ValueError("No active privacy policy found")
        
        consent_request = {
            "user_id": user_id,
            "policy_version": policy.version,
            "purposes": [],
            "timestamp": datetime.utcnow().isoformat(),
            "context": context
        }
        
        for purpose in purposes:
            purpose_details = await self._get_purpose_details(purpose)
            
            # Check if user already has valid consent
            existing_consent = await self.has_consent(
                user_id, purpose, tenant_id
            )
            
            consent_request["purposes"].append({
                "purpose": purpose,
                "description": purpose_details["description"],
                "data_types": purpose_details["data_types"],
                "retention_period": self.CONSENT_EXPIRATION.get(purpose),
                "third_party_sharing": purpose in [
                    ConsentPurpose.THIRD_PARTY,
                    ConsentPurpose.ADVERTISING
                ],
                "required": purpose == ConsentPurpose.ESSENTIAL,
                "explicit_required": purpose in self.EXPLICIT_CONSENT_REQUIRED,
                "current_consent": existing_consent,
                "legal_basis": purpose_details.get("legal_basis", "consent")
            })
        
        return consent_request
    
    async def record_consent(
        self,
        user_id: int,
        consents: Dict[str, bool],
        context: Dict[str, Any],
        tenant_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Record user's consent decisions
        
        Args:
            user_id: User ID
            consents: Dictionary of purpose -> granted (bool)
            context: Context including IP, user agent, method
            tenant_id: Tenant ID
            
        Returns:
            Recorded consent details
        """
        results = {
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "consents": {},
            "policy_version": None
        }
        
        # Get active privacy policy
        policy = await self._get_active_privacy_policy()
        if policy:
            results["policy_version"] = policy.version
            
            # Record policy acceptance if any consent is granted
            if any(consents.values()):
                await self._record_policy_acceptance(
                    user_id, policy.id, context, tenant_id
                )
        
        # Process each consent
        for purpose, granted in consents.items():
            # Map purpose to consent type
            consent_type = self._map_purpose_to_type(purpose)
            
            # Check for existing consent
            existing = await self._get_existing_consent(
                user_id, consent_type, tenant_id
            )
            
            if existing:
                # Update existing consent
                existing.granted = granted
                existing.version = policy.version if policy else "1.0"
                
                if granted:
                    existing.granted_at = datetime.utcnow()
                    existing.revoked_at = None
                    
                    # Set expiration
                    expiration_days = self.CONSENT_EXPIRATION.get(purpose)
                    if expiration_days:
                        existing.expires_at = datetime.utcnow() + timedelta(
                            days=expiration_days
                        )
                else:
                    existing.revoked_at = datetime.utcnow()
                
                # Update context
                existing.ip_address = context.get("ip_address")
                existing.user_agent = context.get("user_agent")
                existing.consent_method = context.get("method", "explicit_action")
                
                await self.db.commit()
                
                results["consents"][purpose] = {
                    "granted": granted,
                    "updated": True,
                    "expires_at": existing.expires_at.isoformat() if existing.expires_at else None
                }
            else:
                # Create new consent record
                new_consent = Consent(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    consent_type=consent_type,
                    granted=granted,
                    purpose=await self._get_purpose_description(purpose),
                    description=await self._get_purpose_details(purpose),
                    version=policy.version if policy else "1.0",
                    legal_basis=self._get_legal_basis(purpose),
                    granted_at=datetime.utcnow() if granted else None,
                    revoked_at=None if granted else datetime.utcnow(),
                    ip_address=context.get("ip_address"),
                    user_agent=context.get("user_agent"),
                    consent_method=context.get("method", "explicit_action")
                )
                
                # Set expiration
                if granted:
                    expiration_days = self.CONSENT_EXPIRATION.get(purpose)
                    if expiration_days:
                        new_consent.expires_at = datetime.utcnow() + timedelta(
                            days=expiration_days
                        )
                
                self.db.add(new_consent)
                await self.db.commit()
                
                results["consents"][purpose] = {
                    "granted": granted,
                    "created": True,
                    "expires_at": new_consent.expires_at.isoformat() if new_consent.expires_at else None
                }
        
        # Trigger consent change events
        await self._trigger_consent_changes(user_id, consents)
        
        return results
    
    async def has_consent(
        self,
        user_id: int,
        purpose: str,
        tenant_id: Optional[int] = None,
        check_expiry: bool = True
    ) -> bool:
        """Check if user has valid consent for purpose"""
        consent_type = self._map_purpose_to_type(purpose)
        
        query = select(Consent).where(
            and_(
                Consent.user_id == user_id,
                Consent.consent_type == consent_type,
                Consent.granted == True,
                Consent.revoked_at.is_(None)
            )
        )
        
        if tenant_id:
            query = query.where(Consent.tenant_id == tenant_id)
        
        result = await self.db.execute(query)
        consent = result.scalar_one_or_none()
        
        if not consent:
            return False
        
        # Check expiration
        if check_expiry and consent.expires_at:
            if datetime.utcnow() > consent.expires_at:
                return False
        
        return True
    
    async def get_user_consents(
        self,
        user_id: int,
        tenant_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get all consent statuses for a user"""
        query = select(Consent).where(
            Consent.user_id == user_id
        )
        
        if tenant_id:
            query = query.where(Consent.tenant_id == tenant_id)
        
        result = await self.db.execute(query)
        consents = result.scalars().all()
        
        # Build consent status for all purposes
        consent_status = {}
        
        for purpose in [
            ConsentPurpose.ESSENTIAL,
            ConsentPurpose.ANALYTICS,
            ConsentPurpose.MARKETING,
            ConsentPurpose.PERSONALIZATION,
            ConsentPurpose.THIRD_PARTY,
            ConsentPurpose.TELEMETRY,
            ConsentPurpose.ADVERTISING,
            ConsentPurpose.RESEARCH,
            ConsentPurpose.COMMUNICATIONS
        ]:
            consent_type = self._map_purpose_to_type(purpose)
            
            # Find matching consent
            matching = None
            for consent in consents:
                if consent.consent_type == consent_type:
                    matching = consent
                    break
            
            if matching:
                is_valid = matching.is_valid()
                consent_status[purpose] = {
                    "granted": matching.granted and is_valid,
                    "timestamp": matching.granted_at.isoformat() if matching.granted_at else None,
                    "expires_at": matching.expires_at.isoformat() if matching.expires_at else None,
                    "version": matching.version,
                    "revoked": matching.revoked_at is not None,
                    "revoked_at": matching.revoked_at.isoformat() if matching.revoked_at else None
                }
            else:
                # No consent record - default based on purpose
                consent_status[purpose] = {
                    "granted": purpose == ConsentPurpose.ESSENTIAL,  # Essential is implicit
                    "timestamp": None,
                    "expires_at": None,
                    "version": None,
                    "revoked": False,
                    "revoked_at": None
                }
        
        return {
            "user_id": user_id,
            "consents": consent_status,
            "last_updated": max(
                (c.updated_at for c in consents),
                default=datetime.utcnow()
            ).isoformat()
        }
    
    async def withdraw_consent(
        self,
        user_id: int,
        purposes: List[str],
        reason: Optional[str] = None,
        tenant_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Withdraw consent for specified purposes
        
        Args:
            user_id: User ID
            purposes: List of purposes to withdraw
            reason: Optional reason for withdrawal
            tenant_id: Tenant ID
            
        Returns:
            Withdrawal details
        """
        results = {
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "purposes": purposes,
            "reason": reason,
            "withdrawn": []
        }
        
        for purpose in purposes:
            consent_type = self._map_purpose_to_type(purpose)
            
            # Find existing consent
            existing = await self._get_existing_consent(
                user_id, consent_type, tenant_id
            )
            
            if existing and existing.granted:
                existing.granted = False
                existing.revoked_at = datetime.utcnow()
                
                # Store reason in description
                if reason:
                    existing.description = f"Withdrawn: {reason}"
                
                await self.db.commit()
                results["withdrawn"].append(purpose)
        
        # Trigger withdrawal events
        await self._trigger_consent_withdrawal(user_id, purposes)
        
        return results
    
    async def get_consent_history(
        self,
        user_id: int,
        purpose: Optional[str] = None,
        tenant_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get consent history for user"""
        # This would be implemented with an audit log table
        # For now, return current consent as history
        current = await self.get_user_consents(user_id, tenant_id)
        
        history = []
        for consent_purpose, details in current["consents"].items():
            if purpose and consent_purpose != purpose:
                continue
            
            history.append({
                "purpose": consent_purpose,
                "action": "granted" if details["granted"] else "withdrawn",
                "timestamp": details["timestamp"] or details["revoked_at"],
                "version": details["version"],
                "expires_at": details["expires_at"]
            })
        
        return sorted(history, key=lambda x: x["timestamp"] or "", reverse=True)
    
    # Private helper methods
    
    async def _get_active_privacy_policy(self) -> Optional[PrivacyPolicy]:
        """Get currently active privacy policy"""
        result = await self.db.execute(
            select(PrivacyPolicy).where(
                PrivacyPolicy.is_active == True
            ).order_by(PrivacyPolicy.effective_date.desc())
        )
        return result.scalar_one_or_none()
    
    async def _get_purpose_details(self, purpose: str) -> Dict[str, Any]:
        """Get detailed information about a consent purpose"""
        details = {
            ConsentPurpose.ESSENTIAL: {
                "description": "Essential cookies and data processing required for the service to function",
                "data_types": ["authentication", "session", "security"],
                "legal_basis": "legitimate_interest"
            },
            ConsentPurpose.ANALYTICS: {
                "description": "Analytics to understand how you use our service and improve it",
                "data_types": ["usage_statistics", "performance_metrics", "error_logs"],
                "legal_basis": "consent"
            },
            ConsentPurpose.MARKETING: {
                "description": "Marketing communications about our products and services",
                "data_types": ["contact_information", "preferences", "interaction_history"],
                "legal_basis": "consent"
            },
            ConsentPurpose.PERSONALIZATION: {
                "description": "Personalize your experience based on your preferences and usage",
                "data_types": ["preferences", "usage_patterns", "device_information"],
                "legal_basis": "consent"
            },
            ConsentPurpose.THIRD_PARTY: {
                "description": "Share data with third-party partners for enhanced features",
                "data_types": ["usage_data", "preferences", "anonymized_statistics"],
                "legal_basis": "consent"
            },
            ConsentPurpose.TELEMETRY: {
                "description": "Collect performance and diagnostic data to improve reliability",
                "data_types": ["performance_metrics", "error_reports", "system_information"],
                "legal_basis": "legitimate_interest"
            },
            ConsentPurpose.ADVERTISING: {
                "description": "Show targeted advertisements based on your interests",
                "data_types": ["browsing_history", "interests", "demographic_data"],
                "legal_basis": "consent"
            },
            ConsentPurpose.RESEARCH: {
                "description": "Use your data for product research and development",
                "data_types": ["usage_patterns", "feedback", "anonymized_data"],
                "legal_basis": "consent"
            },
            ConsentPurpose.COMMUNICATIONS: {
                "description": "Send service-related communications and updates",
                "data_types": ["contact_information", "preferences"],
                "legal_basis": "legitimate_interest"
            }
        }
        
        return details.get(purpose, {
            "description": f"Process data for {purpose}",
            "data_types": ["general_data"],
            "legal_basis": "consent"
        })
    
    async def _get_purpose_description(self, purpose: str) -> str:
        """Get simple description for a purpose"""
        details = await self._get_purpose_details(purpose)
        return details.get("description", f"Process data for {purpose}")
    
    def _map_purpose_to_type(self, purpose: str) -> ConsentType:
        """Map purpose string to ConsentType enum"""
        mapping = {
            ConsentPurpose.ANALYTICS: ConsentType.ANALYTICS,
            ConsentPurpose.MARKETING: ConsentType.MARKETING,
            ConsentPurpose.THIRD_PARTY: ConsentType.THIRD_PARTY,
            ConsentPurpose.ADVERTISING: ConsentType.MARKETING,
            ConsentPurpose.COMMUNICATIONS: ConsentType.COMMUNICATIONS,
            ConsentPurpose.ESSENTIAL: ConsentType.DATA_PROCESSING,
            ConsentPurpose.PERSONALIZATION: ConsentType.DATA_PROCESSING,
            ConsentPurpose.TELEMETRY: ConsentType.DATA_PROCESSING,
            ConsentPurpose.RESEARCH: ConsentType.DATA_PROCESSING
        }
        
        return mapping.get(purpose, ConsentType.DATA_PROCESSING)
    
    def _get_legal_basis(self, purpose: str) -> str:
        """Get legal basis for processing (GDPR Article 6)"""
        if purpose == ConsentPurpose.ESSENTIAL:
            return "contract"  # Necessary for contract
        elif purpose in [ConsentPurpose.TELEMETRY, ConsentPurpose.COMMUNICATIONS]:
            return "legitimate_interest"
        else:
            return "consent"
    
    async def _get_existing_consent(
        self,
        user_id: int,
        consent_type: ConsentType,
        tenant_id: Optional[int]
    ) -> Optional[Consent]:
        """Get existing consent record"""
        query = select(Consent).where(
            and_(
                Consent.user_id == user_id,
                Consent.consent_type == consent_type
            )
        )
        
        if tenant_id:
            query = query.where(Consent.tenant_id == tenant_id)
        
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def _record_policy_acceptance(
        self,
        user_id: int,
        policy_id: int,
        context: Dict[str, Any],
        tenant_id: Optional[int]
    ) -> None:
        """Record privacy policy acceptance"""
        # Check if already accepted
        existing = await self.db.execute(
            select(PrivacyPolicyAcceptance).where(
                and_(
                    PrivacyPolicyAcceptance.user_id == user_id,
                    PrivacyPolicyAcceptance.policy_id == policy_id
                )
            )
        )
        
        if existing.scalar_one_or_none():
            return
        
        # Create acceptance record
        acceptance = PrivacyPolicyAcceptance(
            user_id=user_id,
            policy_id=policy_id,
            tenant_id=tenant_id,
            accepted_at=datetime.utcnow(),
            ip_address=context.get("ip_address"),
            user_agent=context.get("user_agent")
        )
        
        self.db.add(acceptance)
        await self.db.commit()
    
    async def _trigger_consent_changes(
        self,
        user_id: int,
        consents: Dict[str, bool]
    ) -> None:
        """Trigger events for consent changes"""
        # This would integrate with an event system
        # For now, just log
        for purpose, granted in consents.items():
            if not granted and purpose in [
                ConsentPurpose.ANALYTICS,
                ConsentPurpose.MARKETING,
                ConsentPurpose.ADVERTISING
            ]:
                # User opted out - trigger cleanup
                await self._cleanup_user_data_for_purpose(user_id, purpose)
    
    async def _trigger_consent_withdrawal(
        self,
        user_id: int,
        purposes: List[str]
    ) -> None:
        """Trigger events for consent withdrawal"""
        for purpose in purposes:
            await self._cleanup_user_data_for_purpose(user_id, purpose)
    
    async def _cleanup_user_data_for_purpose(
        self,
        user_id: int,
        purpose: str
    ) -> None:
        """Clean up user data when consent is withdrawn"""
        # This would be implemented based on your data model
        # Example actions:
        # - Remove from marketing lists
        # - Delete analytics data
        # - Remove from advertising segments
        pass