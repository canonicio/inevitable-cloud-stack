"""
Consent management system for GDPR compliance
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from modules.privacy.models import Consent, ConsentType
from modules.core.security import SecurityUtils
from modules.observability.logging import audit_logger

logger = logging.getLogger(__name__)


class ConsentManager:
    """Manages user consent for data processing."""
    
    def __init__(self):
        self.consent_versions = {
            ConsentType.MARKETING: "1.0",
            ConsentType.ANALYTICS: "1.0",
            ConsentType.THIRD_PARTY: "1.0",
            ConsentType.COOKIES: "1.0",
            ConsentType.DATA_PROCESSING: "1.0",
            ConsentType.COMMUNICATIONS: "1.0"
        }
        
        self.consent_purposes = {
            ConsentType.MARKETING: "To send you promotional materials and updates about our products",
            ConsentType.ANALYTICS: "To analyze usage patterns and improve our services",
            ConsentType.THIRD_PARTY: "To share data with trusted partners for service delivery",
            ConsentType.COOKIES: "To store preferences and enhance your browsing experience",
            ConsentType.DATA_PROCESSING: "To process your personal data for service delivery",
            ConsentType.COMMUNICATIONS: "To send you service updates and important notifications"
        }
    
    def record_consent(
        self,
        db: Session,
        user_id: int,
        consent_type: ConsentType,
        granted: bool,
        ip_address: str = None,
        user_agent: str = None,
        consent_method: str = "explicit_action",
        tenant_id: str = None
    ) -> Consent:
        """Record user consent."""
        try:
            # Check if consent already exists
            existing_consent = db.query(Consent).filter(
                Consent.user_id == user_id,
                Consent.consent_type == consent_type,
                Consent.tenant_id == tenant_id
            ).first()
            
            if existing_consent:
                # Update existing consent
                existing_consent.granted = granted
                existing_consent.version = self.consent_versions[consent_type]
                existing_consent.purpose = self.consent_purposes[consent_type]
                existing_consent.consent_method = consent_method
                existing_consent.ip_address = SecurityUtils.sanitize_ip(ip_address) if ip_address else None
                existing_consent.user_agent = user_agent[:500] if user_agent else None  # Limit length
                
                if granted:
                    existing_consent.granted_at = datetime.utcnow()
                    existing_consent.revoked_at = None
                else:
                    existing_consent.revoked_at = datetime.utcnow()
                
                consent = existing_consent
            else:
                # Create new consent record
                consent = Consent(
                    user_id=user_id,
                    consent_type=consent_type,
                    granted=granted,
                    purpose=self.consent_purposes[consent_type],
                    version=self.consent_versions[consent_type],
                    consent_method=consent_method,
                    ip_address=SecurityUtils.sanitize_ip(ip_address) if ip_address else None,
                    user_agent=user_agent[:500] if user_agent else None,
                    tenant_id=tenant_id
                )
                
                if granted:
                    consent.granted_at = datetime.utcnow()
                
                db.add(consent)
            
            db.commit()
            
            # Log consent action
            audit_logger.log_user_action(
                action="consent_recorded",
                user_id=user_id,
                resource_type="consent",
                resource_id=str(consent.id),
                tenant_id=tenant_id,
                details={
                    "consent_type": consent_type.value,
                    "granted": granted,
                    "version": consent.version,
                    "method": consent_method
                }
            )
            
            return consent
            
        except Exception as e:
            logger.error(f"Error recording consent: {e}")
            db.rollback()
            raise
    
    def get_user_consents(
        self,
        db: Session,
        user_id: int,
        tenant_id: str = None
    ) -> Dict[str, Any]:
        """Get all consents for a user."""
        consents = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.tenant_id == tenant_id
        ).all()
        
        consent_status = {}
        for consent_type in ConsentType:
            consent = next(
                (c for c in consents if c.consent_type == consent_type),
                None
            )
            
            if consent:
                consent_status[consent_type.value] = {
                    "granted": consent.is_valid(),
                    "version": consent.version,
                    "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                    "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                    "purpose": consent.purpose
                }
            else:
                consent_status[consent_type.value] = {
                    "granted": False,
                    "version": self.consent_versions[consent_type],
                    "granted_at": None,
                    "revoked_at": None,
                    "purpose": self.consent_purposes[consent_type]
                }
        
        return consent_status
    
    def check_consent(
        self,
        db: Session,
        user_id: int,
        consent_type: ConsentType,
        tenant_id: str = None
    ) -> bool:
        """Check if user has valid consent for a specific type."""
        consent = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.consent_type == consent_type,
            Consent.tenant_id == tenant_id
        ).first()
        
        return consent.is_valid() if consent else False
    
    def bulk_update_consents(
        self,
        db: Session,
        user_id: int,
        consents: Dict[str, bool],
        ip_address: str = None,
        user_agent: str = None,
        tenant_id: str = None
    ) -> Dict[str, Any]:
        """Update multiple consents at once."""
        results = {}
        
        for consent_type_str, granted in consents.items():
            try:
                consent_type = ConsentType(consent_type_str)
                consent = self.record_consent(
                    db=db,
                    user_id=user_id,
                    consent_type=consent_type,
                    granted=granted,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    tenant_id=tenant_id
                )
                results[consent_type_str] = {
                    "success": True,
                    "granted": granted
                }
            except Exception as e:
                logger.error(f"Error updating consent {consent_type_str}: {e}")
                results[consent_type_str] = {
                    "success": False,
                    "error": str(e)
                }
        
        return results
    
    def get_consent_history(
        self,
        db: Session,
        user_id: int,
        consent_type: Optional[ConsentType] = None,
        tenant_id: str = None
    ) -> List[Dict[str, Any]]:
        """Get consent history for audit purposes."""
        query = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.tenant_id == tenant_id
        )
        
        if consent_type:
            query = query.filter(Consent.consent_type == consent_type)
        
        consents = query.order_by(Consent.created_at.desc()).all()
        
        history = []
        for consent in consents:
            history.append({
                "consent_type": consent.consent_type.value,
                "granted": consent.granted,
                "version": consent.version,
                "purpose": consent.purpose,
                "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                "consent_method": consent.consent_method,
                "created_at": consent.created_at.isoformat()
            })
        
        return history
    
    def withdraw_all_consents(
        self,
        db: Session,
        user_id: int,
        tenant_id: str = None
    ) -> Dict[str, bool]:
        """Withdraw all consents for a user."""
        consents = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.tenant_id == tenant_id,
            Consent.granted == True
        ).all()
        
        results = {}
        for consent in consents:
            consent.granted = False
            consent.revoked_at = datetime.utcnow()
            results[consent.consent_type.value] = True
        
        db.commit()
        
        # Log withdrawal
        audit_logger.log_user_action(
            action="all_consents_withdrawn",
            user_id=user_id,
            resource_type="consent",
            tenant_id=tenant_id,
            details={
                "withdrawn_types": list(results.keys())
            }
        )
        
        return results
    
    def get_users_by_consent(
        self,
        db: Session,
        consent_type: ConsentType,
        granted: bool = True,
        tenant_id: str = None
    ) -> List[int]:
        """Get list of users who have granted/revoked specific consent."""
        consents = db.query(Consent).filter(
            Consent.consent_type == consent_type,
            Consent.granted == granted,
            Consent.tenant_id == tenant_id
        )
        
        if granted:
            # Only include valid consents
            consents = consents.filter(
                Consent.revoked_at.is_(None),
                (Consent.expires_at.is_(None) | (Consent.expires_at > datetime.utcnow()))
            )
        
        return [consent.user_id for consent in consents.all()]
    
    def set_consent_expiry(
        self,
        db: Session,
        user_id: int,
        consent_type: ConsentType,
        days: int,
        tenant_id: str = None
    ) -> bool:
        """Set expiry date for a consent."""
        consent = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.consent_type == consent_type,
            Consent.tenant_id == tenant_id
        ).first()
        
        if consent and consent.granted:
            consent.expires_at = datetime.utcnow() + timedelta(days=days)
            db.commit()
            return True
        
        return False


# Global consent manager instance
consent_manager = ConsentManager()