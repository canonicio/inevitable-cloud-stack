"""
Privacy services for GDPR compliance
"""
import json
import csv
import io
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_
import secrets

from modules.privacy.models import (
    DataRequest, DataRequestType, DataRequestStatus,
    PrivacyPolicy, PrivacyPolicyAcceptance, DataRetention,
    DataProcessingActivity
)
from modules.auth.models import User
from modules.core.security import SecurityUtils
from modules.observability.logging import audit_logger
from modules.admin.audit_logs import AuditLog

logger = logging.getLogger(__name__)


class PrivacyService:
    """Main privacy service for GDPR compliance."""
    
    def create_data_request(
        self,
        db: Session,
        user_id: int,
        request_type: DataRequestType,
        description: str = None,
        tenant_id: str = None
    ) -> DataRequest:
        """Create a new data request."""
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Calculate legal deadline (30 days for GDPR)
        legal_deadline = datetime.utcnow() + timedelta(days=30)
        
        data_request = DataRequest(
            user_id=user_id,
            request_type=request_type,
            description=description,
            verification_token=verification_token,
            legal_deadline=legal_deadline,
            tenant_id=tenant_id
        )
        
        db.add(data_request)
        db.commit()
        
        # Log the request
        audit_logger.log_user_action(
            action="data_request_created",
            user_id=user_id,
            resource_type="data_request",
            resource_id=str(data_request.id),
            tenant_id=tenant_id,
            details={
                "request_type": request_type.value,
                "legal_deadline": legal_deadline.isoformat()
            }
        )
        
        return data_request
    
    def verify_data_request(
        self,
        db: Session,
        request_id: int,
        verification_token: str
    ) -> bool:
        """Verify a data request."""
        data_request = db.query(DataRequest).filter(
            DataRequest.id == request_id,
            DataRequest.verification_token == verification_token,
            DataRequest.status == DataRequestStatus.PENDING
        ).first()
        
        if data_request:
            data_request.verified_at = datetime.utcnow()
            data_request.status = DataRequestStatus.IN_PROGRESS
            db.commit()
            return True
        
        return False
    
    def get_user_data_requests(
        self,
        db: Session,
        user_id: int,
        tenant_id: str = None
    ) -> List[DataRequest]:
        """Get all data requests for a user."""
        return db.query(DataRequest).filter(
            DataRequest.user_id == user_id,
            DataRequest.tenant_id == tenant_id
        ).order_by(DataRequest.created_at.desc()).all()
    
    def process_data_request(
        self,
        db: Session,
        request_id: int,
        processor_id: int,
        action: str,
        notes: str = None
    ) -> DataRequest:
        """Process a data request."""
        data_request = db.query(DataRequest).get(request_id)
        
        if not data_request:
            raise ValueError("Data request not found")
        
        if action == "complete":
            data_request.status = DataRequestStatus.COMPLETED
        elif action == "reject":
            data_request.status = DataRequestStatus.REJECTED
        else:
            raise ValueError("Invalid action")
        
        data_request.processed_by = processor_id
        data_request.processed_at = datetime.utcnow()
        data_request.processing_notes = notes
        
        db.commit()
        
        # Log the processing
        audit_logger.log_admin_action(
            action=f"data_request_{action}",
            admin_id=processor_id,
            target_user_id=data_request.user_id,
            details={
                "request_id": request_id,
                "request_type": data_request.request_type.value,
                "notes": notes
            }
        )
        
        return data_request
    
    def create_privacy_policy(
        self,
        db: Session,
        version: str,
        content: str,
        effective_date: datetime,
        published_by: int,
        summary_of_changes: str = None,
        languages: Dict[str, str] = None
    ) -> PrivacyPolicy:
        """Create a new privacy policy version."""
        policy = PrivacyPolicy(
            version=version,
            content=content,
            effective_date=effective_date,
            published_by=published_by,
            summary_of_changes=summary_of_changes,
            languages=languages or {"en": content}
        )
        
        db.add(policy)
        db.commit()
        
        return policy
    
    def accept_privacy_policy(
        self,
        db: Session,
        user_id: int,
        policy_id: int,
        ip_address: str = None,
        user_agent: str = None,
        tenant_id: str = None
    ) -> PrivacyPolicyAcceptance:
        """Record user acceptance of privacy policy."""
        # Check if already accepted
        existing = db.query(PrivacyPolicyAcceptance).filter(
            PrivacyPolicyAcceptance.user_id == user_id,
            PrivacyPolicyAcceptance.policy_id == policy_id
        ).first()
        
        if existing:
            return existing
        
        acceptance = PrivacyPolicyAcceptance(
            user_id=user_id,
            policy_id=policy_id,
            ip_address=SecurityUtils.sanitize_ip(ip_address) if ip_address else None,
            user_agent=user_agent[:500] if user_agent else None,
            tenant_id=tenant_id
        )
        
        db.add(acceptance)
        db.commit()
        
        # Log acceptance
        audit_logger.log_user_action(
            action="privacy_policy_accepted",
            user_id=user_id,
            resource_type="privacy_policy",
            resource_id=str(policy_id),
            tenant_id=tenant_id
        )
        
        return acceptance
    
    def get_active_privacy_policy(
        self,
        db: Session,
        language: str = "en"
    ) -> Optional[PrivacyPolicy]:
        """Get the currently active privacy policy."""
        policy = db.query(PrivacyPolicy).filter(
            PrivacyPolicy.is_active == True,
            PrivacyPolicy.effective_date <= datetime.utcnow()
        ).order_by(PrivacyPolicy.effective_date.desc()).first()
        
        if policy and policy.languages and language in policy.languages:
            # Return localized version
            localized_policy = PrivacyPolicy()
            localized_policy.__dict__.update(policy.__dict__)
            localized_policy.content = policy.languages[language]
            return localized_policy
        
        return policy
    
    def configure_data_retention(
        self,
        db: Session,
        data_type: str,
        retention_days: int,
        description: str = None,
        legal_basis: str = None,
        auto_delete: bool = True,
        tenant_id: str = None
    ) -> DataRetention:
        """Configure data retention policy."""
        retention = db.query(DataRetention).filter(
            DataRetention.data_type == data_type,
            DataRetention.tenant_id == tenant_id
        ).first()
        
        if retention:
            retention.retention_days = retention_days
            retention.description = description
            retention.legal_basis = legal_basis
            retention.auto_delete = auto_delete
        else:
            retention = DataRetention(
                data_type=data_type,
                retention_days=retention_days,
                description=description,
                legal_basis=legal_basis,
                auto_delete=auto_delete,
                tenant_id=tenant_id
            )
            db.add(retention)
        
        db.commit()
        return retention
    
    def get_data_retention_policies(
        self,
        db: Session,
        tenant_id: str = None
    ) -> List[DataRetention]:
        """Get all data retention policies."""
        return db.query(DataRetention).filter(
            DataRetention.tenant_id == tenant_id
        ).all()
    
    def record_processing_activity(
        self,
        db: Session,
        name: str,
        purposes: List[str],
        legal_basis: str,
        data_categories: List[str],
        data_subjects: List[str],
        controller: str,
        security_measures: str,
        retention_period: str,
        recipients: List[str] = None,
        processor: str = None,
        dpo_contact: str = None,
        tenant_id: str = None
    ) -> DataProcessingActivity:
        """Record data processing activity for GDPR Article 30."""
        activity = DataProcessingActivity(
            name=name,
            purposes=purposes,
            legal_basis=legal_basis,
            data_categories=data_categories,
            data_subjects=data_subjects,
            controller=controller,
            processor=processor,
            security_measures=security_measures,
            retention_period=retention_period,
            recipients=recipients,
            dpo_contact=dpo_contact,
            tenant_id=tenant_id
        )
        
        db.add(activity)
        db.commit()
        
        return activity


class DataExportService:
    """Service for handling data export requests."""
    
    def export_user_data(
        self,
        db: Session,
        user_id: int,
        format: str = "json",
        tenant_id: str = None
    ) -> Dict[str, Any]:
        """Export all user data in requested format."""
        data = self._collect_user_data(db, user_id, tenant_id)
        
        if format == "json":
            return self._export_as_json(data)
        elif format == "csv":
            return self._export_as_csv(data)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _collect_user_data(
        self,
        db: Session,
        user_id: int,
        tenant_id: str
    ) -> Dict[str, Any]:
        """Collect all user data from different tables."""
        user = db.query(User).get(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Collect data from various sources
        data = {
            "user_profile": {
                "id": user.id,
                "email": user.email,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "is_active": user.is_active
            },
            "consents": [],
            "audit_logs": [],
            "data_requests": []
        }
        
        # Get consents
        from modules.privacy.models import Consent
        consents = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.tenant_id == tenant_id
        ).all()
        
        for consent in consents:
            data["consents"].append({
                "type": consent.consent_type.value,
                "granted": consent.granted,
                "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                "version": consent.version
            })
        
        # Get audit logs
        audit_logs = db.query(AuditLog).filter(
            AuditLog.user_id == user_id,
            AuditLog.tenant_id == tenant_id
        ).limit(1000).all()  # Limit for performance
        
        for log in audit_logs:
            data["audit_logs"].append({
                "action": log.action,
                "timestamp": log.created_at.isoformat(),
                "resource_type": log.resource_type,
                "resource_id": log.resource_id
            })
        
        # Get data requests
        requests = db.query(DataRequest).filter(
            DataRequest.user_id == user_id,
            DataRequest.tenant_id == tenant_id
        ).all()
        
        for req in requests:
            data["data_requests"].append({
                "type": req.request_type.value,
                "status": req.status.value,
                "created_at": req.created_at.isoformat(),
                "processed_at": req.processed_at.isoformat() if req.processed_at else None
            })
        
        return data
    
    def _export_as_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Export data as JSON."""
        return {
            "format": "json",
            "content": json.dumps(data, indent=2),
            "filename": f"user_data_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            "content_type": "application/json"
        }
    
    def _export_as_csv(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Export data as CSV files."""
        files = {}
        
        for section, records in data.items():
            if isinstance(records, list) and records:
                output = io.StringIO()
                if records:
                    writer = csv.DictWriter(output, fieldnames=records[0].keys())
                    writer.writeheader()
                    writer.writerows(records)
                    files[f"{section}.csv"] = output.getvalue()
            elif isinstance(records, dict):
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=["field", "value"])
                writer.writeheader()
                for key, value in records.items():
                    writer.writerow({"field": key, "value": value})
                files[f"{section}.csv"] = output.getvalue()
        
        return {
            "format": "csv",
            "files": files,
            "filename": f"user_data_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip",
            "content_type": "application/zip"
        }


class DataDeletionService:
    """Service for handling data deletion requests."""
    
    def delete_user_data(
        self,
        db: Session,
        user_id: int,
        tenant_id: str = None,
        preserve_legal_records: bool = True
    ) -> Dict[str, int]:
        """Delete user data while preserving legally required records."""
        deletion_report = {}
        
        # Anonymize user profile
        user = db.query(User).get(user_id)
        if user:
            user.email = f"deleted_user_{user.id}@deleted.local"
            user.is_active = False
            deletion_report["user_anonymized"] = 1
        
        # Delete consents (keeping audit trail)
        from modules.privacy.models import Consent
        consents_deleted = db.query(Consent).filter(
            Consent.user_id == user_id,
            Consent.tenant_id == tenant_id
        ).delete()
        deletion_report["consents_deleted"] = consents_deleted
        
        # Keep audit logs if required for legal purposes
        if not preserve_legal_records:
            logs_deleted = db.query(AuditLog).filter(
                AuditLog.user_id == user_id,
                AuditLog.tenant_id == tenant_id
            ).delete()
            deletion_report["audit_logs_deleted"] = logs_deleted
        
        db.commit()
        
        # Log the deletion
        audit_logger.log_user_action(
            action="user_data_deleted",
            user_id=user_id,
            resource_type="user_data",
            tenant_id=tenant_id,
            details=deletion_report
        )
        
        return deletion_report


class DataRetentionService:
    """Service for managing data retention policies."""
    
    def apply_retention_policy(
        self,
        db: Session,
        retention_days: int,
        data_category: str,
        tenant_id: str = None
    ) -> Dict[str, int]:
        """Apply retention policy by deleting data older than retention period."""
        retention_date = datetime.utcnow() - timedelta(days=retention_days)
        deletion_report = {"category": data_category, "retention_days": retention_days}
        
        if data_category == "audit_logs":
            # Delete old audit logs
            logs_deleted = db.query(AuditLog).filter(
                AuditLog.created_at < retention_date,
                AuditLog.tenant_id == tenant_id
            ).delete()
            deletion_report["audit_logs_deleted"] = logs_deleted
            
        elif data_category == "user_activity":
            # Delete old user activity records
            from modules.privacy.models import UserActivity
            activities_deleted = db.query(UserActivity).filter(
                UserActivity.created_at < retention_date,
                UserActivity.tenant_id == tenant_id
            ).delete()
            deletion_report["activities_deleted"] = activities_deleted
            
        elif data_category == "consent_history":
            # Keep only the most recent consent record per type
            from modules.privacy.models import Consent
            from sqlalchemy import func
            
            # Find old consent records
            subquery = db.query(
                Consent.user_id,
                Consent.consent_type,
                func.max(Consent.id).label('max_id')
            ).filter(
                Consent.tenant_id == tenant_id
            ).group_by(
                Consent.user_id,
                Consent.consent_type
            ).subquery()
            
            # Delete all but the most recent
            old_consents = db.query(Consent).filter(
                Consent.created_at < retention_date,
                Consent.tenant_id == tenant_id,
                ~Consent.id.in_(db.query(subquery.c.max_id))
            ).delete(synchronize_session=False)
            
            deletion_report["old_consents_deleted"] = old_consents
        
        db.commit()
        
        # Log retention policy application
        audit_logger.log_system_action(
            action="retention_policy_applied",
            resource_type="data_retention",
            tenant_id=tenant_id,
            details=deletion_report
        )
        
        return deletion_report
    
    def get_retention_schedule(
        self,
        db: Session,
        tenant_id: str = None
    ) -> List[Dict[str, Any]]:
        """Get configured retention policies."""
        from modules.privacy.models import DataRetention
        
        policies = db.query(DataRetention).filter(
            DataRetention.tenant_id == tenant_id,
            DataRetention.is_active == True
        ).all()
        
        return [
            {
                "data_category": policy.data_category,
                "retention_days": policy.retention_days,
                "description": policy.description,
                "last_applied": policy.last_applied_at
            }
            for policy in policies
        ]


# Global service instances
privacy_service = PrivacyService()
data_export_service = DataExportService()
data_deletion_service = DataDeletionService()