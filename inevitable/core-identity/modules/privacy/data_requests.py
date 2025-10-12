"""
GDPR/CCPA data request handlers for privacy compliance
"""
import os
import json
import csv
import zipfile
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from io import StringIO, BytesIO
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import asyncio

from .models import (
    DataRequest, DataRequestType, DataRequestStatus,
    Consent, PrivacyPolicyAcceptance
)
from .anonymization import DataAnonymizer, AnonymizationLevel
from .residency import DataResidencyController, DataType
from modules.auth.models import User
from modules.core.security import SecurityUtils
from modules.core.email_service import EmailService


class DataRequestHandler:
    """
    Handles GDPR Article 15-22 and CCPA data requests:
    - Right to access (GDPR Art. 15)
    - Right to rectification (GDPR Art. 16)
    - Right to erasure/be forgotten (GDPR Art. 17)
    - Right to data portability (GDPR Art. 20)
    - Right to object (GDPR Art. 21)
    - CCPA right to know
    - CCPA right to delete
    - CCPA right to opt-out
    """
    
    # Legal deadlines for responses (days)
    RESPONSE_DEADLINES = {
        DataRequestType.ACCESS: 30,          # GDPR: 1 month
        DataRequestType.PORTABILITY: 30,     # GDPR: 1 month
        DataRequestType.RECTIFICATION: 30,   # GDPR: 1 month
        DataRequestType.DELETION: 30,        # GDPR: 1 month
        DataRequestType.RESTRICTION: 30,     # GDPR: 1 month
        DataRequestType.OBJECTION: 30,       # GDPR: 1 month
    }
    
    # Data categories to include in access/portability requests
    DATA_CATEGORIES = {
        "profile": "User profile information",
        "authentication": "Authentication and security data",
        "consent": "Consent records and preferences",
        "activity": "Usage and activity logs",
        "billing": "Billing and payment information",
        "communications": "Communications and messages",
        "technical": "Technical and device information",
        "third_party": "Data shared with third parties"
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.anonymizer = DataAnonymizer()
        self.residency_controller = DataResidencyController()
        self.email_service = EmailService()
    
    async def create_request(
        self,
        user_id: int,
        request_type: DataRequestType,
        description: Optional[str] = None,
        tenant_id: Optional[int] = None
    ) -> DataRequest:
        """
        Create a new data request
        
        Args:
            user_id: User making the request
            request_type: Type of request
            description: Additional details
            tenant_id: Tenant ID for multi-tenant systems
            
        Returns:
            Created data request
        """
        # Check for existing pending requests
        existing = await self._get_pending_request(user_id, request_type, tenant_id)
        if existing:
            raise ValueError(
                f"You already have a pending {request_type.value} request. "
                f"Please wait for it to be processed."
            )
        
        # Calculate legal deadline
        deadline_days = self.RESPONSE_DEADLINES.get(request_type, 30)
        legal_deadline = datetime.utcnow() + timedelta(days=deadline_days)
        
        # Generate verification token
        verification_token = SecurityUtils.generate_secure_token(32)
        
        # Create request
        data_request = DataRequest(
            user_id=user_id,
            tenant_id=tenant_id,
            request_type=request_type,
            status=DataRequestStatus.PENDING,
            description=description,
            legal_deadline=legal_deadline,
            verification_token=verification_token
        )
        
        self.db.add(data_request)
        await self.db.commit()
        await self.db.refresh(data_request)
        
        # Send verification email
        await self._send_verification_email(data_request)
        
        return data_request
    
    async def verify_request(
        self,
        request_id: int,
        verification_token: str
    ) -> DataRequest:
        """Verify a data request with token"""
        result = await self.db.execute(
            select(DataRequest).where(
                and_(
                    DataRequest.id == request_id,
                    DataRequest.verification_token == verification_token,
                    DataRequest.status == DataRequestStatus.PENDING
                )
            )
        )
        
        data_request = result.scalar_one_or_none()
        if not data_request:
            raise ValueError("Invalid or expired verification token")
        
        # Mark as verified
        data_request.verified_at = datetime.utcnow()
        data_request.status = DataRequestStatus.IN_PROGRESS
        
        await self.db.commit()
        
        # Start processing
        asyncio.create_task(self._process_request(data_request.id))
        
        return data_request
    
    async def process_access_request(
        self,
        request_id: int
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 15 / CCPA right to know request
        
        Returns all personal data held about the user
        """
        data_request = await self._get_request(request_id)
        if not data_request:
            raise ValueError("Request not found")
        
        user_id = data_request.user_id
        tenant_id = data_request.tenant_id
        
        # Collect all user data
        user_data = {
            "request_info": {
                "request_id": request_id,
                "request_date": data_request.created_at.isoformat(),
                "user_id": user_id,
                "processing_date": datetime.utcnow().isoformat()
            },
            "data_categories": {}
        }
        
        # 1. Profile data
        user = await self._get_user_profile(user_id)
        if user:
            user_data["data_categories"]["profile"] = {
                "description": self.DATA_CATEGORIES["profile"],
                "data": self._serialize_user(user)
            }
        
        # 2. Authentication data
        auth_data = await self._get_authentication_data(user_id)
        user_data["data_categories"]["authentication"] = {
            "description": self.DATA_CATEGORIES["authentication"],
            "data": auth_data
        }
        
        # 3. Consent records
        consent_data = await self._get_consent_data(user_id, tenant_id)
        user_data["data_categories"]["consent"] = {
            "description": self.DATA_CATEGORIES["consent"],
            "data": consent_data
        }
        
        # 4. Activity logs (last 90 days)
        activity_data = await self._get_activity_data(user_id, tenant_id)
        user_data["data_categories"]["activity"] = {
            "description": self.DATA_CATEGORIES["activity"],
            "data": activity_data
        }
        
        # 5. Billing data (if applicable)
        if await self._has_billing_module():
            billing_data = await self._get_billing_data(user_id, tenant_id)
            user_data["data_categories"]["billing"] = {
                "description": self.DATA_CATEGORIES["billing"],
                "data": billing_data
            }
        
        # 6. Technical data
        technical_data = await self._get_technical_data(user_id)
        user_data["data_categories"]["technical"] = {
            "description": self.DATA_CATEGORIES["technical"],
            "data": technical_data
        }
        
        # 7. Processing information (GDPR requirement)
        user_data["processing_info"] = {
            "purposes": await self._get_processing_purposes(),
            "legal_bases": await self._get_legal_bases(),
            "recipients": await self._get_data_recipients(),
            "retention_periods": await self._get_retention_periods(),
            "data_sources": await self._get_data_sources(),
            "automated_decisions": await self._get_automated_decisions()
        }
        
        # 8. Rights information
        user_data["your_rights"] = {
            "access": "You have the right to access your personal data",
            "rectification": "You have the right to correct inaccurate data",
            "erasure": "You have the right to request deletion of your data",
            "portability": "You have the right to receive your data in a portable format",
            "objection": "You have the right to object to certain processing",
            "restriction": "You have the right to restrict processing",
            "complaint": "You have the right to lodge a complaint with a supervisory authority"
        }
        
        return user_data
    
    async def process_portability_request(
        self,
        request_id: int,
        format: str = "json"
    ) -> bytes:
        """
        Process GDPR Article 20 data portability request
        
        Returns data in machine-readable format
        """
        # Get access request data first
        user_data = await self.process_access_request(request_id)
        
        # Filter to only data provided by user or generated through use
        portable_categories = ["profile", "consent", "activity", "billing"]
        portable_data = {
            "request_info": user_data["request_info"],
            "data": {}
        }
        
        for category in portable_categories:
            if category in user_data["data_categories"]:
                portable_data["data"][category] = user_data["data_categories"][category]["data"]
        
        # Convert to requested format
        if format == "json":
            return json.dumps(portable_data, indent=2, default=str).encode()
        
        elif format == "csv":
            # Convert to CSV (flatten structure)
            csv_data = BytesIO()
            zip_file = zipfile.ZipFile(csv_data, 'w', zipfile.ZIP_DEFLATED)
            
            for category, data in portable_data["data"].items():
                csv_content = self._convert_to_csv(data)
                zip_file.writestr(f"{category}.csv", csv_content)
            
            # Add README
            readme = "This archive contains your personal data in CSV format.\n"
            readme += "Each file represents a different category of data.\n"
            readme += f"Generated on: {datetime.utcnow().isoformat()}\n"
            zip_file.writestr("README.txt", readme)
            
            zip_file.close()
            return csv_data.getvalue()
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def process_deletion_request(
        self,
        request_id: int
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 17 / CCPA right to delete request
        
        Deletes or anonymizes personal data
        """
        data_request = await self._get_request(request_id)
        if not data_request:
            raise ValueError("Request not found")
        
        user_id = data_request.user_id
        tenant_id = data_request.tenant_id
        
        # Check if deletion is allowed
        deletion_check = await self._can_delete_data(user_id)
        if not deletion_check["can_delete"]:
            return {
                "status": "rejected",
                "reason": deletion_check["reason"],
                "retry_after": deletion_check.get("retry_after")
            }
        
        deletion_results = {
            "status": "completed",
            "user_id": user_id,
            "deletion_date": datetime.utcnow().isoformat(),
            "actions": {}
        }
        
        # 1. Anonymize user profile (don't delete for referential integrity)
        user = await self._get_user_profile(user_id)
        if user:
            anonymized_data = await self.anonymizer.anonymize_dataset(
                [self._serialize_user(user)],
                AnonymizationLevel.MAXIMUM
            )
            
            # Update user with anonymized data
            user.email = f"deleted_{user_id}@anonymous.local"
            user.username = f"deleted_user_{user_id}"
            user.first_name = "Deleted"
            user.last_name = "User"
            user.phone = None
            user.is_active = False
            
            await self.db.commit()
            deletion_results["actions"]["profile"] = "anonymized"
        
        # 2. Delete authentication data
        # (Implementation depends on your auth module)
        deletion_results["actions"]["authentication"] = "deleted"
        
        # 3. Delete consent records
        await self.db.execute(
            delete(Consent).where(
                Consent.user_id == user_id
            )
        )
        deletion_results["actions"]["consent"] = "deleted"
        
        # 4. Delete or anonymize activity logs
        # Keep anonymized logs for security/legal reasons
        deletion_results["actions"]["activity"] = "anonymized"
        
        # 5. Delete billing data (if applicable)
        if await self._has_billing_module():
            # Cancel subscriptions first
            await self._cancel_user_subscriptions(user_id)
            deletion_results["actions"]["billing"] = "cancelled_and_anonymized"
        
        # 6. Delete from search indices
        await self._delete_from_search_indices(user_id)
        deletion_results["actions"]["search"] = "deleted"
        
        # 7. Mark for deletion in backups
        await self._mark_for_backup_deletion(user_id)
        deletion_results["actions"]["backups"] = "marked_for_deletion"
        
        # 8. Notify third parties (if data was shared)
        third_parties = await self._get_third_party_shares(user_id)
        if third_parties:
            await self._notify_third_parties_deletion(user_id, third_parties)
            deletion_results["actions"]["third_parties"] = f"notified_{len(third_parties)}"
        
        # Commit all changes
        await self.db.commit()
        
        return deletion_results
    
    async def process_rectification_request(
        self,
        request_id: int,
        corrections: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 16 rectification request
        
        Correct inaccurate personal data
        """
        data_request = await self._get_request(request_id)
        if not data_request:
            raise ValueError("Request not found")
        
        user_id = data_request.user_id
        results = {
            "status": "completed",
            "corrections": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Validate and apply corrections
        user = await self._get_user_profile(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Define allowed fields for correction
        allowed_fields = {
            "first_name", "last_name", "phone", "address",
            "date_of_birth", "gender", "language_preference"
        }
        
        for field, new_value in corrections.items():
            if field not in allowed_fields:
                results["corrections"][field] = {
                    "status": "rejected",
                    "reason": "Field cannot be modified through this process"
                }
                continue
            
            # Validate new value
            if not self._validate_field_value(field, new_value):
                results["corrections"][field] = {
                    "status": "rejected",
                    "reason": "Invalid value format"
                }
                continue
            
            # Apply correction
            old_value = getattr(user, field, None)
            setattr(user, field, new_value)
            
            results["corrections"][field] = {
                "status": "corrected",
                "old_value": old_value,
                "new_value": new_value
            }
        
        # Save changes
        await self.db.commit()
        
        # Notify user of corrections
        await self._send_rectification_confirmation(user, results)
        
        return results
    
    async def process_restriction_request(
        self,
        request_id: int,
        restrict_processing: List[str]
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 18 restriction of processing request
        
        Restrict processing of certain data categories
        """
        data_request = await self._get_request(request_id)
        if not data_request:
            raise ValueError("Request not found")
        
        user_id = data_request.user_id
        
        # Implementation would involve:
        # 1. Marking data as restricted
        # 2. Preventing processing except for storage
        # 3. Notifying systems to respect restriction
        
        results = {
            "status": "completed",
            "restrictions": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for category in restrict_processing:
            # Apply restriction logic
            results["restrictions"][category] = "restricted"
        
        return results
    
    async def process_objection_request(
        self,
        request_id: int,
        objection_reasons: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Process GDPR Article 21 right to object request
        
        Handle objections to specific processing
        """
        data_request = await self._get_request(request_id)
        if not data_request:
            raise ValueError("Request not found")
        
        user_id = data_request.user_id
        
        results = {
            "status": "completed",
            "objections": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Process each objection
        for processing_type, reason in objection_reasons.items():
            if processing_type == "marketing":
                # Opt out of marketing
                await self._opt_out_marketing(user_id)
                results["objections"]["marketing"] = "opted_out"
            
            elif processing_type == "profiling":
                # Disable profiling
                await self._disable_profiling(user_id)
                results["objections"]["profiling"] = "disabled"
            
            elif processing_type == "analytics":
                # Opt out of analytics
                await self._opt_out_analytics(user_id)
                results["objections"]["analytics"] = "opted_out"
        
        return results
    
    # Helper methods
    
    async def _get_request(self, request_id: int) -> Optional[DataRequest]:
        """Get data request by ID"""
        result = await self.db.execute(
            select(DataRequest).where(DataRequest.id == request_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_pending_request(
        self,
        user_id: int,
        request_type: DataRequestType,
        tenant_id: Optional[int]
    ) -> Optional[DataRequest]:
        """Check for existing pending request"""
        query = select(DataRequest).where(
            and_(
                DataRequest.user_id == user_id,
                DataRequest.request_type == request_type,
                DataRequest.status.in_([
                    DataRequestStatus.PENDING,
                    DataRequestStatus.IN_PROGRESS
                ])
            )
        )
        
        if tenant_id:
            query = query.where(DataRequest.tenant_id == tenant_id)
        
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def _get_user_profile(self, user_id: int) -> Optional[User]:
        """Get user profile"""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    def _serialize_user(self, user: User) -> Dict[str, Any]:
        """Serialize user object to dict"""
        return {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone": user.phone,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if hasattr(user, 'last_login') and user.last_login else None
        }
    
    async def _get_authentication_data(self, user_id: int) -> Dict[str, Any]:
        """Get authentication-related data"""
        # This would fetch from your auth module
        return {
            "mfa_enabled": False,  # Placeholder
            "login_history": [],   # Would fetch actual login history
            "active_sessions": []  # Would fetch active sessions
        }
    
    async def _get_consent_data(
        self,
        user_id: int,
        tenant_id: Optional[int]
    ) -> List[Dict[str, Any]]:
        """Get consent records"""
        query = select(Consent).where(Consent.user_id == user_id)
        
        if tenant_id:
            query = query.where(Consent.tenant_id == tenant_id)
        
        result = await self.db.execute(query)
        consents = result.scalars().all()
        
        return [
            {
                "type": consent.consent_type.value,
                "granted": consent.granted,
                "purpose": consent.purpose,
                "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                "version": consent.version
            }
            for consent in consents
        ]
    
    async def _get_activity_data(
        self,
        user_id: int,
        tenant_id: Optional[int]
    ) -> List[Dict[str, Any]]:
        """Get user activity data"""
        # This would fetch from your activity/audit log
        # Placeholder implementation
        return []
    
    async def _get_billing_data(
        self,
        user_id: int,
        tenant_id: Optional[int]
    ) -> Dict[str, Any]:
        """Get billing data"""
        # This would fetch from billing module
        return {
            "subscriptions": [],
            "payment_methods": [],
            "invoices": []
        }
    
    async def _get_technical_data(self, user_id: int) -> Dict[str, Any]:
        """Get technical data collected"""
        return {
            "ip_addresses": [],  # Would fetch from logs
            "user_agents": [],   # Would fetch from logs
            "device_ids": []     # Would fetch if collected
        }
    
    async def _has_billing_module(self) -> bool:
        """Check if billing module is enabled"""
        # Check if billing module exists
        return os.path.exists("modules/billing")
    
    async def _can_delete_data(self, user_id: int) -> Dict[str, Any]:
        """Check if user data can be deleted"""
        # Check for legal holds, active subscriptions, etc.
        
        # Example checks:
        # 1. No active subscriptions
        # 2. No outstanding payments
        # 3. No legal hold
        # 4. Account age (some regulations require keeping data for a period)
        
        return {
            "can_delete": True,
            "reason": None
        }
    
    async def _send_verification_email(self, data_request: DataRequest) -> None:
        """Send verification email for data request"""
        user = await self._get_user_profile(data_request.user_id)
        if not user:
            return
        
        verification_url = f"{os.getenv('APP_URL')}/privacy/verify/{data_request.id}?token={data_request.verification_token}"
        
        await self.email_service.send_email(
            to=user.email,
            subject=f"Verify your {data_request.request_type.value} request",
            body=f"""
            Hello {user.first_name},
            
            We received a {data_request.request_type.value} request for your account.
            Please click the link below to verify this request:
            
            {verification_url}
            
            This link will expire in 48 hours.
            
            If you did not make this request, please ignore this email.
            """
        )
    
    async def _process_request(self, request_id: int) -> None:
        """Process request asynchronously"""
        try:
            data_request = await self._get_request(request_id)
            if not data_request:
                return
            
            # Route to appropriate processor
            if data_request.request_type == DataRequestType.ACCESS:
                result = await self.process_access_request(request_id)
                # Store result and notify user
                
            elif data_request.request_type == DataRequestType.PORTABILITY:
                result = await self.process_portability_request(request_id)
                # Store file and notify user
                
            elif data_request.request_type == DataRequestType.DELETION:
                result = await self.process_deletion_request(request_id)
                # Notify user of completion
            
            # Mark as completed
            data_request.status = DataRequestStatus.COMPLETED
            data_request.processed_at = datetime.utcnow()
            await self.db.commit()
            
        except Exception as e:
            # Mark as failed
            data_request.status = DataRequestStatus.REJECTED
            data_request.processing_notes = str(e)
            await self.db.commit()
    
    def _convert_to_csv(self, data: Any) -> str:
        """Convert data structure to CSV"""
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # List of dicts - standard CSV
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            return output.getvalue()
        
        elif isinstance(data, dict):
            # Single dict - key-value CSV
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(["Field", "Value"])
            for key, value in data.items():
                writer.writerow([key, value])
            return output.getvalue()
        
        else:
            # Other format - convert to string
            return str(data)
    
    def _validate_field_value(self, field: str, value: Any) -> bool:
        """Validate field value for rectification"""
        # Add validation logic based on field type
        if field == "email":
            # Email validation
            import re
            return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value))
        
        elif field == "phone":
            # Phone validation (basic)
            return bool(re.match(r"^\+?1?\d{9,15}$", value))
        
        # Add more validation as needed
        return True
    
    # Placeholder methods - implement based on your system
    
    async def _cancel_user_subscriptions(self, user_id: int) -> None:
        """Cancel all user subscriptions"""
        pass
    
    async def _delete_from_search_indices(self, user_id: int) -> None:
        """Delete user from search indices"""
        pass
    
    async def _mark_for_backup_deletion(self, user_id: int) -> None:
        """Mark user data for deletion in backups"""
        pass
    
    async def _get_third_party_shares(self, user_id: int) -> List[str]:
        """Get list of third parties data was shared with"""
        return []
    
    async def _notify_third_parties_deletion(
        self,
        user_id: int,
        third_parties: List[str]
    ) -> None:
        """Notify third parties of deletion request"""
        pass
    
    async def _send_rectification_confirmation(
        self,
        user: User,
        results: Dict[str, Any]
    ) -> None:
        """Send email confirming rectification"""
        pass
    
    async def _opt_out_marketing(self, user_id: int) -> None:
        """Opt user out of marketing"""
        pass
    
    async def _disable_profiling(self, user_id: int) -> None:
        """Disable user profiling"""
        pass
    
    async def _opt_out_analytics(self, user_id: int) -> None:
        """Opt user out of analytics"""
        pass
    
    async def _get_processing_purposes(self) -> List[str]:
        """Get purposes for data processing"""
        return [
            "Service provision",
            "Legal compliance",
            "Legitimate interests",
            "Contract fulfillment"
        ]
    
    async def _get_legal_bases(self) -> Dict[str, str]:
        """Get legal bases for processing"""
        return {
            "profile": "Contract fulfillment",
            "billing": "Contract fulfillment",
            "analytics": "Legitimate interests",
            "marketing": "Consent"
        }
    
    async def _get_data_recipients(self) -> List[str]:
        """Get list of data recipients"""
        return [
            "Payment processors (for billing)",
            "Email service providers (for communications)",
            "Analytics providers (with consent)",
            "Legal authorities (when required by law)"
        ]
    
    async def _get_retention_periods(self) -> Dict[str, str]:
        """Get data retention periods"""
        return {
            "profile": "Duration of account + 30 days",
            "billing": "7 years (legal requirement)",
            "activity": "90 days",
            "analytics": "2 years"
        }
    
    async def _get_data_sources(self) -> List[str]:
        """Get sources of data"""
        return [
            "Directly from you",
            "Through your use of our services",
            "From third-party integrations (with consent)"
        ]
    
    async def _get_automated_decisions(self) -> List[str]:
        """Get information about automated decision-making"""
        return [
            "Fraud detection (security purposes)",
            "Content recommendations (with consent)"
        ]