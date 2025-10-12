"""
Privacy/GDPR Module
Provides comprehensive privacy compliance features:
- Consent management (GDPR/CCPA)
- Data subject rights (access, portability, deletion, etc.)
- Data anonymization with k-anonymity and differential privacy
- Data residency controls for multi-region compliance
- Privacy-preserving analytics
- Automated compliance reporting
"""
from .models import (
    Consent, ConsentType,
    DataRequest, DataRequestType, DataRequestStatus,
    PrivacyPolicy, PrivacyPolicyAcceptance,
    DataRetention, DataProcessingActivity
)
from .routes import router as privacy_router
from .enhanced_routes import router as enhanced_privacy_router
from .services import PrivacyService, DataExportService, DataDeletionService
from .consent import ConsentManager

# Import new enhanced components
from .consent_manager import ConsentManager as EnhancedConsentManager, ConsentPurpose
from .anonymization import DataAnonymizer, AnonymizationLevel
from .residency import DataResidencyController, DataRegion, DataType, TransferMechanism
from .data_requests import DataRequestHandler

__all__ = [
    # Models
    'Consent', 'ConsentType',
    'DataRequest', 'DataRequestType', 'DataRequestStatus',
    'PrivacyPolicy', 'PrivacyPolicyAcceptance',
    'DataRetention', 'DataProcessingActivity',
    
    # Routers
    'privacy_router',
    'enhanced_privacy_router',
    
    # Services (legacy)
    'PrivacyService',
    'DataExportService',
    'DataDeletionService',
    'ConsentManager',
    
    # Enhanced Services
    'EnhancedConsentManager', 'ConsentPurpose',
    'DataAnonymizer', 'AnonymizationLevel',
    'DataResidencyController', 'DataRegion', 'DataType', 'TransferMechanism',
    'DataRequestHandler'
]