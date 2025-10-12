"""
License key generation utility (for testing and administration)
"""
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .license import LicenseType, FeatureScope


class LicenseGenerator:
    """Generate signed license keys"""
    
    def __init__(self, private_key_pem: Optional[str] = None):
        if private_key_pem:
            self.private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None
            )
        else:
            # Generate a new key pair for testing
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        
        self.public_key = self.private_key.public_key()
        self.public_key_id = "platform-forge-2024"
    
    def generate_license(
        self,
        license_type: LicenseType,
        organization_name: str,
        contact_email: str,
        allowed_features: List[FeatureScope],
        expires_at: Optional[datetime] = None,
        max_users: Optional[int] = None,
        max_api_calls_per_month: Optional[int] = None,
        max_storage_gb: Optional[int] = None,
        feature_limits: Optional[Dict[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a signed license key"""
        
        # Create license data
        license_data = {
            "license_type": license_type.value,
            "organization_name": organization_name,
            "contact_email": contact_email,
            "allowed_features": [f.value for f in allowed_features],
            "issued_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "max_users": max_users,
            "max_api_calls_per_month": max_api_calls_per_month,
            "max_storage_gb": max_storage_gb,
            "feature_limits": feature_limits or {},
            "metadata": metadata or {},
            "public_key_id": self.public_key_id
        }
        
        # Generate unique license key
        import uuid
        license_key = f"PF-{license_type.value.upper()}-{str(uuid.uuid4()).replace('-', '').upper()[:16]}"
        license_data["license_key"] = license_key
        
        # Sign the license
        signature = self._sign_license_data(license_data)
        license_data["signature"] = signature
        
        # Encode as base64
        license_json = json.dumps(license_data, sort_keys=True)
        license_key_encoded = base64.b64encode(license_json.encode()).decode()
        
        return license_key_encoded
    
    def _sign_license_data(self, license_data: Dict[str, Any]) -> str:
        """Sign license data"""
        # Create message to sign (excluding signature field)
        sign_data = {
            "license_key": license_data["license_key"],
            "license_type": license_data["license_type"],
            "organization_name": license_data["organization_name"],
            "expires_at": license_data.get("expires_at"),
            "allowed_features": license_data["allowed_features"],
            "max_users": license_data.get("max_users"),
            "max_api_calls_per_month": license_data.get("max_api_calls_per_month")
        }
        
        message = json.dumps(sign_data, sort_keys=True).encode()
        
        # Sign with private key
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def get_private_key_pem(self) -> str:
        """Get private key in PEM format (for backup/storage)"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()


def generate_test_licenses() -> Dict[str, str]:
    """Generate test licenses for different tiers"""
    generator = LicenseGenerator()
    
    licenses = {}
    
    # Free tier license (basic features only)
    licenses["free"] = generator.generate_license(
        license_type=LicenseType.FREE,
        organization_name="Test Organization Free",
        contact_email="test@example.com",
        allowed_features=[FeatureScope.MCP_BASIC],
        max_users=5,
        max_api_calls_per_month=10000,
        max_storage_gb=1
    )
    
    # Starter tier license
    licenses["starter"] = generator.generate_license(
        license_type=LicenseType.STARTER,
        organization_name="Test Organization Starter",
        contact_email="test@example.com",
        allowed_features=[
            FeatureScope.MCP_BASIC,
            FeatureScope.WEB3_AUTH,
            FeatureScope.ANALYTICS_ADVANCED
        ],
        max_users=25,
        max_api_calls_per_month=100000,
        max_storage_gb=10,
        expires_at=datetime.utcnow() + timedelta(days=365)
    )
    
    # Professional tier license
    licenses["professional"] = generator.generate_license(
        license_type=LicenseType.PROFESSIONAL,
        organization_name="Test Organization Pro",
        contact_email="test@example.com",
        allowed_features=[
            FeatureScope.MCP_BASIC,
            FeatureScope.MCP_ADVANCED,
            FeatureScope.WEB3_AUTH,
            FeatureScope.WEB3_BILLING,
            FeatureScope.ANALYTICS_ADVANCED,
            FeatureScope.BILLING_ADVANCED,
            FeatureScope.PERFORMANCE_MONITORING
        ],
        max_users=100,
        max_api_calls_per_month=1000000,
        max_storage_gb=100,
        expires_at=datetime.utcnow() + timedelta(days=365),
        feature_limits={
            "mcp_advanced": {"daily_limit": 1000},
            "web3_billing": {"daily_limit": 500}
        }
    )
    
    # Enterprise tier license (unlimited)
    licenses["enterprise"] = generator.generate_license(
        license_type=LicenseType.ENTERPRISE,
        organization_name="Test Organization Enterprise",
        contact_email="test@example.com",
        allowed_features=[
            FeatureScope.MCP_BASIC,
            FeatureScope.MCP_ADVANCED,
            FeatureScope.ENTERPRISE_SSO,
            FeatureScope.WEB3_AUTH,
            FeatureScope.WEB3_BILLING,
            FeatureScope.ANALYTICS_ADVANCED,
            FeatureScope.BILLING_ADVANCED,
            FeatureScope.PERFORMANCE_MONITORING,
            FeatureScope.CUSTOM_BRANDING,
            FeatureScope.API_UNLIMITED,
            FeatureScope.PRIORITY_SUPPORT
        ],
        max_users=None,  # Unlimited
        max_api_calls_per_month=None,  # Unlimited
        max_storage_gb=None,  # Unlimited
        expires_at=datetime.utcnow() + timedelta(days=365),
        metadata={
            "enterprise_features": {
                "dedicated_support": True,
                "custom_integrations": True,
                "priority_queue": True
            }
        }
    )
    
    return licenses


def print_test_licenses():
    """Print test licenses for easy copying"""
    licenses = generate_test_licenses()
    
    print("=" * 80)
    print("PLATFORM FORGE TEST LICENSES")
    print("=" * 80)
    
    for tier, license_key in licenses.items():
        print(f"\n{tier.upper()} TIER:")
        print("-" * 40)
        print(f"License Key: {license_key}")
        print(f"Length: {len(license_key)} characters")
        
        # Decode and show content
        try:
            decoded = json.loads(base64.b64decode(license_key).decode())
            print(f"Organization: {decoded['organization_name']}")
            print(f"Type: {decoded['license_type']}")
            print(f"Features: {', '.join(decoded['allowed_features'])}")
            print(f"Max Users: {decoded.get('max_users', 'Unlimited')}")
            print(f"Max API Calls/Month: {decoded.get('max_api_calls_per_month', 'Unlimited')}")
            print(f"Expires: {decoded.get('expires_at', 'Never')}")
        except Exception as e:
            print(f"Error decoding: {e}")
    
    print("\n" + "=" * 80)
    print("Copy any license key above to test the license system")
    print("=" * 80)


if __name__ == "__main__":
    print_test_licenses()