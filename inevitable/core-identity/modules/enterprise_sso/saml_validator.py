"""
SAML Response Validator with Signature Wrapping Protection
Addresses CRITICAL-SSO-001: SAML Signature Wrapping Attack
"""
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
import xml.etree.ElementTree as ET
from lxml import etree
from signxml import XMLSigner, XMLVerifier, InvalidSignature
import logging

from ..core.config import settings

logger = logging.getLogger(__name__)


class SAMLValidator:
    """
    Secure SAML response validator with comprehensive security checks
    Prevents signature wrapping, XXE, and replay attacks
    """
    
    def __init__(
        self,
        idp_cert: str,
        sp_entity_id: str,
        idp_entity_id: str,
        allowed_clock_skew: int = 300  # 5 minutes
    ):
        """
        Initialize SAML validator
        
        Args:
            idp_cert: Identity Provider's X.509 certificate
            sp_entity_id: Service Provider entity ID
            idp_entity_id: Identity Provider entity ID
            allowed_clock_skew: Allowed time difference in seconds
        """
        self.idp_cert = idp_cert
        self.sp_entity_id = sp_entity_id
        self.idp_entity_id = idp_entity_id
        self.allowed_clock_skew = allowed_clock_skew
        
        # Track processed assertions to prevent replay
        self.processed_assertions = set()
        self.max_assertion_age = 3600  # 1 hour
    
    def validate_saml_response(
        self,
        saml_response: str,
        expected_in_response_to: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Validate SAML response with comprehensive security checks
        
        Returns:
            (is_valid, user_data, error_message)
        """
        try:
            # Decode SAML response
            try:
                decoded = base64.b64decode(saml_response)
            except Exception as e:
                return False, None, f"Failed to decode SAML response: {e}"
            
            # Parse XML securely (prevent XXE)
            try:
                parser = etree.XMLParser(
                    no_network=True,
                    resolve_entities=False,
                    dtd_validation=False,
                    load_dtd=False
                )
                root = etree.fromstring(decoded, parser)
            except Exception as e:
                return False, None, f"Failed to parse SAML XML: {e}"
            
            # CRITICAL: Check for multiple assertions (signature wrapping attack)
            assertions = root.findall(
                './/{urn:oasis:names:tc:SAML:2.0:assertion}Assertion'
            )
            
            if len(assertions) == 0:
                return False, None, "No assertions found in SAML response"
            
            if len(assertions) > 1:
                logger.error(
                    f"SECURITY: Multiple assertions detected ({len(assertions)}). "
                    f"Possible signature wrapping attack!"
                )
                return False, None, "Multiple assertions detected - possible attack"
            
            assertion = assertions[0]
            
            # Verify signature on the assertion
            try:
                verified_data = XMLVerifier().verify(
                    etree.tostring(assertion),
                    x509_cert=self.idp_cert
                )
            except InvalidSignature as e:
                logger.error(f"SAML signature verification failed: {e}")
                return False, None, "Invalid SAML signature"
            
            # Additional signature position check
            # Ensure signature is inside the assertion, not wrapped around it
            signatures = assertion.findall(
                './/{http://www.w3.org/2000/09/xmldsig#}Signature'
            )
            
            if len(signatures) != 1:
                logger.error(
                    f"SECURITY: Unexpected number of signatures in assertion: {len(signatures)}"
                )
                return False, None, "Invalid signature structure"
            
            # Verify the signature references the assertion ID
            signature = signatures[0]
            reference = signature.find(
                './/{http://www.w3.org/2000/09/xmldsig#}Reference'
            )
            
            if reference is not None:
                ref_uri = reference.get('URI', '')
                assertion_id = assertion.get('ID', '')
                
                if not ref_uri.startswith('#') or ref_uri[1:] != assertion_id:
                    logger.error(
                        f"SECURITY: Signature reference mismatch. "
                        f"Expected: #{assertion_id}, Got: {ref_uri}"
                    )
                    return False, None, "Signature reference mismatch"
            
            # Check assertion ID for replay attacks
            assertion_id = assertion.get('ID')
            if assertion_id in self.processed_assertions:
                logger.error(f"SECURITY: Assertion replay detected: {assertion_id}")
                return False, None, "Assertion has already been processed"
            
            # Validate time constraints
            conditions = assertion.find(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'
            )
            
            if conditions is not None:
                not_before = conditions.get('NotBefore')
                not_on_or_after = conditions.get('NotOnOrAfter')
                
                now = datetime.utcnow()
                
                if not_before:
                    not_before_time = datetime.fromisoformat(
                        not_before.replace('Z', '+00:00')
                    )
                    if now < not_before_time - timedelta(seconds=self.allowed_clock_skew):
                        return False, None, "Assertion not yet valid"
                
                if not_on_or_after:
                    not_after_time = datetime.fromisoformat(
                        not_on_or_after.replace('Z', '+00:00')
                    )
                    if now >= not_after_time + timedelta(seconds=self.allowed_clock_skew):
                        return False, None, "Assertion has expired"
            
            # Validate audience restriction
            audience_restrictions = assertion.findall(
                './/{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction'
            )
            
            valid_audience = False
            for restriction in audience_restrictions:
                audiences = restriction.findall(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}Audience'
                )
                for audience in audiences:
                    if audience.text == self.sp_entity_id:
                        valid_audience = True
                        break
            
            if not valid_audience and audience_restrictions:
                logger.error(
                    f"SECURITY: Invalid audience. Expected: {self.sp_entity_id}"
                )
                return False, None, "Invalid audience restriction"
            
            # Validate issuer
            issuer = assertion.find(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer'
            )
            
            if issuer is None or issuer.text != self.idp_entity_id:
                logger.error(
                    f"SECURITY: Invalid issuer. "
                    f"Expected: {self.idp_entity_id}, Got: {issuer.text if issuer else 'None'}"
                )
                return False, None, "Invalid assertion issuer"
            
            # Validate InResponseTo if provided
            if expected_in_response_to:
                subject = assertion.find(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}Subject'
                )
                if subject is not None:
                    subject_confirmations = subject.findall(
                        '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation'
                    )
                    
                    valid_response = False
                    for confirmation in subject_confirmations:
                        confirmation_data = confirmation.find(
                            '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData'
                        )
                        if confirmation_data is not None:
                            in_response_to = confirmation_data.get('InResponseTo')
                            if in_response_to == expected_in_response_to:
                                valid_response = True
                                break
                    
                    if not valid_response:
                        logger.error(
                            f"SECURITY: InResponseTo mismatch. "
                            f"Expected: {expected_in_response_to}"
                        )
                        return False, None, "Invalid InResponseTo value"
            
            # Extract user attributes
            user_data = self._extract_user_attributes(assertion)
            
            if not user_data:
                return False, None, "No user attributes found"
            
            # Mark assertion as processed (prevent replay)
            self.processed_assertions.add(assertion_id)
            
            # Clean old assertions periodically
            if len(self.processed_assertions) > 10000:
                self.processed_assertions.clear()
            
            logger.info(
                f"SAML response validated successfully for user: {user_data.get('email', 'unknown')}"
            )
            
            return True, user_data, None
            
        except Exception as e:
            logger.error(f"SAML validation error: {e}")
            return False, None, f"Validation error: {str(e)}"
    
    def _extract_user_attributes(self, assertion: ET.Element) -> Dict[str, Any]:
        """Extract user attributes from SAML assertion"""
        user_data = {}
        
        # Extract NameID
        subject = assertion.find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Subject'
        )
        if subject is not None:
            name_id = subject.find(
                '{urn:oasis:names:tc:SAML:2.0:assertion}NameID'
            )
            if name_id is not None:
                user_data['name_id'] = name_id.text
                user_data['name_id_format'] = name_id.get('Format', '')
        
        # Extract attributes
        attribute_statements = assertion.findall(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement'
        )
        
        for statement in attribute_statements:
            attributes = statement.findall(
                '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
            )
            
            for attribute in attributes:
                attr_name = attribute.get('Name')
                attr_values = attribute.findall(
                    '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
                )
                
                if attr_values:
                    # Handle multiple values
                    values = [v.text for v in attr_values if v.text]
                    
                    if len(values) == 1:
                        user_data[attr_name] = values[0]
                    else:
                        user_data[attr_name] = values
        
        # Map common attributes
        attribute_mapping = {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'email',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'name',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'first_name',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'last_name',
            'http://schemas.microsoft.com/identity/claims/displayname': 'display_name',
        }
        
        mapped_data = {}
        for saml_attr, friendly_name in attribute_mapping.items():
            if saml_attr in user_data:
                mapped_data[friendly_name] = user_data[saml_attr]
        
        # Include both mapped and unmapped attributes
        user_data.update(mapped_data)
        
        return user_data
    
    def generate_authn_request(
        self,
        sso_url: str,
        assertion_consumer_service_url: str,
        force_authn: bool = False,
        name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    ) -> Tuple[str, str]:
        """
        Generate SAML authentication request
        
        Returns:
            (request_id, encoded_request)
        """
        import uuid
        from urllib.parse import quote
        
        request_id = f"id-{uuid.uuid4()}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        authn_request = f"""
        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{issue_instant}"
            Destination="{sso_url}"
            AssertionConsumerServiceURL="{assertion_consumer_service_url}"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>{self.sp_entity_id}</saml:Issuer>
            <samlp:NameIDPolicy
                Format="{name_id_format}"
                AllowCreate="true" />
        </samlp:AuthnRequest>
        """.strip()
        
        # Base64 encode
        encoded = base64.b64encode(authn_request.encode()).decode()
        
        return request_id, encoded
