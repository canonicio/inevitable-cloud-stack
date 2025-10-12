"""
PayPal service for Platform Forge billing
Provides subscription and payment processing through PayPal
"""
import os
import json
import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from decimal import Decimal

from ..core.config import settings

logger = logging.getLogger(__name__)


class PayPalError(Exception):
    """PayPal API error"""
    pass


class PayPalService:
    """Service for handling PayPal operations."""
    
    def __init__(self):
        self.client_id = settings.PAYPAL_CLIENT_ID or os.getenv("PAYPAL_CLIENT_ID")
        self.client_secret = settings.PAYPAL_CLIENT_SECRET or os.getenv("PAYPAL_CLIENT_SECRET")
        self.environment = settings.PAYPAL_ENVIRONMENT or os.getenv("PAYPAL_ENVIRONMENT", "sandbox")
        
        # Set base URL based on environment
        if self.environment == "live":
            self.base_url = "https://api.paypal.com"
        else:
            self.base_url = "https://api.sandbox.paypal.com"
        
        self._access_token = None
        self._token_expires_at = None
        
        if self.client_id and self.client_secret:
            logger.info(f"PayPal API initialized ({self.environment})")
        else:
            logger.warning("PayPal credentials not configured")
    
    def _get_access_token(self) -> str:
        """Get or refresh PayPal access token"""
        if (self._access_token and self._token_expires_at and 
            datetime.utcnow() < self._token_expires_at):
            return self._access_token
        
        # Request new token
        url = f"{self.base_url}/v1/oauth2/token"
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en_US",
        }
        data = "grant_type=client_credentials"
        
        try:
            response = requests.post(
                url,
                headers=headers,
                data=data,
                auth=(self.client_id, self.client_secret),
                timeout=30
            )
            response.raise_for_status()
            
            token_data = response.json()
            self._access_token = token_data["access_token"]
            expires_in = token_data["expires_in"]  # seconds
            
            # Set expiration with 5-minute buffer
            self._token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 300)
            
            logger.info("PayPal access token refreshed")
            return self._access_token
            
        except requests.RequestException as e:
            logger.error(f"Error getting PayPal access token: {e}")
            raise PayPalError(f"Failed to authenticate with PayPal: {e}")
    
    def _make_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated request to PayPal API"""
        token = self._get_access_token()
        url = f"{self.base_url}{endpoint}"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "PayPal-Request-Id": f"platform-forge-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        }
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=json.dumps(data) if data else None,
                timeout=30
            )
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.RequestException as e:
            logger.error(f"PayPal API error: {e}")
            if hasattr(e, 'response') and e.response:
                try:
                    error_data = e.response.json()
                    logger.error(f"PayPal error details: {error_data}")
                except:
                    pass
            raise PayPalError(f"PayPal API error: {e}")
    
    # Product and Plan Management
    
    def create_product(self, name: str, description: str, product_id: str = None) -> Dict[str, Any]:
        """Create a PayPal product for subscriptions"""
        data = {
            "name": name,
            "description": description,
            "type": "SERVICE",
            "category": "SOFTWARE"
        }
        
        if product_id:
            data["id"] = product_id
        
        return self._make_request("POST", "/v1/catalogs/products", data)
    
    def create_subscription_plan(
        self,
        product_id: str,
        name: str,
        amount: str,
        currency: str = "USD",
        interval_unit: str = "MONTH",
        interval_count: int = 1,
        setup_fee: str = None
    ) -> Dict[str, Any]:
        """Create a subscription plan"""
        billing_cycles = [
            {
                "frequency": {
                    "interval_unit": interval_unit,
                    "interval_count": interval_count
                },
                "tenure_type": "REGULAR",
                "sequence": 1,
                "total_cycles": 0,  # Infinite
                "pricing_scheme": {
                    "fixed_price": {
                        "value": amount,
                        "currency_code": currency
                    }
                }
            }
        ]
        
        # Add setup fee if specified
        if setup_fee:
            billing_cycles.insert(0, {
                "frequency": {
                    "interval_unit": interval_unit,
                    "interval_count": 1
                },
                "tenure_type": "TRIAL",
                "sequence": 1,
                "total_cycles": 1,
                "pricing_scheme": {
                    "fixed_price": {
                        "value": setup_fee,
                        "currency_code": currency
                    }
                }
            })
            # Update regular cycle sequence
            billing_cycles[1]["sequence"] = 2
        
        data = {
            "product_id": product_id,
            "name": name,
            "status": "ACTIVE",
            "billing_cycles": billing_cycles,
            "payment_preferences": {
                "auto_bill_outstanding": True,
                "setup_fee_failure_action": "CONTINUE",
                "payment_failure_threshold": 3
            }
        }
        
        return self._make_request("POST", "/v1/billing/plans", data)
    
    def get_plan(self, plan_id: str) -> Dict[str, Any]:
        """Get subscription plan details"""
        return self._make_request("GET", f"/v1/billing/plans/{plan_id}")
    
    def update_plan(self, plan_id: str, patches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Update subscription plan"""
        return self._make_request("PATCH", f"/v1/billing/plans/{plan_id}", patches)
    
    def deactivate_plan(self, plan_id: str) -> Dict[str, Any]:
        """Deactivate a subscription plan"""
        patches = [
            {
                "op": "replace",
                "path": "/status",
                "value": "INACTIVE"
            }
        ]
        return self.update_plan(plan_id, patches)
    
    # Subscription Management
    
    def create_subscription(
        self,
        plan_id: str,
        return_url: str,
        cancel_url: str,
        custom_id: str = None,
        metadata: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Create a subscription"""
        data = {
            "plan_id": plan_id,
            "application_context": {
                "brand_name": "Platform Forge",
                "locale": "en-US",
                "shipping_preference": "NO_SHIPPING",
                "user_action": "SUBSCRIBE_NOW",
                "return_url": return_url,
                "cancel_url": cancel_url
            }
        }
        
        if custom_id:
            data["custom_id"] = custom_id
        
        if metadata:
            data["custom"] = json.dumps(metadata)
        
        return self._make_request("POST", "/v1/billing/subscriptions", data)
    
    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Get subscription details"""
        return self._make_request("GET", f"/v1/billing/subscriptions/{subscription_id}")
    
    def cancel_subscription(self, subscription_id: str, reason: str = "User requested cancellation") -> Dict[str, Any]:
        """Cancel a subscription"""
        data = {
            "reason": reason
        }
        return self._make_request("POST", f"/v1/billing/subscriptions/{subscription_id}/cancel", data)
    
    def suspend_subscription(self, subscription_id: str, reason: str = "Suspended by admin") -> Dict[str, Any]:
        """Suspend a subscription"""
        data = {
            "reason": reason
        }
        return self._make_request("POST", f"/v1/billing/subscriptions/{subscription_id}/suspend", data)
    
    def activate_subscription(self, subscription_id: str, reason: str = "Activated by admin") -> Dict[str, Any]:
        """Activate a suspended subscription"""
        data = {
            "reason": reason
        }
        return self._make_request("POST", f"/v1/billing/subscriptions/{subscription_id}/activate", data)
    
    def update_subscription_plan(self, subscription_id: str, new_plan_id: str) -> Dict[str, Any]:
        """Update subscription to a different plan"""
        data = {
            "plan_id": new_plan_id,
            "application_context": {
                "brand_name": "Platform Forge",
                "locale": "en-US",
                "user_action": "CONTINUE"
            }
        }
        return self._make_request("POST", f"/v1/billing/subscriptions/{subscription_id}/revise", data)
    
    # Payment Processing
    
    def create_payment(
        self,
        amount: str,
        currency: str = "USD",
        description: str = "Platform Forge Payment",
        return_url: str = None,
        cancel_url: str = None
    ) -> Dict[str, Any]:
        """Create a one-time payment"""
        data = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "amount": {
                        "currency_code": currency,
                        "value": amount
                    },
                    "description": description
                }
            ],
            "application_context": {
                "brand_name": "Platform Forge",
                "locale": "en-US",
                "landing_page": "BILLING",
                "shipping_preference": "NO_SHIPPING",
                "user_action": "PAY_NOW"
            }
        }
        
        if return_url:
            data["application_context"]["return_url"] = return_url
        if cancel_url:
            data["application_context"]["cancel_url"] = cancel_url
        
        return self._make_request("POST", "/v2/checkout/orders", data)
    
    def capture_payment(self, order_id: str) -> Dict[str, Any]:
        """Capture an approved payment"""
        return self._make_request("POST", f"/v2/checkout/orders/{order_id}/capture")
    
    def refund_payment(self, capture_id: str, amount: str = None, currency: str = "USD") -> Dict[str, Any]:
        """Refund a captured payment"""
        data = {}
        if amount:
            data["amount"] = {
                "value": amount,
                "currency_code": currency
            }
        
        return self._make_request("POST", f"/v2/payments/captures/{capture_id}/refund", data)
    
    # Webhook Management
    
    def create_webhook(self, url: str, events: List[str]) -> Dict[str, Any]:
        """Create a webhook endpoint"""
        data = {
            "url": url,
            "event_types": [{"name": event} for event in events]
        }
        return self._make_request("POST", "/v1/notifications/webhooks", data)
    
    def verify_webhook_signature(self, headers: Dict[str, str], body: str, webhook_id: str) -> bool:
        """Verify PayPal webhook signature"""
        try:
            # PayPal webhook verification is more complex and typically
            # requires the webhook certificate. For now, we'll implement
            # basic verification and recommend using PayPal's SDK for production.
            
            # Get webhook details to verify
            webhook_data = self._make_request("GET", f"/v1/notifications/webhooks/{webhook_id}")
            
            # Basic verification - in production, use PayPal's verification API
            expected_headers = ['PAYPAL-TRANSMISSION-ID', 'PAYPAL-CERT-ID', 'PAYPAL-TRANSMISSION-SIG']
            return all(header in headers for header in expected_headers)
            
        except Exception as e:
            logger.error(f"Webhook verification error: {e}")
            return False


# Global service instance
paypal_service = PayPalService()