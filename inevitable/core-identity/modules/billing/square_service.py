"""
Square service for Platform Forge billing
Provides payment processing through Square APIs
"""
import os
import json
import logging
import requests
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from decimal import Decimal

from ..core.config import settings

logger = logging.getLogger(__name__)


class SquareError(Exception):
    """Square API error"""
    pass


class SquareService:
    """Service for handling Square operations."""
    
    def __init__(self):
        self.access_token = settings.SQUARE_ACCESS_TOKEN or os.getenv("SQUARE_ACCESS_TOKEN")
        self.application_id = settings.SQUARE_APPLICATION_ID or os.getenv("SQUARE_APPLICATION_ID")
        self.environment = settings.SQUARE_ENVIRONMENT or os.getenv("SQUARE_ENVIRONMENT", "sandbox")
        self.location_id = settings.SQUARE_LOCATION_ID or os.getenv("SQUARE_LOCATION_ID")
        
        # Set base URL based on environment
        if self.environment == "production":
            self.base_url = "https://connect.squareup.com"
        else:
            self.base_url = "https://connect.squareupsandbox.com"
        
        if self.access_token:
            logger.info(f"Square API initialized ({self.environment})")
        else:
            logger.warning("Square access token not configured")
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Dict[str, Any] = None,
        params: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Square API"""
        url = f"{self.base_url}{endpoint}"
        
        headers = {
            "Square-Version": "2023-10-18",  # Latest API version
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=json.dumps(data) if data else None,
                params=params,
                timeout=30
            )
            
            result = response.json() if response.content else {}
            
            # Check for API errors
            if "errors" in result:
                error_msg = "; ".join([error.get("detail", str(error)) for error in result["errors"]])
                raise SquareError(f"Square API error: {error_msg}")
            
            response.raise_for_status()
            return result
            
        except requests.RequestException as e:
            logger.error(f"Square API request error: {e}")
            raise SquareError(f"Square API error: {e}")
    
    # Customer Management
    
    def create_customer(self, email: str = None, name: str = None, phone: str = None) -> Dict[str, Any]:
        """Create a Square customer"""
        given_name = ""
        family_name = ""
        
        if name:
            name_parts = name.split(" ", 1)
            given_name = name_parts[0]
            family_name = name_parts[1] if len(name_parts) > 1 else ""
        
        data = {}
        if given_name or family_name:
            data["given_name"] = given_name
            data["family_name"] = family_name
        if email:
            data["email_address"] = email
        if phone:
            data["phone_number"] = phone
        
        return self._make_request("POST", "/v2/customers", data)
    
    def get_customer(self, customer_id: str) -> Dict[str, Any]:
        """Get customer details"""
        return self._make_request("GET", f"/v2/customers/{customer_id}")
    
    def update_customer(self, customer_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update customer information"""
        return self._make_request("PUT", f"/v2/customers/{customer_id}", updates)
    
    def delete_customer(self, customer_id: str) -> Dict[str, Any]:
        """Delete a customer"""
        return self._make_request("DELETE", f"/v2/customers/{customer_id}")
    
    def list_customers(self, cursor: str = None, limit: int = 100) -> Dict[str, Any]:
        """List customers"""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        
        return self._make_request("GET", "/v2/customers", params=params)
    
    # Payment Processing
    
    def create_payment(
        self,
        amount: int,  # In cents
        currency: str = "USD",
        source_id: str = None,  # Card nonce or saved card ID
        customer_id: str = None,
        reference_id: str = None,
        note: str = None,
        autocomplete: bool = True
    ) -> Dict[str, Any]:
        """Create a payment"""
        data = {
            "source_id": source_id,
            "idempotency_key": str(uuid.uuid4()),
            "amount_money": {
                "amount": amount,
                "currency": currency
            }
        }
        
        if customer_id:
            data["customer_id"] = customer_id
        if reference_id:
            data["reference_id"] = reference_id
        if note:
            data["note"] = note
        if autocomplete:
            data["autocomplete"] = True
        if self.location_id:
            data["location_id"] = self.location_id
        
        return self._make_request("POST", "/v2/payments", data)
    
    def get_payment(self, payment_id: str) -> Dict[str, Any]:
        """Get payment details"""
        return self._make_request("GET", f"/v2/payments/{payment_id}")
    
    def complete_payment(self, payment_id: str) -> Dict[str, Any]:
        """Complete (capture) a payment"""
        return self._make_request("POST", f"/v2/payments/{payment_id}/complete")
    
    def cancel_payment(self, payment_id: str) -> Dict[str, Any]:
        """Cancel a payment"""
        return self._make_request("POST", f"/v2/payments/{payment_id}/cancel")
    
    def list_payments(
        self,
        begin_time: str = None,
        end_time: str = None,
        cursor: str = None,
        location_id: str = None,
        total: int = None,
        last_4: str = None,
        card_brand: str = None
    ) -> Dict[str, Any]:
        """List payments"""
        params = {}
        if begin_time:
            params["begin_time"] = begin_time
        if end_time:
            params["end_time"] = end_time
        if cursor:
            params["cursor"] = cursor
        if location_id:
            params["location_id"] = location_id
        elif self.location_id:
            params["location_id"] = self.location_id
        if total:
            params["total"] = total
        if last_4:
            params["last_4"] = last_4
        if card_brand:
            params["card_brand"] = card_brand
        
        return self._make_request("GET", "/v2/payments", params=params)
    
    # Refunds
    
    def create_refund(
        self,
        payment_id: str,
        amount: int = None,  # In cents, if None refunds full amount
        currency: str = "USD",
        reason: str = None
    ) -> Dict[str, Any]:
        """Create a refund"""
        data = {
            "idempotency_key": str(uuid.uuid4()),
            "payment_id": payment_id
        }
        
        if amount:
            data["amount_money"] = {
                "amount": amount,
                "currency": currency
            }
        if reason:
            data["reason"] = reason
        
        return self._make_request("POST", "/v2/refunds", data)
    
    def get_refund(self, refund_id: str) -> Dict[str, Any]:
        """Get refund details"""
        return self._make_request("GET", f"/v2/refunds/{refund_id}")
    
    def list_refunds(
        self,
        begin_time: str = None,
        end_time: str = None,
        cursor: str = None,
        location_id: str = None
    ) -> Dict[str, Any]:
        """List refunds"""
        params = {}
        if begin_time:
            params["begin_time"] = begin_time
        if end_time:
            params["end_time"] = end_time
        if cursor:
            params["cursor"] = cursor
        if location_id:
            params["location_id"] = location_id
        elif self.location_id:
            params["location_id"] = self.location_id
        
        return self._make_request("GET", "/v2/refunds", params=params)
    
    # Subscriptions (Square's subscription model is different from Stripe/PayPal)
    
    def create_subscription(
        self,
        location_id: str = None,
        plan_id: str = None,
        customer_id: str = None,
        card_id: str = None,
        start_date: str = None,
        canceled_date: str = None,
        tax_percentage: str = None,
        price_override_money: Dict[str, Any] = None,
        timezone: str = "America/New_York"
    ) -> Dict[str, Any]:
        """Create a subscription"""
        data = {
            "idempotency_key": str(uuid.uuid4()),
            "location_id": location_id or self.location_id,
            "plan_id": plan_id,
            "customer_id": customer_id,
            "timezone": timezone
        }
        
        if card_id:
            data["card_id"] = card_id
        if start_date:
            data["start_date"] = start_date
        if canceled_date:
            data["canceled_date"] = canceled_date
        if tax_percentage:
            data["tax_percentage"] = tax_percentage
        if price_override_money:
            data["price_override_money"] = price_override_money
        
        return self._make_request("POST", "/v2/subscriptions", data)
    
    def get_subscription(self, subscription_id: str, include: List[str] = None) -> Dict[str, Any]:
        """Get subscription details"""
        params = {}
        if include:
            params["include"] = include
        
        return self._make_request("GET", f"/v2/subscriptions/{subscription_id}", params=params)
    
    def update_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update subscription"""
        return self._make_request("PUT", f"/v2/subscriptions/{subscription_id}", updates)
    
    def cancel_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Cancel subscription"""
        return self._make_request("POST", f"/v2/subscriptions/{subscription_id}/cancel")
    
    def pause_subscription(self, subscription_id: str, pause_effective_date: str = None) -> Dict[str, Any]:
        """Pause subscription"""
        data = {}
        if pause_effective_date:
            data["pause_effective_date"] = pause_effective_date
        
        return self._make_request("POST", f"/v2/subscriptions/{subscription_id}/pause", data)
    
    def resume_subscription(self, subscription_id: str, resume_effective_date: str = None) -> Dict[str, Any]:
        """Resume subscription"""
        data = {}
        if resume_effective_date:
            data["resume_effective_date"] = resume_effective_date
        
        return self._make_request("POST", f"/v2/subscriptions/{subscription_id}/resume", data)
    
    def swap_subscription_plan(self, subscription_id: str, new_plan_id: str) -> Dict[str, Any]:
        """Change subscription plan"""
        data = {
            "new_plan_id": new_plan_id
        }
        return self._make_request("POST", f"/v2/subscriptions/{subscription_id}/swap-plan", data)
    
    def list_subscriptions(
        self,
        cursor: str = None,
        location_id: str = None,
        customer_id: str = None
    ) -> Dict[str, Any]:
        """List subscriptions"""
        params = {}
        if cursor:
            params["cursor"] = cursor
        if location_id:
            params["location_id"] = location_id
        elif self.location_id:
            params["location_id"] = self.location_id
        if customer_id:
            params["customer_id"] = customer_id
        
        return self._make_request("GET", "/v2/subscriptions", params=params)
    
    # Catalog (Products/Items)
    
    def create_catalog_item(
        self,
        name: str,
        description: str = None,
        category_id: str = None,
        variations: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a catalog item"""
        item_data = {
            "name": name,
            "description": description or ""
        }
        
        if category_id:
            item_data["category_id"] = category_id
        
        if variations:
            item_data["variations"] = variations
        
        data = {
            "idempotency_key": str(uuid.uuid4()),
            "object": {
                "type": "ITEM",
                "id": f"#{uuid.uuid4()}",
                "item_data": item_data
            }
        }
        
        return self._make_request("POST", "/v2/catalog/object", data)
    
    def get_catalog_item(self, item_id: str) -> Dict[str, Any]:
        """Get catalog item"""
        return self._make_request("GET", f"/v2/catalog/object/{item_id}")
    
    def update_catalog_item(self, item_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update catalog item"""
        return self._make_request("PUT", f"/v2/catalog/object/{item_id}", updates)
    
    def delete_catalog_item(self, item_id: str) -> Dict[str, Any]:
        """Delete catalog item"""
        return self._make_request("DELETE", f"/v2/catalog/object/{item_id}")
    
    def list_catalog_items(self, types: str = "ITEM", cursor: str = None) -> Dict[str, Any]:
        """List catalog items"""
        params = {"types": types}
        if cursor:
            params["cursor"] = cursor
        
        return self._make_request("GET", "/v2/catalog/list", params=params)
    
    # Webhook Management
    
    def create_webhook_subscription(
        self,
        notification_url: str,
        event_types: List[str],
        api_version: str = "2023-10-18"
    ) -> Dict[str, Any]:
        """Create webhook subscription"""
        data = {
            "subscription": {
                "notification_url": notification_url,
                "event_types": event_types,
                "api_version": api_version
            }
        }
        return self._make_request("POST", "/v2/webhooks/subscriptions", data)
    
    def get_webhook_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Get webhook subscription"""
        return self._make_request("GET", f"/v2/webhooks/subscriptions/{subscription_id}")
    
    def update_webhook_subscription(self, subscription_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update webhook subscription"""
        return self._make_request("PUT", f"/v2/webhooks/subscriptions/{subscription_id}", updates)
    
    def delete_webhook_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Delete webhook subscription"""
        return self._make_request("DELETE", f"/v2/webhooks/subscriptions/{subscription_id}")
    
    def list_webhook_subscriptions(self) -> Dict[str, Any]:
        """List webhook subscriptions"""
        return self._make_request("GET", "/v2/webhooks/subscriptions")
    
    def verify_webhook_signature(
        self,
        request_body: str,
        signature_header: str,
        notification_url: str,
        webhook_signature_key: str
    ) -> bool:
        """Verify webhook signature"""
        try:
            import hmac
            import hashlib
            from urllib.parse import urlparse
            
            # Extract the notification URL without query parameters
            parsed_url = urlparse(notification_url)
            url_without_query = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Create the string to sign
            string_to_sign = url_without_query + request_body
            
            # Create HMAC signature
            expected_signature = hmac.new(
                webhook_signature_key.encode('utf-8'),
                string_to_sign.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures
            return hmac.compare_digest(signature_header, expected_signature)
            
        except Exception as e:
            logger.error(f"Webhook signature verification error: {e}")
            return False


# Global service instance
square_service = SquareService()