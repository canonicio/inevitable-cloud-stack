"""
Extended Webhook Handlers for Subscription Management

Handles subscription lifecycle events and integrates with audit logging.
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from .subscription_management import (
    SubscriptionMigration, MigrationStatus, SubscriptionAuditLog
)
from .models import Customer, Package
from pydantic import ValidationError

logger = logging.getLogger(__name__)


class SubscriptionWebhookHandler:
    """Handle subscription-related webhook events with audit logging"""
    
    def __init__(self):
        self.event_handlers = {
            "customer.subscription.created": self.handle_subscription_created,
            "customer.subscription.updated": self.handle_subscription_updated,
            "customer.subscription.deleted": self.handle_subscription_deleted,
            "customer.subscription.paused": self.handle_subscription_paused,
            "customer.subscription.resumed": self.handle_subscription_resumed,
            "customer.subscription.pending_update_applied": self.handle_pending_update_applied,
            "customer.subscription.pending_update_expired": self.handle_pending_update_expired,
            "customer.subscription.trial_will_end": self.handle_trial_will_end,
            "price.created": self.handle_price_created,
            "price.updated": self.handle_price_updated,
            "price.deleted": self.handle_price_deleted,
        }
    
    async def process_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Process a webhook event"""
        handler = self.event_handlers.get(event_type)
        
        if not handler:
            logger.info(f"No handler for event type: {event_type}")
            return {"status": "ignored", "message": f"No handler for {event_type}"}
        
        try:
            result = await handler(event_data, db)
            return {"status": "success", "result": result}
        except Exception as e:
            logger.error(f"Error processing {event_type}: {e}")
            return {"status": "error", "message": str(e)}
    
    async def handle_subscription_created(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle new subscription creation"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        customer_id = subscription.get("customer")
        
        # Get or create customer
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == customer_id
        ).first()
        
        if not customer:
            logger.warning(f"Customer {customer_id} not found for subscription {subscription_id}")
            return {"warning": "Customer not found"}
        
        # Create or update package
        package = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id
        ).first()
        
        if not package:
            package = Package(
                customer_id=customer.id,
                stripe_subscription_id=subscription_id,
                plan_id=subscription["items"]["data"][0]["price"]["id"],
                status=subscription["status"],
                current_period_start=datetime.fromtimestamp(subscription["current_period_start"]),
                current_period_end=datetime.fromtimestamp(subscription["current_period_end"]),
                tenant_id=customer.tenant_id
            )
            db.add(package)
        
        # Log audit
        self._log_audit(
            db=db,
            subscription_id=subscription_id,
            customer_id=customer.id,
            action="created",
            old_values={},
            new_values={
                "plan_id": package.plan_id,
                "status": package.status
            },
            initiated_by_type="webhook",
            reason="Subscription created via Stripe"
        )
        
        db.commit()
        
        return {
            "subscription_id": subscription_id,
            "customer_id": customer.id,
            "action": "created"
        }
    
    async def handle_subscription_updated(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle subscription updates"""
        subscription = event_data.get("data", {}).get("object", {})
        previous = event_data.get("data", {}).get("previous_attributes", {})
        subscription_id = subscription.get("id")
        
        # Get package
        package = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id
        ).first()
        
        if not package:
            logger.warning(f"Package not found for subscription {subscription_id}")
            return {"warning": "Package not found"}
        
        # Track what changed
        old_values = {}
        new_values = {}
        
        # Check for plan change
        if "items" in previous:
            old_plan = previous["items"]["data"][0]["price"]["id"]
            new_plan = subscription["items"]["data"][0]["price"]["id"]
            if old_plan != new_plan:
                old_values["plan_id"] = old_plan
                new_values["plan_id"] = new_plan
                package.plan_id = new_plan
                
                # Check if this was from a migration
                migration = db.query(SubscriptionMigration).filter(
                    SubscriptionMigration.subscription_id == subscription_id,
                    SubscriptionMigration.status == MigrationStatus.IN_PROGRESS
                ).first()
                
                if migration:
                    migration.status = MigrationStatus.COMPLETED
                    migration.completed_at = datetime.utcnow()
        
        # Check for status change
        if "status" in previous:
            old_values["status"] = previous["status"]
            new_values["status"] = subscription["status"]
            package.status = subscription["status"]
        
        # Check for cancel_at_period_end change
        if "cancel_at_period_end" in previous:
            old_values["cancel_at_period_end"] = previous["cancel_at_period_end"]
            new_values["cancel_at_period_end"] = subscription["cancel_at_period_end"]
        
        # Update period dates
        package.current_period_start = datetime.fromtimestamp(subscription["current_period_start"])
        package.current_period_end = datetime.fromtimestamp(subscription["current_period_end"])
        
        # Log audit if there were changes
        if old_values or new_values:
            self._log_audit(
                db=db,
                subscription_id=subscription_id,
                customer_id=package.customer_id,
                action="updated",
                old_values=old_values,
                new_values=new_values,
                initiated_by_type="webhook",
                reason="Subscription updated via Stripe",
                stripe_event_id=event_data.get("id")
            )
        
        db.commit()
        
        return {
            "subscription_id": subscription_id,
            "action": "updated",
            "changes": new_values
        }
    
    async def handle_subscription_deleted(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle subscription cancellation/deletion"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        
        # Get package
        package = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id
        ).first()
        
        if not package:
            logger.warning(f"Package not found for subscription {subscription_id}")
            return {"warning": "Package not found"}
        
        old_status = package.status
        package.status = "canceled"
        
        # Log audit
        self._log_audit(
            db=db,
            subscription_id=subscription_id,
            customer_id=package.customer_id,
            action="cancelled",
            old_values={"status": old_status},
            new_values={"status": "canceled"},
            initiated_by_type="webhook",
            reason="Subscription cancelled via Stripe"
        )
        
        db.commit()
        
        return {
            "subscription_id": subscription_id,
            "action": "cancelled"
        }
    
    async def handle_subscription_paused(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle subscription pause"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        
        # Update package status
        package = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id
        ).first()
        
        if package:
            old_status = package.status
            package.status = "paused"
            
            self._log_audit(
                db=db,
                subscription_id=subscription_id,
                customer_id=package.customer_id,
                action="paused",
                old_values={"status": old_status},
                new_values={"status": "paused"},
                initiated_by_type="webhook",
                reason="Subscription paused"
            )
            
            db.commit()
        
        return {"subscription_id": subscription_id, "action": "paused"}
    
    async def handle_subscription_resumed(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle subscription resume"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        
        # Update package status
        package = db.query(Package).filter(
            Package.stripe_subscription_id == subscription_id
        ).first()
        
        if package:
            old_status = package.status
            package.status = "active"
            
            self._log_audit(
                db=db,
                subscription_id=subscription_id,
                customer_id=package.customer_id,
                action="resumed",
                old_values={"status": old_status},
                new_values={"status": "active"},
                initiated_by_type="webhook",
                reason="Subscription resumed"
            )
            
            db.commit()
        
        return {"subscription_id": subscription_id, "action": "resumed"}
    
    async def handle_pending_update_applied(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle when a pending subscription update is applied"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        
        # Check for any pending migrations
        migration = db.query(SubscriptionMigration).filter(
            SubscriptionMigration.subscription_id == subscription_id,
            SubscriptionMigration.status == MigrationStatus.PENDING,
            SubscriptionMigration.strategy == "end_of_billing_period"
        ).first()
        
        if migration:
            migration.status = MigrationStatus.COMPLETED
            migration.completed_at = datetime.utcnow()
            db.commit()
        
        return {
            "subscription_id": subscription_id,
            "action": "pending_update_applied"
        }
    
    async def handle_pending_update_expired(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle when a pending subscription update expires"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        
        # Cancel any pending migrations
        migration = db.query(SubscriptionMigration).filter(
            SubscriptionMigration.subscription_id == subscription_id,
            SubscriptionMigration.status == MigrationStatus.PENDING
        ).first()
        
        if migration:
            migration.status = MigrationStatus.CANCELLED
            migration.error_message = "Pending update expired"
            db.commit()
        
        return {
            "subscription_id": subscription_id,
            "action": "pending_update_expired"
        }
    
    async def handle_trial_will_end(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle trial ending notification"""
        subscription = event_data.get("data", {}).get("object", {})
        subscription_id = subscription.get("id")
        trial_end = subscription.get("trial_end")
        
        # Log this event for notification purposes
        self._log_audit(
            db=db,
            subscription_id=subscription_id,
            customer_id=None,
            action="trial_ending",
            old_values={},
            new_values={"trial_end": datetime.fromtimestamp(trial_end).isoformat()},
            initiated_by_type="webhook",
            reason="Trial period ending notification"
        )
        
        db.commit()
        
        return {
            "subscription_id": subscription_id,
            "action": "trial_ending",
            "trial_end": trial_end
        }
    
    async def handle_price_created(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle new price creation"""
        # This would trigger a sync of pricing plans
        from .subscription_service import subscription_management_service
        
        try:
            result = subscription_management_service.sync_pricing_plans(db)
            return {
                "action": "price_created",
                "sync_result": result
            }
        except Exception as e:
            logger.error(f"Error syncing prices: {e}")
            return {
                "action": "price_created",
                "error": str(e)
            }
    
    async def handle_price_updated(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle price update"""
        # Sync pricing plans
        from .subscription_service import subscription_management_service
        
        try:
            result = subscription_management_service.sync_pricing_plans(db)
            return {
                "action": "price_updated",
                "sync_result": result
            }
        except Exception as e:
            logger.error(f"Error syncing prices: {e}")
            return {
                "action": "price_updated",
                "error": str(e)
            }
    
    async def handle_price_deleted(
        self,
        event_data: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        """Handle price deletion"""
        price = event_data.get("data", {}).get("object", {})
        price_id = price.get("id")
        
        # Mark the pricing plan as discontinued
        from .subscription_management import PricingPlan, PricingPlanStatus
        
        plan = db.query(PricingPlan).filter(
            PricingPlan.stripe_price_id == price_id
        ).first()
        
        if plan:
            plan.status = PricingPlanStatus.DISCONTINUED
            plan.discontinued_at = datetime.utcnow()
            db.commit()
        
        return {
            "action": "price_deleted",
            "price_id": price_id
        }
    
    def _log_audit(
        self,
        db: Session,
        subscription_id: str,
        customer_id: Optional[int],
        action: str,
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
        initiated_by_type: str,
        reason: str,
        stripe_event_id: Optional[str] = None
    ):
        """Log audit entry for subscription changes"""
        audit = SubscriptionAuditLog(
            subscription_id=subscription_id,
            customer_id=customer_id or 0,
            action=action,
            old_values=old_values,
            new_values=new_values,
            changes={k: {"old": old_values.get(k), "new": v} 
                    for k, v in new_values.items() if old_values.get(k) != v},
            initiated_by_type=initiated_by_type,
            reason=reason,
            stripe_event_id=stripe_event_id,
            tenant_id="system"  # Webhook events are system-wide
        )
        
        db.add(audit)


# Global instance
subscription_webhook_handler = SubscriptionWebhookHandler()