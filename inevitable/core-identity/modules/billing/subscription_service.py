"""
Subscription Management Service

Handles admin operations for subscription management, migrations, and pricing transitions.
"""
import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from decimal import Decimal
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from .subscription_management import (
    PricingPlan, PricingPlanStatus, SubscriptionMigration, MigrationStatus,
    MigrationStrategy, BulkMigrationJob, SubscriptionAuditLog, PlanTransitionRule
)
from .models import Customer, Package
from .stripe_service import stripe_service
from ..auth.models import User
from pydantic import ValidationError
from fastapi import HTTPException

logger = logging.getLogger(__name__)


class SubscriptionManagementService:
    """Service for managing subscriptions, migrations, and pricing plans"""
    
    def __init__(self):
        self.stripe = stripe_service
    
    # ==================== Pricing Plan Management ====================
    
    def sync_pricing_plans(self, db: Session) -> Dict[str, Any]:
        """Sync pricing plans from Stripe"""
        try:
            # Fetch all prices from Stripe
            prices = self.stripe.stripe.Price.list(active=True, limit=100)
            
            synced_count = 0
            errors = []
            
            for stripe_price in prices.data:
                try:
                    # Get product details
                    product = self.stripe.stripe.Product.retrieve(stripe_price.product)
                    
                    # Check if plan exists
                    plan = db.query(PricingPlan).filter(
                        PricingPlan.stripe_price_id == stripe_price.id
                    ).first()
                    
                    if not plan:
                        plan = PricingPlan(
                            stripe_price_id=stripe_price.id,
                            stripe_product_id=product.id,
                            tenant_id="system"  # System-wide plans
                        )
                    
                    # Update plan details
                    plan.name = product.name
                    plan.description = product.description
                    plan.amount = stripe_price.unit_amount
                    plan.currency = stripe_price.currency
                    plan.interval = stripe_price.recurring.interval if stripe_price.recurring else "one_time"
                    plan.interval_count = stripe_price.recurring.interval_count if stripe_price.recurring else 1
                    plan.plan_metadata = {
                        "stripe_metadata": stripe_price.metadata,
                        "product_metadata": product.metadata
                    }
                    
                    # Extract features from metadata
                    if "features" in product.metadata:
                        plan.features = product.metadata.get("features", {})
                    
                    db.add(plan)
                    synced_count += 1
                    
                except Exception as e:
                    errors.append({
                        "price_id": stripe_price.id,
                        "error": str(e)
                    })
                    logger.error(f"Error syncing price {stripe_price.id}: {e}")
            
            db.commit()
            
            return {
                "synced": synced_count,
                "total": len(prices.data),
                "errors": errors
            }
            
        except Exception as e:
            logger.error(f"Error syncing pricing plans: {e}")
            raise
    
    def update_plan_status(
        self,
        db: Session,
        plan_id: int,
        status: PricingPlanStatus,
        replacement_plan_id: Optional[int] = None,
        migration_strategy: Optional[MigrationStrategy] = None,
        sunset_date: Optional[datetime] = None,
        admin_user_id: int = None
    ) -> PricingPlan:
        """Update pricing plan status"""
        plan = db.query(PricingPlan).filter(PricingPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Pricing plan not found")
        
        old_status = plan.status
        plan.status = status
        
        # Set timestamps based on status
        if status == PricingPlanStatus.DEPRECATED:
            plan.deprecated_at = datetime.utcnow()
        elif status == PricingPlanStatus.DISCONTINUED:
            plan.discontinued_at = datetime.utcnow()
        
        # Set additional fields
        if replacement_plan_id:
            plan.replacement_plan_id = replacement_plan_id
        if migration_strategy:
            plan.migration_strategy = migration_strategy
        if sunset_date:
            plan.sunset_date = sunset_date
        
        db.commit()
        
        # Log the change
        self._log_audit(
            db=db,
            subscription_id=None,
            customer_id=None,
            action="plan_status_changed",
            old_values={"status": old_status},
            new_values={"status": status.value},
            initiated_by=admin_user_id,
            initiated_by_type="admin",
            reason=f"Plan status changed from {old_status} to {status.value}"
        )
        
        return plan
    
    # ==================== Subscription Migration ====================
    
    def create_migration(
        self,
        db: Session,
        subscription_id: str,
        target_plan_id: int,
        strategy: MigrationStrategy,
        admin_user_id: int,
        scheduled_for: Optional[datetime] = None,
        reason: Optional[str] = None,
        preserve_billing_date: bool = True,
        notify_customer: bool = True
    ) -> SubscriptionMigration:
        """Create a single subscription migration"""
        # Get subscription details from Stripe
        subscription = self.stripe.stripe.Subscription.retrieve(subscription_id)
        
        # Get customer
        customer = db.query(Customer).filter(
            Customer.stripe_customer_id == subscription.customer
        ).first()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        # Get current plan
        current_price_id = subscription["items"]["data"][0]["price"]["id"]
        source_plan = db.query(PricingPlan).filter(
            PricingPlan.stripe_price_id == current_price_id
        ).first()
        
        # Get target plan
        target_plan = db.query(PricingPlan).filter(
            PricingPlan.id == target_plan_id
        ).first()
        if not target_plan:
            raise HTTPException(status_code=404, detail="Target plan not found")
        
        # Calculate proration if immediate
        prorated_amount = None
        if strategy == MigrationStrategy.IMMEDIATE:
            # Stripe will calculate proration automatically
            preview = self.stripe.stripe.Invoice.upcoming(
                customer=subscription.customer,
                subscription=subscription_id,
                subscription_items=[{
                    'id': subscription["items"]["data"][0].id,
                    'price': target_plan.stripe_price_id
                }]
            )
            prorated_amount = preview.amount_due
        
        # Create migration record
        migration = SubscriptionMigration(
            subscription_id=subscription_id,
            customer_id=customer.id,
            user_id=customer.user_id if hasattr(customer, 'user_id') else None,
            source_plan_id=source_plan.id if source_plan else None,
            target_plan_id=target_plan.id,
            strategy=strategy,
            status=MigrationStatus.PENDING,
            scheduled_for=scheduled_for or datetime.utcnow(),
            prorated_amount=prorated_amount,
            preserve_billing_date=preserve_billing_date,
            initiated_by=admin_user_id,
            reason=reason,
            tenant_id=customer.tenant_id
        )
        
        db.add(migration)
        db.commit()
        
        # Execute immediately if strategy is IMMEDIATE
        if strategy == MigrationStrategy.IMMEDIATE:
            self.execute_migration(db, migration.id, admin_user_id)
        
        return migration
    
    def execute_migration(
        self,
        db: Session,
        migration_id: int,
        admin_user_id: int
    ) -> SubscriptionMigration:
        """Execute a pending migration"""
        migration = db.query(SubscriptionMigration).filter(
            SubscriptionMigration.id == migration_id
        ).first()
        if not migration:
            raise HTTPException(status_code=404, detail="Migration not found")
        
        if migration.status != MigrationStatus.PENDING:
            raise ValidationError(f"Migration is not pending (status: {migration.status})")
        
        try:
            migration.status = MigrationStatus.IN_PROGRESS
            migration.started_at = datetime.utcnow()
            db.commit()
            
            # Get subscription from Stripe
            subscription = self.stripe.stripe.Subscription.retrieve(migration.subscription_id)
            
            # Prepare update parameters
            update_params = {
                "items": [{
                    "id": subscription["items"]["data"][0].id,
                    "price": migration.target_plan.stripe_price_id
                }]
            }
            
            # Preserve billing date if requested
            if migration.preserve_billing_date:
                update_params["proration_behavior"] = "none"
            else:
                update_params["proration_behavior"] = "create_prorations"
            
            # Update subscription in Stripe
            updated_subscription = self.stripe.stripe.Subscription.modify(
                migration.subscription_id,
                **update_params
            )
            
            # Update local package record
            package = db.query(Package).filter(
                Package.stripe_subscription_id == migration.subscription_id
            ).first()
            if package:
                package.plan_id = migration.target_plan.stripe_price_id
                
            # Mark migration as completed
            migration.status = MigrationStatus.COMPLETED
            migration.completed_at = datetime.utcnow()
            migration.changes_applied = {
                "old_price": subscription["items"]["data"][0]["price"]["id"],
                "new_price": migration.target_plan.stripe_price_id,
                "proration_behavior": update_params.get("proration_behavior")
            }
            
            db.commit()
            
            # Log audit
            self._log_audit(
                db=db,
                subscription_id=migration.subscription_id,
                customer_id=migration.customer_id,
                action="migrated",
                old_values={"plan_id": migration.source_plan.stripe_price_id if migration.source_plan else None},
                new_values={"plan_id": migration.target_plan.stripe_price_id},
                initiated_by=admin_user_id,
                initiated_by_type="admin",
                reason=migration.reason,
                migration_id=migration.id
            )
            
            # Send notification if enabled
            if migration.customer_notified:
                self._send_migration_notification(migration)
            
            return migration
            
        except Exception as e:
            migration.status = MigrationStatus.FAILED
            migration.error_message = str(e)
            db.commit()
            logger.error(f"Migration {migration_id} failed: {e}")
            raise
    
    # ==================== Bulk Migration ====================
    
    def create_bulk_migration(
        self,
        db: Session,
        name: str,
        source_plan_ids: List[int],
        target_plan_id: int,
        strategy: MigrationStrategy,
        admin_user_id: int,
        criteria: Optional[Dict[str, Any]] = None,
        scheduled_for: Optional[datetime] = None,
        dry_run: bool = False,
        notify_customers: bool = True,
        require_approval: bool = False
    ) -> BulkMigrationJob:
        """Create a bulk migration job"""
        # Validate target plan
        target_plan = db.query(PricingPlan).filter(
            PricingPlan.id == target_plan_id
        ).first()
        if not target_plan:
            raise HTTPException(status_code=404, detail="Target plan not found")
        
        # Count affected subscriptions
        affected_count = self._count_affected_subscriptions(
            db, source_plan_ids, criteria
        )
        
        # Create job
        job = BulkMigrationJob(
            job_id=f"bulk_{uuid.uuid4().hex[:8]}",
            name=name,
            source_plan_ids=source_plan_ids,
            target_plan_id=target_plan_id,
            criteria=criteria or {},
            total_subscriptions=affected_count,
            status=MigrationStatus.PENDING,
            strategy=strategy,
            scheduled_for=scheduled_for or datetime.utcnow(),
            dry_run=dry_run,
            notify_customers=notify_customers,
            require_approval=require_approval,
            created_by=admin_user_id,
            tenant_id="system"  # System-wide operation
        )
        
        db.add(job)
        db.commit()
        
        return job
    
    def execute_bulk_migration(
        self,
        db: Session,
        job_id: int,
        admin_user_id: int,
        batch_size: int = 100
    ) -> BulkMigrationJob:
        """Execute a bulk migration job"""
        job = db.query(BulkMigrationJob).filter(
            BulkMigrationJob.id == job_id
        ).first()
        if not job:
            raise HTTPException(status_code=404, detail="Bulk migration job not found")
        
        if job.status != MigrationStatus.PENDING:
            raise ValidationError(f"Job is not pending (status: {job.status})")
        
        if job.require_approval and not job.approved_by:
            raise ValidationError("Job requires approval before execution")
        
        try:
            job.status = MigrationStatus.IN_PROGRESS
            job.started_at = datetime.utcnow()
            job.executed_by = admin_user_id
            db.commit()
            
            # Get affected subscriptions
            subscriptions = self._get_affected_subscriptions(
                db, job.source_plan_ids, job.criteria, batch_size
            )
            
            migration_batch_id = f"batch_{job.job_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            
            for subscription in subscriptions:
                try:
                    # Create individual migration
                    migration = self.create_migration(
                        db=db,
                        subscription_id=subscription.stripe_subscription_id,
                        target_plan_id=job.target_plan_id,
                        strategy=job.strategy,
                        admin_user_id=admin_user_id,
                        reason=f"Bulk migration: {job.name}",
                        notify_customer=job.notify_customers
                    )
                    
                    migration.migration_batch_id = migration_batch_id
                    
                    if not job.dry_run and job.strategy == MigrationStrategy.IMMEDIATE:
                        self.execute_migration(db, migration.id, admin_user_id)
                    
                    job.processed_count += 1
                    job.success_count += 1
                    
                except Exception as e:
                    job.processed_count += 1
                    job.failed_count += 1
                    job.errors.append({
                        "subscription_id": subscription.stripe_subscription_id,
                        "error": str(e)
                    })
                    logger.error(f"Failed to migrate subscription {subscription.stripe_subscription_id}: {e}")
                
                # Commit progress periodically
                if job.processed_count % 10 == 0:
                    db.commit()
            
            # Mark job as completed
            job.status = MigrationStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.summary = {
                "total": job.total_subscriptions,
                "processed": job.processed_count,
                "success": job.success_count,
                "failed": job.failed_count,
                "skipped": job.skipped_count
            }
            
            db.commit()
            
            return job
            
        except Exception as e:
            job.status = MigrationStatus.FAILED
            job.errors.append({"general_error": str(e)})
            db.commit()
            logger.error(f"Bulk migration job {job_id} failed: {e}")
            raise
    
    # ==================== Grandfathering Support ====================
    
    def grandfather_subscriptions(
        self,
        db: Session,
        plan_id: int,
        admin_user_id: int,
        criteria: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Mark subscriptions as grandfathered on a deprecated plan"""
        plan = db.query(PricingPlan).filter(PricingPlan.id == plan_id).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Pricing plan not found")
        
        # Update plan status
        plan.status = PricingPlanStatus.GRANDFATHERED
        
        # Get affected subscriptions
        subscriptions = self._get_subscriptions_on_plan(db, plan.stripe_price_id, criteria)
        
        grandfathered_count = 0
        for subscription in subscriptions:
            # Add metadata to Stripe subscription
            self.stripe.stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                metadata={
                    "grandfathered": "true",
                    "grandfathered_date": datetime.utcnow().isoformat(),
                    "grandfathered_by": str(admin_user_id)
                }
            )
            
            # Log audit
            self._log_audit(
                db=db,
                subscription_id=subscription.stripe_subscription_id,
                customer_id=subscription.customer_id,
                action="grandfathered",
                old_values={},
                new_values={"grandfathered": True},
                initiated_by=admin_user_id,
                initiated_by_type="admin",
                reason=f"Plan {plan.name} grandfathered"
            )
            
            grandfathered_count += 1
        
        db.commit()
        
        return {
            "plan_id": plan_id,
            "plan_name": plan.name,
            "grandfathered_count": grandfathered_count
        }
    
    # ==================== Transition Rules ====================
    
    def create_transition_rule(
        self,
        db: Session,
        name: str,
        source_plan_id: int,
        target_plan_id: int,
        strategy: MigrationStrategy,
        conditions: Optional[Dict[str, Any]] = None,
        effective_date: Optional[datetime] = None,
        auto_approve: bool = False,
        notify_customer: bool = True
    ) -> PlanTransitionRule:
        """Create an automatic plan transition rule"""
        rule = PlanTransitionRule(
            name=name,
            source_plan_id=source_plan_id,
            target_plan_id=target_plan_id,
            strategy=strategy,
            conditions=conditions or {},
            effective_date=effective_date or datetime.utcnow(),
            auto_approve=auto_approve,
            notify_customer=notify_customer,
            tenant_id="system"
        )
        
        db.add(rule)
        db.commit()
        
        return rule
    
    def apply_transition_rules(
        self,
        db: Session,
        admin_user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Apply all active transition rules"""
        # Get active rules
        rules = db.query(PlanTransitionRule).filter(
            PlanTransitionRule.is_active == True,
            PlanTransitionRule.effective_date <= datetime.utcnow(),
            or_(
                PlanTransitionRule.expiration_date.is_(None),
                PlanTransitionRule.expiration_date > datetime.utcnow()
            )
        ).order_by(PlanTransitionRule.priority.desc()).all()
        
        results = {
            "rules_processed": 0,
            "migrations_created": 0,
            "errors": []
        }
        
        for rule in rules:
            try:
                # Get subscriptions matching the rule
                subscriptions = self._get_subscriptions_on_plan(
                    db, rule.source_plan.stripe_price_id, rule.conditions
                )
                
                for subscription in subscriptions:
                    # Check if migration already exists
                    existing = db.query(SubscriptionMigration).filter(
                        SubscriptionMigration.subscription_id == subscription.stripe_subscription_id,
                        SubscriptionMigration.status.in_([
                            MigrationStatus.PENDING,
                            MigrationStatus.IN_PROGRESS
                        ])
                    ).first()
                    
                    if not existing:
                        migration = self.create_migration(
                            db=db,
                            subscription_id=subscription.stripe_subscription_id,
                            target_plan_id=rule.target_plan_id,
                            strategy=rule.strategy,
                            admin_user_id=admin_user_id or 0,  # System user
                            reason=f"Automatic transition rule: {rule.name}",
                            notify_customer=rule.notify_customer
                        )
                        
                        if rule.auto_approve and rule.strategy == MigrationStrategy.IMMEDIATE:
                            self.execute_migration(db, migration.id, admin_user_id or 0)
                        
                        results["migrations_created"] += 1
                
                results["rules_processed"] += 1
                
            except Exception as e:
                results["errors"].append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "error": str(e)
                })
                logger.error(f"Error applying transition rule {rule.id}: {e}")
        
        return results
    
    # ==================== Helper Methods ====================
    
    def _count_affected_subscriptions(
        self,
        db: Session,
        source_plan_ids: List[int],
        criteria: Optional[Dict[str, Any]] = None
    ) -> int:
        """Count subscriptions that would be affected by a migration"""
        # Get Stripe price IDs for the plans
        plans = db.query(PricingPlan).filter(
            PricingPlan.id.in_(source_plan_ids)
        ).all()
        stripe_price_ids = [plan.stripe_price_id for plan in plans]
        
        # Query packages
        query = db.query(Package).filter(
            Package.plan_id.in_(stripe_price_ids),
            Package.status == "active"
        )
        
        # Apply additional criteria if provided
        if criteria:
            # Example criteria: {"created_before": "2024-01-01"}
            pass
        
        return query.count()
    
    def _get_affected_subscriptions(
        self,
        db: Session,
        source_plan_ids: List[int],
        criteria: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> List[Package]:
        """Get subscriptions that would be affected by a migration"""
        plans = db.query(PricingPlan).filter(
            PricingPlan.id.in_(source_plan_ids)
        ).all()
        stripe_price_ids = [plan.stripe_price_id for plan in plans]
        
        query = db.query(Package).filter(
            Package.plan_id.in_(stripe_price_ids),
            Package.status == "active"
        )
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def _get_subscriptions_on_plan(
        self,
        db: Session,
        stripe_price_id: str,
        criteria: Optional[Dict[str, Any]] = None
    ) -> List[Package]:
        """Get all subscriptions on a specific plan"""
        query = db.query(Package).filter(
            Package.plan_id == stripe_price_id,
            Package.status == "active"
        )
        
        return query.all()
    
    def _log_audit(
        self,
        db: Session,
        subscription_id: Optional[str],
        customer_id: Optional[int],
        action: str,
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
        initiated_by: Optional[int],
        initiated_by_type: str,
        reason: Optional[str] = None,
        migration_id: Optional[int] = None,
        bulk_job_id: Optional[int] = None
    ):
        """Log subscription change to audit trail"""
        audit = SubscriptionAuditLog(
            subscription_id=subscription_id or "N/A",
            customer_id=customer_id or 0,
            action=action,
            old_values=old_values,
            new_values=new_values,
            changes={k: {"old": old_values.get(k), "new": v} 
                    for k, v in new_values.items() if old_values.get(k) != v},
            initiated_by=initiated_by,
            initiated_by_type=initiated_by_type,
            reason=reason,
            migration_id=migration_id,
            bulk_job_id=bulk_job_id,
            tenant_id="system"
        )
        
        db.add(audit)
        db.commit()
    
    def _send_migration_notification(self, migration: SubscriptionMigration):
        """Send notification to customer about migration"""
        # This would integrate with the email service
        # For now, just log it
        logger.info(f"Would send migration notification for subscription {migration.subscription_id}")


# Global service instance
subscription_management_service = SubscriptionManagementService()