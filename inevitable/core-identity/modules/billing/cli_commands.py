"""
CLI Commands for Subscription Management

Provides command-line tools for managing subscriptions and pricing plans.
"""
import click
import asyncio
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typing import Optional

from .subscription_management import (
    PricingPlanStatus, MigrationStrategy, MigrationStatus
)
from .subscription_service import subscription_management_service
from ..core.config import settings

# Create database session
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@click.group()
def billing():
    """Billing management commands"""
    pass


@billing.command()
@click.option('--dry-run', is_flag=True, help='Preview changes without executing')
def sync_pricing_plans(dry_run: bool):
    """Sync pricing plans from Stripe"""
    db = SessionLocal()
    try:
        if dry_run:
            click.echo("🔍 Dry run mode - no changes will be made")
        
        click.echo("📥 Syncing pricing plans from Stripe...")
        result = subscription_management_service.sync_pricing_plans(db)
        
        click.echo(f"✅ Synced {result['synced']} of {result['total']} plans")
        
        if result['errors']:
            click.echo(f"⚠️  {len(result['errors'])} errors occurred:")
            for error in result['errors'][:5]:  # Show first 5 errors
                click.echo(f"  - {error['price_id']}: {error['error']}")
    
    finally:
        db.close()


@billing.command()
@click.argument('plan_id', type=int)
@click.option('--status', type=click.Choice(['deprecated', 'sunset', 'discontinued']), required=True)
@click.option('--replacement-plan-id', type=int, help='ID of replacement plan')
@click.option('--migration-strategy', 
              type=click.Choice(['immediate', 'end_of_billing_period', 'manual', 'grandfathered']),
              default='end_of_billing_period')
@click.option('--sunset-days', type=int, default=30, help='Days until sunset (default: 30)')
@click.option('--admin-user-id', type=int, default=1, help='Admin user ID for audit')
def deprecate_plan(
    plan_id: int,
    status: str,
    replacement_plan_id: Optional[int],
    migration_strategy: str,
    sunset_days: int,
    admin_user_id: int
):
    """Deprecate a pricing plan"""
    db = SessionLocal()
    try:
        # Map string to enum
        status_enum = PricingPlanStatus(status)
        strategy_enum = MigrationStrategy(migration_strategy) if migration_strategy else None
        
        # Calculate sunset date
        sunset_date = None
        if status == 'sunset':
            sunset_date = datetime.utcnow() + timedelta(days=sunset_days)
        
        click.echo(f"🔄 Updating plan {plan_id} to status: {status}")
        
        plan = subscription_management_service.update_plan_status(
            db=db,
            plan_id=plan_id,
            status=status_enum,
            replacement_plan_id=replacement_plan_id,
            migration_strategy=strategy_enum,
            sunset_date=sunset_date,
            admin_user_id=admin_user_id
        )
        
        click.echo(f"✅ Plan '{plan.name}' updated successfully")
        click.echo(f"   Status: {plan.status}")
        if plan.replacement_plan_id:
            click.echo(f"   Replacement Plan ID: {plan.replacement_plan_id}")
        if plan.sunset_date:
            click.echo(f"   Sunset Date: {plan.sunset_date.strftime('%Y-%m-%d')}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
@click.argument('name')
@click.option('--source-plan-ids', multiple=True, type=int, required=True, help='Source plan IDs')
@click.option('--target-plan-id', type=int, required=True, help='Target plan ID')
@click.option('--strategy', 
              type=click.Choice(['immediate', 'end_of_billing_period', 'manual']),
              default='end_of_billing_period')
@click.option('--dry-run', is_flag=True, help='Preview migration without executing')
@click.option('--notify-customers/--no-notify', default=True, help='Send notifications')
@click.option('--require-approval/--auto-approve', default=True, help='Require approval')
@click.option('--admin-user-id', type=int, default=1, help='Admin user ID')
def create_bulk_migration(
    name: str,
    source_plan_ids: tuple,
    target_plan_id: int,
    strategy: str,
    dry_run: bool,
    notify_customers: bool,
    require_approval: bool,
    admin_user_id: int
):
    """Create a bulk subscription migration"""
    db = SessionLocal()
    try:
        strategy_enum = MigrationStrategy(strategy)
        
        click.echo(f"📋 Creating bulk migration: {name}")
        click.echo(f"   Source Plans: {list(source_plan_ids)}")
        click.echo(f"   Target Plan: {target_plan_id}")
        click.echo(f"   Strategy: {strategy}")
        click.echo(f"   Dry Run: {'Yes' if dry_run else 'No'}")
        
        job = subscription_management_service.create_bulk_migration(
            db=db,
            name=name,
            source_plan_ids=list(source_plan_ids),
            target_plan_id=target_plan_id,
            strategy=strategy_enum,
            admin_user_id=admin_user_id,
            dry_run=dry_run,
            notify_customers=notify_customers,
            require_approval=require_approval
        )
        
        click.echo(f"✅ Bulk migration job created")
        click.echo(f"   Job ID: {job.job_id}")
        click.echo(f"   Affected Subscriptions: {job.total_subscriptions}")
        click.echo(f"   Status: {job.status}")
        
        if require_approval:
            click.echo(f"⚠️  This job requires approval before execution")
            click.echo(f"   Run: billing approve-migration {job.id}")
        elif not dry_run:
            click.echo(f"🚀 Migration will execute automatically")
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
@click.argument('job_id', type=int)
@click.option('--admin-user-id', type=int, default=1, help='Admin user ID')
def approve_migration(job_id: int, admin_user_id: int):
    """Approve and execute a bulk migration"""
    db = SessionLocal()
    try:
        from .subscription_management import BulkMigrationJob
        
        job = db.query(BulkMigrationJob).filter(
            BulkMigrationJob.id == job_id
        ).first()
        
        if not job:
            click.echo(f"❌ Job {job_id} not found", err=True)
            return
        
        if not job.require_approval:
            click.echo(f"ℹ️  Job does not require approval")
        elif job.approved_by:
            click.echo(f"ℹ️  Job already approved by user {job.approved_by}")
        else:
            job.approved_by = admin_user_id
            db.commit()
            click.echo(f"✅ Job approved")
        
        # Execute if ready
        if job.scheduled_for <= datetime.utcnow() and job.status == MigrationStatus.PENDING:
            click.echo(f"🚀 Executing migration...")
            result = subscription_management_service.execute_bulk_migration(
                db=db,
                job_id=job_id,
                admin_user_id=admin_user_id
            )
            
            click.echo(f"✅ Migration completed")
            click.echo(f"   Processed: {result.processed_count}")
            click.echo(f"   Successful: {result.success_count}")
            click.echo(f"   Failed: {result.failed_count}")
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
@click.argument('plan_id', type=int)
@click.option('--admin-user-id', type=int, default=1, help='Admin user ID')
def grandfather_plan(plan_id: int, admin_user_id: int):
    """Grandfather all subscriptions on a deprecated plan"""
    db = SessionLocal()
    try:
        click.echo(f"👴 Grandfathering subscriptions on plan {plan_id}...")
        
        result = subscription_management_service.grandfather_subscriptions(
            db=db,
            plan_id=plan_id,
            admin_user_id=admin_user_id
        )
        
        click.echo(f"✅ Grandfathered {result['grandfathered_count']} subscriptions")
        click.echo(f"   Plan: {result['plan_name']}")
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
@click.option('--apply', is_flag=True, help='Apply rules (default is preview only)')
@click.option('--admin-user-id', type=int, default=1, help='Admin user ID')
def apply_transition_rules(apply: bool, admin_user_id: int):
    """Apply automatic plan transition rules"""
    db = SessionLocal()
    try:
        if not apply:
            click.echo("🔍 Preview mode - use --apply to execute")
        
        click.echo("📋 Applying transition rules...")
        
        result = subscription_management_service.apply_transition_rules(
            db=db,
            admin_user_id=admin_user_id if apply else None
        )
        
        click.echo(f"✅ Processed {result['rules_processed']} rules")
        click.echo(f"   Migrations Created: {result['migrations_created']}")
        
        if result['errors']:
            click.echo(f"⚠️  {len(result['errors'])} errors occurred:")
            for error in result['errors'][:5]:
                click.echo(f"  - Rule {error['rule_id']} ({error['rule_name']}): {error['error']}")
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
@click.option('--status', type=click.Choice(['pending', 'in_progress', 'completed', 'failed']))
@click.option('--limit', type=int, default=10, help='Number of migrations to show')
def list_migrations(status: Optional[str], limit: int):
    """List recent subscription migrations"""
    db = SessionLocal()
    try:
        from .subscription_management import SubscriptionMigration
        
        query = db.query(SubscriptionMigration)
        
        if status:
            status_enum = MigrationStatus(status)
            query = query.filter(SubscriptionMigration.status == status_enum)
        
        migrations = query.order_by(
            SubscriptionMigration.created_at.desc()
        ).limit(limit).all()
        
        if not migrations:
            click.echo("No migrations found")
            return
        
        click.echo(f"📋 Recent migrations (showing {len(migrations)}):")
        click.echo("-" * 80)
        
        for m in migrations:
            click.echo(f"ID: {m.id} | Subscription: {m.subscription_id}")
            click.echo(f"   Status: {m.status}")
            click.echo(f"   Strategy: {m.strategy}")
            if m.source_plan:
                click.echo(f"   From: {m.source_plan.name}")
            if m.target_plan:
                click.echo(f"   To: {m.target_plan.name}")
            click.echo(f"   Created: {m.created_at.strftime('%Y-%m-%d %H:%M')}")
            if m.completed_at:
                click.echo(f"   Completed: {m.completed_at.strftime('%Y-%m-%d %H:%M')}")
            if m.error_message:
                click.echo(f"   ❌ Error: {m.error_message}")
            click.echo("-" * 80)
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


@billing.command()
def migration_stats():
    """Show migration statistics"""
    db = SessionLocal()
    try:
        from .subscription_management import SubscriptionMigration, BulkMigrationJob
        from sqlalchemy import func
        
        # Get migration counts by status
        status_counts = db.query(
            SubscriptionMigration.status,
            func.count(SubscriptionMigration.id)
        ).group_by(SubscriptionMigration.status).all()
        
        # Get bulk job counts
        job_counts = db.query(
            BulkMigrationJob.status,
            func.count(BulkMigrationJob.id)
        ).group_by(BulkMigrationJob.status).all()
        
        click.echo("📊 Migration Statistics")
        click.echo("=" * 40)
        
        click.echo("\n📋 Individual Migrations:")
        for status, count in status_counts:
            click.echo(f"   {status}: {count}")
        
        click.echo("\n📦 Bulk Migration Jobs:")
        for status, count in job_counts:
            click.echo(f"   {status}: {count}")
        
        # Get total subscriptions migrated
        total_migrated = db.query(SubscriptionMigration).filter(
            SubscriptionMigration.status == MigrationStatus.COMPLETED
        ).count()
        
        click.echo(f"\n✅ Total Successful Migrations: {total_migrated}")
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
    finally:
        db.close()


if __name__ == '__main__':
    billing()