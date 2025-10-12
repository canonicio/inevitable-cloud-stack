"""
Webhook deduplication service
Addresses HIGH-007: Webhook Replay Attacks
"""
import time
import json
import hashlib
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Integer, Text, Index
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import logging

from ..core.database import Base, get_db
from ..core.config import settings

logger = logging.getLogger(__name__)


class ProcessedWebhook(Base):
    """Track processed webhooks to prevent replay attacks"""
    __tablename__ = "processed_webhooks"
    
    # Use webhook ID as primary key
    webhook_id = Column(String(255), primary_key=True)
    
    # Additional metadata
    event_type = Column(String(100), nullable=False)
    processed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    payload_hash = Column(String(64), nullable=False)  # SHA256 hash of payload
    source = Column(String(50), nullable=False, default="stripe")
    
    # For debugging/auditing
    status = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)
    
    # Indexes for cleanup and querying
    __table_args__ = (
        Index('idx_processed_at', 'processed_at'),
        Index('idx_payload_hash', 'payload_hash'),
    )


class WebhookDeduplicationService:
    """
    Persistent webhook deduplication service
    - Prevents replay attacks
    - Handles idempotency
    - Automatic cleanup of old entries
    """
    
    def __init__(self, retention_days: int = 30):
        self.retention_days = retention_days
        self._cleanup_interval = 3600  # Run cleanup every hour
        self._last_cleanup = 0
    
    def compute_payload_hash(self, payload: bytes) -> str:
        """Compute SHA256 hash of webhook payload"""
        return hashlib.sha256(payload).hexdigest()
    
    def check_and_record_webhook(
        self,
        webhook_id: str,
        event_type: str,
        payload: bytes,
        db: Session,
        source: str = "stripe"
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if webhook has been processed and record it
        Returns: (is_duplicate, existing_status)
        """
        # Compute payload hash
        payload_hash = self.compute_payload_hash(payload)
        
        # Check if already processed
        existing = db.query(ProcessedWebhook).filter(
            ProcessedWebhook.webhook_id == webhook_id
        ).first()
        
        if existing:
            logger.info(
                f"Duplicate webhook detected: {webhook_id} "
                f"(originally processed at {existing.processed_at})"
            )
            return True, existing.status
        
        # Also check by payload hash (in case webhook ID changes)
        hash_match = db.query(ProcessedWebhook).filter(
            ProcessedWebhook.payload_hash == payload_hash,
            ProcessedWebhook.processed_at > datetime.utcnow() - timedelta(minutes=5)
        ).first()
        
        if hash_match:
            logger.warning(
                f"Potential replay attack: Same payload as webhook {hash_match.webhook_id} "
                f"but different ID: {webhook_id}"
            )
            return True, hash_match.status
        
        # Record new webhook as processing
        try:
            processed_webhook = ProcessedWebhook(
                webhook_id=webhook_id,
                event_type=event_type,
                payload_hash=payload_hash,
                source=source,
                status="processing",
                processed_at=datetime.utcnow()
            )
            db.add(processed_webhook)
            db.commit()
            
            # Run cleanup if needed
            self._maybe_cleanup(db)
            
            return False, None
            
        except IntegrityError:
            # Race condition - another process recorded it first
            db.rollback()
            existing = db.query(ProcessedWebhook).filter(
                ProcessedWebhook.webhook_id == webhook_id
            ).first()
            return True, existing.status if existing else "processing"
    
    def update_webhook_status(
        self,
        webhook_id: str,
        status: str,
        details: Optional[Dict[str, Any]],
        db: Session
    ):
        """Update the status of a processed webhook"""
        webhook = db.query(ProcessedWebhook).filter(
            ProcessedWebhook.webhook_id == webhook_id
        ).first()
        
        if webhook:
            webhook.status = status
            if details:
                webhook.details = json.dumps(details)
            db.commit()
        else:
            logger.error(f"Webhook {webhook_id} not found for status update")
    
    def _maybe_cleanup(self, db: Session):
        """Run cleanup if enough time has passed"""
        current_time = time.time()
        
        if current_time - self._last_cleanup > self._cleanup_interval:
            self._last_cleanup = current_time
            self.cleanup_old_webhooks(db)
    
    def cleanup_old_webhooks(self, db: Session):
        """Remove old webhook records beyond retention period"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
            
            deleted_count = db.query(ProcessedWebhook).filter(
                ProcessedWebhook.processed_at < cutoff_date
            ).delete()
            
            db.commit()
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old webhook records")
                
        except Exception as e:
            logger.error(f"Error cleaning up webhooks: {e}")
            db.rollback()
    
    def get_webhook_history(
        self,
        webhook_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        db: Session = None
    ) -> list:
        """Get webhook processing history for debugging"""
        query = db.query(ProcessedWebhook)
        
        if webhook_id:
            query = query.filter(ProcessedWebhook.webhook_id == webhook_id)
        
        if event_type:
            query = query.filter(ProcessedWebhook.event_type == event_type)
        
        return query.order_by(
            ProcessedWebhook.processed_at.desc()
        ).limit(limit).all()


# Global instance
_dedup_service = None


def get_dedup_service() -> WebhookDeduplicationService:
    """Get global deduplication service instance"""
    global _dedup_service
    if _dedup_service is None:
        retention_days = int(settings.WEBHOOK_RETENTION_DAYS) if hasattr(settings, 'WEBHOOK_RETENTION_DAYS') else 30
        _dedup_service = WebhookDeduplicationService(retention_days)
    return _dedup_service