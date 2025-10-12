from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Numeric, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from modules.core.database import Base, TimestampMixin, TenantMixin


class Customer(Base, TimestampMixin, TenantMixin):
    __tablename__ = "customers"
    
    id = Column(Integer, primary_key=True)
    stripe_customer_id = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), nullable=False)
    name = Column(String(255))
    
    # Relationships
    packages = relationship("Package", back_populates="customer")
    adapter_access = relationship("CustomerAdapterAccess", back_populates="customer")


class Package(Base, TimestampMixin, TenantMixin):
    __tablename__ = "packages"
    
    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    stripe_subscription_id = Column(String(255), unique=True, nullable=True)
    plan_id = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)  # active, canceled, etc.
    current_period_start = Column(DateTime(timezone=True))
    current_period_end = Column(DateTime(timezone=True))
    
    # Relationships
    customer = relationship("Customer", back_populates="packages")


class Adapter(Base, TimestampMixin, TenantMixin):
    __tablename__ = "adapters"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(100), nullable=False)
    config = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    customer_access = relationship("CustomerAdapterAccess", back_populates="adapter")


class CustomerAdapterAccess(Base, TimestampMixin, TenantMixin):
    __tablename__ = "customer_adapter_access"
    
    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    adapter_id = Column(Integer, ForeignKey("adapters.id"), nullable=False)
    access_level = Column(String(50), nullable=False)  # read, write, admin
    
    # Relationships
    customer = relationship("Customer", back_populates="adapter_access")
    adapter = relationship("Adapter", back_populates="customer_access")


class Subscription(Base, TimestampMixin, TenantMixin):
    """Subscription model for billing management"""
    __tablename__ = "subscriptions"
    
    id = Column(String(255), primary_key=True)  # Use string ID for Stripe compatibility
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    stripe_subscription_id = Column(String(255), unique=True, nullable=False, index=True)
    status = Column(String(50), nullable=False)  # active, canceled, incomplete, etc.
    plan_name = Column(String(255), nullable=False)
    plan_id = Column(String(255), nullable=False)
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String(3), nullable=False, default='usd')
    interval = Column(String(20), nullable=False)  # month, year
    trial_end = Column(DateTime(timezone=True), nullable=True)
    current_period_start = Column(DateTime(timezone=True), nullable=False)
    current_period_end = Column(DateTime(timezone=True), nullable=False)
    canceled_at = Column(DateTime(timezone=True), nullable=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    customer = relationship("Customer")
    invoices = relationship("Invoice", back_populates="subscription")
    

class Invoice(Base, TimestampMixin, TenantMixin):
    """Invoice model for billing management"""
    __tablename__ = "invoices"
    
    id = Column(String(255), primary_key=True)  # Use string ID for Stripe compatibility
    subscription_id = Column(String(255), ForeignKey("subscriptions.id"), nullable=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    stripe_invoice_id = Column(String(255), unique=True, nullable=False, index=True)
    stripe_payment_intent_id = Column(String(255), nullable=True, index=True)
    amount_cents = Column(Integer, nullable=False)
    amount_paid_cents = Column(Integer, nullable=False, default=0)
    amount_due_cents = Column(Integer, nullable=False)
    refunded_amount_cents = Column(Integer, nullable=False, default=0)
    currency = Column(String(3), nullable=False, default='usd')
    status = Column(String(50), nullable=False)  # draft, open, paid, uncollectible, void, refunded, partially_refunded
    description = Column(Text, nullable=True)
    invoice_pdf = Column(String(1024), nullable=True)  # URL to Stripe-hosted PDF
    due_date = Column(DateTime(timezone=True), nullable=True)
    paid_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    subscription = relationship("Subscription", back_populates="invoices")
    customer = relationship("Customer")
    refunds = relationship("Refund", back_populates="invoice")


class Refund(Base, TimestampMixin, TenantMixin):
    """Refund model for comprehensive refund management"""
    __tablename__ = "refunds"
    
    id = Column(String(255), primary_key=True)
    invoice_id = Column(String(255), ForeignKey("invoices.id"), nullable=False, index=True)
    user_id = Column(String(255), nullable=False)  # User who requested the refund
    stripe_refund_id = Column(String(255), unique=True, nullable=True, index=True)
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String(3), nullable=False, default='usd')
    status = Column(String(50), nullable=False)  # pending, approved, rejected, processed, failed, cancelled
    reason = Column(String(100), nullable=False)  # customer_request, billing_error, service_issue, etc.
    customer_note = Column(Text, nullable=True)
    internal_note = Column(Text, nullable=True)
    
    # Fraud prevention
    fraud_score = Column(Numeric(3, 2), nullable=False, default=0.0)
    requires_approval = Column(Boolean, nullable=False, default=False)
    
    # Approval workflow
    approved_by = Column(String(255), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approval_note = Column(Text, nullable=True)
    rejected_by = Column(String(255), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    
    # Processing
    requested_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    failure_reason = Column(Text, nullable=True)
    
    # Relationships
    invoice = relationship("Invoice", back_populates="refunds")
