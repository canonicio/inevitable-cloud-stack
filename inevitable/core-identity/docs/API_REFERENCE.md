# Platform Forge API Reference

## Overview

This document provides comprehensive API documentation for all Platform Forge modules. All APIs follow RESTful principles and return JSON responses.

## Base URL

```
https://api.your-domain.com/api/v1
```

## Authentication

All API endpoints (except authentication endpoints) require JWT authentication.

### Headers

```http
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

### JWT Token Structure

```json
{
  "sub": "user_id",
  "tenant_id": "tenant_id",
  "roles": ["user", "admin"],
  "exp": 1234567890
}
```

## Common Response Formats

### Success Response

```json
{
  "status": "success",
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2024-01-20T10:00:00Z",
    "version": "1.0"
  }
}
```

### Error Response

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      // Additional error details
    }
  },
  "meta": {
    "timestamp": "2024-01-20T10:00:00Z",
    "request_id": "req_123456"
  }
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `TENANT_MISMATCH` | 403 | Cross-tenant access attempt |

## Rate Limiting

All endpoints are rate-limited per tenant:

- **Default**: 1000 requests per hour
- **Auth endpoints**: 20 requests per minute
- **Admin endpoints**: 100 requests per hour

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

---

## Authentication Module

### Register User

```http
POST /auth/register
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe",
  "tenant_id": "tenant_123"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "name": "John Doe",
      "tenant_id": "tenant_123",
      "created_at": "2024-01-20T10:00:00Z"
    },
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
}
```

### Login

```http
POST /auth/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "mfa_code": "123456"  // Optional, if MFA enabled
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "roles": ["user"]
    }
  }
}
```

### Refresh Token

```http
POST /auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "eyJ..."
}
```

### Enable MFA

```http
POST /auth/mfa/enable
```

**Request Body:**
```json
{
  "method": "totp",  // "totp", "email", or "sms"
  "phone": "+1234567890"  // Required for SMS
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",  // For TOTP
    "qr_code": "data:image/png;base64,...",  // QR code for TOTP
    "backup_codes": [
      "A1B2C3D4",
      "E5F6G7H8"
    ]
  }
}
```

### Verify MFA

```http
POST /auth/mfa/verify
```

**Request Body:**
```json
{
  "code": "123456",
  "method": "totp"
}
```

---

## Admin Module

### Get Audit Logs

```http
GET /admin/audit-logs
```

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `limit` (int): Items per page (default: 20, max: 100)
- `user_id` (string): Filter by user
- `action` (string): Filter by action type
- `start_date` (ISO 8601): Filter start date
- `end_date` (ISO 8601): Filter end date

**Response:**
```json
{
  "status": "success",
  "data": {
    "logs": [
      {
        "id": "log_123",
        "user_id": "user_123",
        "action": "user.login",
        "resource": "auth",
        "details": {
          "ip": "192.168.1.1",
          "user_agent": "Mozilla/5.0..."
        },
        "timestamp": "2024-01-20T10:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 150,
      "pages": 8
    }
  }
}
```

### User Management

```http
GET /admin/users
PUT /admin/users/{user_id}
DELETE /admin/users/{user_id}
POST /admin/users/{user_id}/suspend
POST /admin/users/{user_id}/activate
```

### System Configuration

```http
GET /admin/config
PUT /admin/config
```

**Request Body for PUT:**
```json
{
  "settings": {
    "maintenance_mode": false,
    "registration_enabled": true,
    "mfa_required": true,
    "session_timeout": 3600
  }
}
```

---

## Billing Module

### Create Customer

```http
POST /billing/customers
```

**Request Body:**
```json
{
  "email": "customer@example.com",
  "name": "John Doe",
  "payment_method": "pm_1234567890"
}
```

### Create Subscription

```http
POST /billing/subscriptions
```

**Request Body:**
```json
{
  "customer_id": "cus_123",
  "price_id": "price_123",
  "trial_days": 14,
  "metadata": {
    "tenant_id": "tenant_123"
  }
}
```

### Update Subscription

```http
PUT /billing/subscriptions/{subscription_id}
```

**Request Body:**
```json
{
  "price_id": "price_456",
  "quantity": 5,
  "proration_behavior": "create_prorations"
}
```

### Cancel Subscription

```http
DELETE /billing/subscriptions/{subscription_id}
```

**Query Parameters:**
- `at_period_end` (boolean): Cancel at end of billing period

### List Invoices

```http
GET /billing/invoices
```

**Query Parameters:**
- `customer_id` (string): Filter by customer
- `status` (string): Filter by status (draft, open, paid, void)
- `limit` (int): Number of results

### Stripe Webhooks

```http
POST /billing/webhooks/stripe
```

**Headers Required:**
```http
Stripe-Signature: t=1234567890,v1=...
```

**Webhook Events Handled:**
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`
- `payment_method.attached`
- `payment_method.detached`

---

## Telemetry Module

### Track Event

```http
POST /telemetry/events
```

**Request Body:**
```json
{
  "event_name": "user_action",
  "properties": {
    "action": "click_button",
    "button_id": "submit",
    "page": "/dashboard"
  },
  "context": {
    "ip": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  },
  "timestamp": "2024-01-20T10:00:00Z"
}
```

### Batch Track Events

```http
POST /telemetry/events/batch
```

**Request Body:**
```json
{
  "events": [
    {
      "event_name": "page_view",
      "properties": {"page": "/home"},
      "timestamp": "2024-01-20T10:00:00Z"
    },
    {
      "event_name": "button_click",
      "properties": {"button": "signup"},
      "timestamp": "2024-01-20T10:00:01Z"
    }
  ]
}
```

### Query Metrics

```http
GET /telemetry/metrics
```

**Query Parameters:**
- `metric_names` (array): Metrics to retrieve
- `start_time` (ISO 8601): Start of time range
- `end_time` (ISO 8601): End of time range
- `aggregation` (string): sum, avg, min, max, count
- `group_by` (string): Field to group by
- `interval` (string): Time interval (1m, 5m, 1h, 1d)

### Export Data

```http
GET /telemetry/export
```

**Query Parameters:**
- `format` (string): csv, json, parquet
- `start_date` (ISO 8601): Export start date
- `end_date` (ISO 8601): Export end date

---

## Privacy Module

### Get Consent Status

```http
GET /privacy/consent/status
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "consents": {
      "analytics": true,
      "marketing": false,
      "necessary": true,
      "preferences": true
    },
    "updated_at": "2024-01-20T10:00:00Z"
  }
}
```

### Update Consent

```http
POST /privacy/consent/update
```

**Request Body:**
```json
{
  "consents": {
    "analytics": true,
    "marketing": false
  },
  "consent_version": "2.0"
}
```

### Request Data Export

```http
POST /privacy/data-requests/export
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "request_id": "req_123",
    "status": "processing",
    "estimated_completion": "2024-01-21T10:00:00Z"
  }
}
```

### Request Data Deletion

```http
POST /privacy/data-requests/delete
```

**Request Body:**
```json
{
  "reason": "User request",
  "confirm": true
}
```

---

## Whitelabel Module

### Create Brand

```http
POST /whitelabel/brands
```

**Request Body:**
```json
{
  "name": "Acme Corp",
  "config": {
    "primary_color": "#1976d2",
    "secondary_color": "#dc004e",
    "logo_url": "https://cdn.example.com/logo.png",
    "fonts": {
      "primary": "Inter",
      "secondary": "Roboto"
    }
  }
}
```

### Upload Asset

```http
POST /whitelabel/assets/upload
```

**Request Type:** `multipart/form-data`

**Form Fields:**
- `file`: Asset file
- `type`: Asset type (logo, favicon, banner)
- `tenant_id`: Tenant identifier

### Add Custom Domain

```http
POST /whitelabel/domains
```

**Request Body:**
```json
{
  "domain": "app.example.com",
  "ssl_enabled": true,
  "auto_provision_ssl": true
}
```

### Verify Domain

```http
POST /whitelabel/domains/{domain}/verify
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "verified": false,
    "dns_records": [
      {
        "type": "TXT",
        "name": "_platformforge",
        "value": "verify=abc123..."
      }
    ]
  }
}
```

---

## Security Advanced Module

### Register Service (mTLS)

```http
POST /security/mesh/services/register
```

**Request Body:**
```json
{
  "name": "payment-service",
  "endpoints": ["https://payment.internal:8443"],
  "policies": {
    "require_mtls": true,
    "allowed_callers": ["api-gateway"],
    "rate_limit": 1000
  }
}
```

### Issue Certificate

```http
POST /security/mtls/certificates
```

**Request Body:**
```json
{
  "service_name": "api-service",
  "common_name": "api.internal",
  "san": ["api.internal", "api-service.svc"],
  "validity_days": 365
}
```

### List Threats

```http
GET /security/threats
```

**Query Parameters:**
- `severity` (string): critical, high, medium, low
- `status` (string): active, mitigated, false_positive
- `start_date` (ISO 8601): Filter start date

### Trigger Security Scan

```http
POST /security/scans
```

**Request Body:**
```json
{
  "scan_types": ["dependencies", "containers", "secrets", "code"],
  "targets": ["/app", "/config"],
  "deep_scan": true
}
```

---

## Enterprise SSO Module

### SAML Configuration

```http
POST /sso/saml/configure
```

**Request Body:**
```json
{
  "idp_metadata_url": "https://idp.example.com/metadata",
  "sp_entity_id": "https://app.example.com",
  "attribute_mapping": {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
  }
}
```

### OIDC Configuration

```http
POST /sso/oidc/configure
```

**Request Body:**
```json
{
  "issuer": "https://accounts.google.com",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "redirect_uri": "https://app.example.com/auth/oidc/callback"
}
```

### SSO Login

```http
GET /sso/login/{provider}
```

**Query Parameters:**
- `redirect_uri` (string): Post-login redirect
- `state` (string): CSRF protection state

---

## Performance Module

### Get Performance Metrics

```http
GET /performance/metrics
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "api_response_time": {
      "p50": 45,
      "p95": 120,
      "p99": 250
    },
    "database_queries": {
      "avg_duration": 5.2,
      "slow_queries": 3
    },
    "cache_hit_rate": 0.92,
    "active_connections": 152
  }
}
```

### Configure Caching

```http
PUT /performance/cache/config
```

**Request Body:**
```json
{
  "strategies": {
    "api_responses": {
      "enabled": true,
      "ttl": 300,
      "invalidation": "tag-based"
    },
    "database_queries": {
      "enabled": true,
      "ttl": 60
    }
  }
}
```

---

## Marketplace Module

### List Extensions

```http
GET /marketplace/extensions
```

**Query Parameters:**
- `category` (string): Category filter
- `search` (string): Search query
- `sort` (string): popular, newest, rating

### Install Extension

```http
POST /marketplace/extensions/{extension_id}/install
```

**Request Body:**
```json
{
  "version": "1.2.3",
  "configuration": {
    "api_key": "ext_key_123"
  }
}
```

### Publish Extension

```http
POST /marketplace/extensions/publish
```

**Request Body:**
```json
{
  "name": "My Extension",
  "version": "1.0.0",
  "description": "Extension description",
  "category": "analytics",
  "manifest": {
    // Extension manifest
  }
}
```

---

## Edge Deployment Module

### Register Device

```http
POST /edge/devices/register
```

**Request Body:**
```json
{
  "device_id": "edge_device_123",
  "capabilities": ["compute", "storage"],
  "location": {
    "latitude": 37.7749,
    "longitude": -122.4194
  }
}
```

### Deploy to Edge

```http
POST /edge/deployments
```

**Request Body:**
```json
{
  "application": "edge-analytics",
  "version": "1.0.0",
  "targets": ["device_123", "device_456"],
  "configuration": {
    "sync_interval": 300,
    "offline_mode": true
  }
}
```

### OTA Update

```http
POST /edge/devices/{device_id}/update
```

**Request Body:**
```json
{
  "firmware_version": "2.1.0",
  "force_update": false,
  "rollback_on_failure": true
}
```

---

## Webhooks

Platform Forge can send webhooks for various events. Configure webhook endpoints in the admin panel.

### Webhook Format

```json
{
  "id": "evt_123",
  "type": "user.created",
  "data": {
    // Event-specific data
  },
  "created_at": "2024-01-20T10:00:00Z",
  "tenant_id": "tenant_123"
}
```

### Webhook Security

All webhooks include an HMAC signature in the `X-Webhook-Signature` header:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Available Webhook Events

- **Authentication**: `user.created`, `user.login`, `user.logout`, `mfa.enabled`
- **Billing**: `subscription.created`, `subscription.updated`, `payment.succeeded`
- **Security**: `threat.detected`, `certificate.expiring`, `policy.violated`
- **System**: `maintenance.scheduled`, `feature.enabled`, `config.updated`

---

## SDK Examples

### Python SDK

```python
from platformforge import Client

client = Client(
    api_key="your_api_key",
    tenant_id="tenant_123"
)

# Track event
client.telemetry.track(
    event="user_action",
    properties={"action": "purchase"}
)

# Create subscription
subscription = client.billing.create_subscription(
    customer_id="cus_123",
    price_id="price_123"
)
```

### JavaScript SDK

```javascript
import { PlatformForge } from '@platformforge/sdk';

const client = new PlatformForge({
  apiKey: 'your_api_key',
  tenantId: 'tenant_123'
});

// Track event
await client.telemetry.track('page_view', {
  page: '/dashboard'
});

// Update consent
await client.privacy.updateConsent({
  analytics: true,
  marketing: false
});
```

### cURL Examples

```bash
# Login
curl -X POST https://api.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}'

# Track event (with auth)
curl -X POST https://api.example.com/api/v1/telemetry/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_name":"test","properties":{"test":true}}'
```

---

## API Versioning

Platform Forge uses URL-based versioning. The current version is `v1`.

### Version Header

Optionally specify version via header:
```http
X-API-Version: 1
```

### Deprecation Policy

- Deprecated endpoints return `X-Deprecated: true` header
- Minimum 6 months notice before removal
- Migration guides provided for breaking changes

---

## Support

- **Documentation**: https://docs.platformforge.com
- **API Status**: https://status.platformforge.com
- **Support**: support@platformforge.com
- **Discord**: https://discord.gg/platformforge