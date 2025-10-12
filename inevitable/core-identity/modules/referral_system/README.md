# Referral System Module

A comprehensive referral tracking and credit system for Platform Forge applications, featuring Product Hunt launch tools, multi-type referral tracking, and a flexible credit engine.

## Features

### 🎯 Multi-Type Referral Tracking
- **Customer Referrals**: Track peer-to-peer referrals with custom codes
- **Affiliate Partners**: Full affiliate management with commission tracking
- **B2B Partners**: Enterprise partnership tracking
- **Influencer Campaigns**: Social media influencer tracking

### 💳 Flexible Credit System
- **Customer-Definable Actions**: Configure credit rewards via YAML
- **Dynamic Value Formulas**: Support for percentage-based and complex calculations
- **Multipliers**: Time-based, user-tier, and custom multipliers
- **Real-time Balance Tracking**: Instant credit updates and history

### 🚀 Product Hunt Launch Tools
- **Activity Verification**: Verify upvotes, reviews, and shares
- **Automated Campaigns**: Launch day automation with milestones
- **Live Leaderboards**: Real-time ranking with badges
- **Credit Rewards**: "Leave a review, get credits" system

### 💰 Commission Management
- **Multiple Models**: Percentage, fixed, tiered, recurring, hybrid
- **Automated Payouts**: Stripe, PayPal, wire transfer support
- **Tax Documentation**: 1099 generation for US affiliates
- **Partner Dashboards**: Real-time earnings tracking

### 🛡️ Fraud Prevention
- **Device Fingerprinting**: Track unique devices
- **Velocity Checks**: Prevent abuse with rate limiting
- **Pattern Detection**: Identify suspicious behaviors
- **Risk Scoring**: Real-time risk assessment

### 📊 Analytics & Reporting
- **Conversion Funnels**: Track referral journey
- **Cohort Analysis**: Understand user behavior over time
- **Attribution Models**: First-touch, last-touch, linear, time-decay
- **ROI Tracking**: Campaign performance metrics

## Installation

Add `referral_system` to your Platform Forge manifest:

```yaml
modules:
  - core
  - auth
  - billing  # Required for commission payouts
  - referral_system

config:
  referral_system:
    enable_product_hunt: true
    enable_commissions: true
    default_cookie_days: 30
```

## Configuration

### Credit Actions

Define custom credit actions in your application:

```python
# Via API
POST /api/referral/credits/actions
{
  "action_key": "signup_bonus",
  "name": "Signup Bonus",
  "description": "Welcome bonus for new users",
  "value_formula": "100",
  "is_active": true,
  "max_daily": 1,
  "max_total": 1
}

# Complex formula example
{
  "action_key": "purchase_reward",
  "name": "Purchase Reward",
  "description": "Earn 10% of purchase value",
  "value_formula": "10% of purchase.total",
  "is_active": true
}
```

### Referral Campaigns

Create campaigns with different commission structures:

```python
POST /api/referral/campaigns
{
  "name": "Summer Launch",
  "description": "Summer product launch campaign",
  "campaign_type": "customer",
  "commission_type": "percentage",
  "commission_config": {
    "rate": 20,
    "currency": "USD",
    "max_commission": 100
  },
  "attribution_model": "last_touch",
  "cookie_duration_days": 30,
  "is_active": true
}
```

### Product Hunt Integration

Process Product Hunt activities:

```python
# Submit an upvote
POST /api/referral/product-hunt/activity
{
  "activity_type": "upvote",
  "ph_username": "johndoe",
  "product_id": "platform-forge"
}

# Submit a review
POST /api/referral/product-hunt/activity
{
  "activity_type": "review",
  "ph_username": "johndoe",
  "proof_url": "https://producthunt.com/posts/platform-forge#comment-123",
  "content": "Amazing platform for building SaaS!",
  "has_screenshot": true
}
```

## API Reference

### Credit System

#### Award Credits
```
POST /api/referral/credits/award
```

#### Get Balance
```
GET /api/referral/credits/balance/{user_id}
```

#### Transaction History
```
GET /api/referral/credits/history/{user_id}
```

### Referral Tracking

#### Generate Code
```
POST /api/referral/generate-code
```

#### Track Referral
```
POST /api/referral/track
```

#### Convert Referral
```
POST /api/referral/referrals/{referral_id}/convert
```

### Product Hunt

#### Submit Activity
```
POST /api/referral/product-hunt/activity
```

#### Get Leaderboard
```
GET /api/referral/product-hunt/leaderboard
```

#### My Rank
```
GET /api/referral/product-hunt/my-rank
```

### Social Verification

#### Verify Share
```
POST /api/referral/social/verify
```

#### Get Templates
```
GET /api/referral/social/templates/{platform}
```

### Analytics

#### Overview
```
GET /api/referral/analytics/overview
```

#### Conversion Funnel
```
GET /api/referral/analytics/funnel/{campaign_id}
```

## Usage Examples

### 1. Basic Referral Flow

```python
# User generates referral code
response = requests.post("/api/referral/generate-code", json={
    "campaign_id": "summer-launch"
})
referral_code = response.json()["referral_code"]

# New user signs up with code
response = requests.post("/api/referral/track", json={
    "campaign_id": "summer-launch",
    "referred_email": "newuser@example.com",
    "referral_source": referral_code
})

# Convert on purchase
response = requests.post(f"/api/referral/referrals/{referral_id}/convert", json={
    "conversion_value": 99.99
})
```

### 2. Product Hunt Campaign

```python
# User upvotes on Product Hunt
response = requests.post("/api/referral/product-hunt/activity", json={
    "activity_type": "upvote",
    "ph_username": "techuser123"
})

# User shares on X.com
response = requests.post("/api/referral/product-hunt/activity", json={
    "activity_type": "share",
    "ph_username": "techuser123",
    "share_platform": "x_com",
    "proof_url": "https://x.com/techuser123/status/123456"
})

# Check leaderboard
response = requests.get("/api/referral/product-hunt/leaderboard")
```

### 3. Credit System Integration

```python
# Define action for user engagement
response = requests.post("/api/referral/credits/actions", json={
    "action_key": "daily_login",
    "name": "Daily Login Bonus",
    "description": "Reward for daily active users",
    "value_formula": "5 * user.streak_days",
    "max_daily": 1
})

# Award credits programmatically
response = requests.post("/api/referral/credits/award", json={
    "user_id": "user123",
    "action_key": "daily_login",
    "context": {
        "user": {"streak_days": 5}
    }
})
```

## Security

The module implements comprehensive security measures:

- **Input Validation**: All user inputs are sanitized
- **Fraud Detection**: Real-time risk analysis
- **Rate Limiting**: Prevent abuse and spam
- **Tenant Isolation**: Complete data segregation
- **Audit Logging**: Track all credit transactions

## Customization

### Custom Credit Formulas

The credit engine supports complex formulas:

```python
# Percentage of value
"10% of purchase.total"

# User attribute multiplication
"user.level * 50"

# Conditional formulas
"100 if user.premium else 50"

# Complex calculations
"(purchase.total * 0.1) + (user.referrals * 5)"
```

### Attribution Models

Configure how referrals are attributed:

- **First Touch**: Credit first referrer
- **Last Touch**: Credit last referrer
- **Linear**: Split credit equally
- **Time Decay**: Recent touches get more credit
- **Custom**: Define your own model

### Commission Tiers

Set up tiered commission structures:

```json
{
  "tiers": [
    {"threshold": 0, "type": "percentage", "rate": 10},
    {"threshold": 1000, "type": "percentage", "rate": 15},
    {"threshold": 5000, "type": "percentage", "rate": 20}
  ]
}
```

## Performance Considerations

- **Caching**: Leaderboards cached for performance
- **Batch Processing**: Commission calculations batched
- **Async Operations**: Non-blocking credit awards
- **Database Indexes**: Optimized for common queries

## Monitoring

Track system health with built-in metrics:

- Credit transaction velocity
- Referral conversion rates
- Fraud detection alerts
- Payout processing status
- System performance metrics

## Support

For issues or questions:
- Check the [API documentation](/api/docs)
- Review [security guidelines](../core/SECURITY.md)
- Contact Platform Forge support