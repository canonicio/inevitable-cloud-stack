"""
Input validators for admin module
"""
from typing import Optio, Annotatednal, List
from pydantic import constr, validator
from datetime import datetime

from ..core.validators import BaseValidator, ValidationPatterns


class UserStatusUpdate(BaseValidator):
    """Validate user status update"""
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_superuser: Optional[bool] = None
    
    @field_validator('*', pre=True)
    @classmethod
    def at_least_one_field(cls, v, values):
        """Ensure at least one field is provided"""
        if not any(values.values()):
            raise ValueError("At least one field must be provided")
        return v


class RoleAssignment(BaseValidator):
    """Validate role assignment"""
    user_id: Annotated[int, Field(gt=0)]
    role_id: Annotated[int, Field(gt=0)]
    
    @field_validator('role_id')
    @classmethod
    def validate_role_id(cls, v):
        """Ensure role exists and is assignable"""
        # In production, this would check against database
        reserved_roles = {1}  # e.g., super_admin role
        if v in reserved_roles:
            raise ValueError("Cannot assign system roles directly")
        return v


class AuditLogFilter(BaseValidator):
    """Validate audit log filters"""
    user_id: Optional[Annotated[int, Field(gt=0)]] = None
    action: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER, max_length=100)]] = None
    resource_type: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER, max_length=50)]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: Annotated[int, Field(ge=1, le=1000)] = 100
    offset: Annotated[int, Field(ge=0)] = 0
    
    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        """Validate action is safe and doesn't contain injection"""
        if v:
            return BaseValidator.validate_no_injection(v, "action")
        return v
    
    @field_validator('end_date')
    @classmethod
    def validate_date_range(cls, v, values):
        """Ensure end date is after start date"""
        if v and 'start_date' in values and values['start_date']:
            if v < values['start_date']:
                raise ValueError("End date must be after start date")
            
            # Prevent excessively large date ranges
            date_diff = (v - values['start_date']).days
            if date_diff > 365:
                raise ValueError("Date range cannot exceed 365 days")
        return v


class MFASetup(BaseValidator):
    """Validate MFA setup request"""
    method: Annotated[str, Field(pattern=r'^(totp|email|sms)]$')
    phone_number: Optional[Annotated[str, Field(pattern=ValidationPatterns.PHONE)]] = None
    
    @field_validator('phone_number')
    @classmethod
    def validate_phone_for_sms(cls, v, values):
        """Ensure phone number is provided for SMS method"""
        if 'method' in values and values['method'] == 'sms' and not v:
            raise ValueError("Phone number required for SMS MFA")
        return v


class MFAVerification(BaseValidator):
    """Validate MFA verification"""
    token: Annotated[str, Field(pattern=r'^\d{6}$|^[A-Z0-9]{4}-[A-Z0-9]{4}$')]
    
    @field_validator('token')
    @classmethod
    def validate_token_format(cls, v):
        """Validate token is either 6-digit TOTP or backup code format"""
        if not (len(v) == 6 and v.isdigit()) and not (len(v) == 9 and '-' in v):
            raise ValueError("Invalid token format")
        return v


class UserSearch(BaseValidator):
    """Validate user search parameters"""
    query: Annotated[str, Field(min_length=2, max_length=100)]
    search_fields: Optional[List[Annotated[str, Field(pattern=r'^(username|email|first_name|last_name)]$')]] = None
    include_inactive: bool = False
    limit: Annotated[int, Field(ge=1, le=100)] = 20
    
    @field_validator('query')
    @classmethod
    def sanitize_query(cls, v):
        """Sanitize search query"""
        # Remove special regex characters that could cause issues
        v = re.sub(r'[.*+?^${}()|[\]\\]', '', v)
        return BaseValidator.validate_no_injection(v, "search query")


class TenantUpdate(BaseValidator):
    """Validate tenant update (multi-tenant deployments)"""
    name: Optional[Annotated[str, Field(min_length=3, max_length=100, pattern=ValidationPatterns.SAFE_STRING)]] = None
    is_active: Optional[bool] = None
    settings: Optional[dict] = None
    
    @field_validator('settings')
    @classmethod
    def validate_settings(cls, v):
        """Validate tenant settings structure"""
        if v:
            # Prevent deeply nested objects
            from ..core.validators import validate_json_schema
            if not validate_json_schema(v, max_depth=5):
                raise ValueError("Settings object too deeply nested")
            
            # Limit total size
            import json
            if len(json.dumps(v)) > 10000:
                raise ValueError("Settings object too large")
        return v


class AdminDashboardFilter(BaseValidator):
    """Validate admin dashboard filters"""
    date_range: Annotated[str, Field(pattern=r'^(today|yesterday|week|month|quarter|year|custom)]$') = 'month'
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    tenant_id: Optional[Annotated[str, Field(pattern=ValidationPatterns.SAFE_IDENTIFIER)]] = None
    
    @field_validator('start_date', 'end_date')
    @classmethod
    def validate_custom_dates(cls, v, values):
        """Validate custom date range"""
        if 'date_range' in values and values['date_range'] == 'custom':
            if not v:
                raise ValueError("Start and end dates required for custom range")
        return v