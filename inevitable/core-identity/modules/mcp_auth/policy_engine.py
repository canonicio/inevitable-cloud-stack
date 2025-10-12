"""
MCP Policy Engine for fine-grained access control
"""
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, time
from ipaddress import ip_address, ip_network
from sqlalchemy.orm import Session

from .models import MCPPolicy, MCPSession, MCPPermissionType, MCPResourceType, MCPRateLimitRule
from modules.auth.models import User


class PolicyEngine:
    """Evaluates MCP access policies"""
    
    def __init__(self, db: Session):
        self.db = db
        self._rate_limit_cache = {}
    
    def check_access(
        self,
        session: MCPSession,
        resource_type: MCPResourceType,
        resource_name: str,
        permission: MCPPermissionType,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a session has access to a resource
        Returns: (allowed, denial_reason)
        """
        
        # Get the policy
        policy = session.policy
        if not policy or not policy.is_active:
            return False, "Policy not found or inactive"
        
        # Check resource type match
        if policy.resource_type != MCPResourceType.ALL and policy.resource_type != resource_type:
            return False, f"Policy does not cover resource type: {resource_type}"
        
        # Check resource pattern match
        if not self._match_resource_pattern(resource_name, policy.resource_pattern):
            return False, f"Resource {resource_name} does not match policy pattern"
        
        # Check permissions
        if permission.value not in policy.permissions:
            return False, f"Permission {permission} not granted by policy"
        
        # Check conditions
        if policy.conditions:
            conditions_result = self._evaluate_conditions(
                policy.conditions,
                session,
                context or {}
            )
            if not conditions_result[0]:
                return False, conditions_result[1]
        
        # Check rate limits
        rate_limit_result = self._check_rate_limits(
            session.tenant_id,
            policy.id,
            resource_name
        )
        if not rate_limit_result[0]:
            return False, rate_limit_result[1]
        
        return True, None
    
    def get_effective_permissions(
        self,
        user: User,
        tenant_id: str
    ) -> Dict[str, List[str]]:
        """Get all effective permissions for a user"""
        
        # Get all active sessions for the user
        sessions = self.db.query(MCPSession).filter(
            MCPSession.user_id == user.id,
            MCPSession.tenant_id == tenant_id,
            MCPSession.expires_at > datetime.utcnow(),
            MCPSession.revoked_at.is_(None)
        ).all()
        
        permissions = {}
        
        for session in sessions:
            policy = session.policy
            if not policy or not policy.is_active:
                continue
            
            resource_key = f"{policy.resource_type.value}:{policy.resource_pattern}"
            if resource_key not in permissions:
                permissions[resource_key] = []
            
            permissions[resource_key].extend(policy.permissions)
        
        # Deduplicate permissions
        for key in permissions:
            permissions[key] = list(set(permissions[key]))
        
        return permissions
    
    def create_policy(
        self,
        tenant_id: str,
        name: str,
        resource_type: MCPResourceType,
        resource_pattern: str,
        permissions: List[MCPPermissionType],
        created_by: User,
        **kwargs
    ) -> MCPPolicy:
        """Create a new MCP policy"""
        
        policy = MCPPolicy(
            tenant_id=tenant_id,
            name=name,
            resource_type=resource_type,
            resource_pattern=resource_pattern,
            permissions=[p.value for p in permissions],
            created_by=created_by.id,
            **kwargs
        )
        
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        
        return policy
    
    def _match_resource_pattern(self, resource_name: str, pattern: str) -> bool:
        """Check if a resource name matches a pattern"""
        
        # Convert pattern to regex
        # * matches any characters within a segment
        # ** matches any characters across segments
        regex_pattern = pattern.replace("**", ".*")
        regex_pattern = regex_pattern.replace("*", "[^/]*")
        regex_pattern = f"^{regex_pattern}$"
        
        return bool(re.match(regex_pattern, resource_name))
    
    def _evaluate_conditions(
        self,
        conditions: Dict[str, Any],
        session: MCPSession,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate policy conditions"""
        
        # Time-based conditions
        if "time_restrictions" in conditions:
            time_result = self._check_time_restrictions(
                conditions["time_restrictions"]
            )
            if not time_result[0]:
                return time_result
        
        # IP-based conditions
        if "ip_whitelist" in conditions:
            ip_result = self._check_ip_whitelist(
                session.ip_address,
                conditions["ip_whitelist"]
            )
            if not ip_result[0]:
                return ip_result
        
        # MFA requirements
        if conditions.get("require_recent_mfa"):
            mfa_result = self._check_recent_mfa(
                session,
                conditions.get("mfa_max_age_minutes", 30)
            )
            if not mfa_result[0]:
                return mfa_result
        
        # Custom conditions
        if "custom" in conditions:
            for condition in conditions["custom"]:
                custom_result = self._evaluate_custom_condition(
                    condition,
                    session,
                    context
                )
                if not custom_result[0]:
                    return custom_result
        
        return True, None
    
    def _check_time_restrictions(
        self,
        restrictions: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Check time-based access restrictions"""
        
        now = datetime.utcnow()
        current_time = now.time()
        current_day = now.strftime("%A").lower()
        
        # Check allowed days
        if "allowed_days" in restrictions:
            if current_day not in restrictions["allowed_days"]:
                return False, f"Access not allowed on {current_day}"
        
        # Check allowed hours
        if "allowed_hours" in restrictions:
            start_time = time.fromisoformat(restrictions["allowed_hours"]["start"])
            end_time = time.fromisoformat(restrictions["allowed_hours"]["end"])
            
            if not (start_time <= current_time <= end_time):
                return False, "Access not allowed at this time"
        
        return True, None
    
    def _check_ip_whitelist(
        self,
        request_ip: Optional[str],
        whitelist: List[str]
    ) -> Tuple[bool, Optional[str]]:
        """Check IP whitelist"""
        
        if not request_ip:
            return False, "No IP address provided"
        
        try:
            request_addr = ip_address(request_ip)
            
            for allowed_ip in whitelist:
                if "/" in allowed_ip:
                    # CIDR notation
                    if request_addr in ip_network(allowed_ip):
                        return True, None
                else:
                    # Single IP
                    if request_addr == ip_address(allowed_ip):
                        return True, None
            
            return False, f"IP {request_ip} not in whitelist"
            
        except ValueError:
            return False, "Invalid IP address"
    
    def _check_recent_mfa(
        self,
        session: MCPSession,
        max_age_minutes: int
    ) -> Tuple[bool, Optional[str]]:
        """Check if MFA was recently verified"""
        
        if not session.mfa_verified:
            return False, "MFA verification required"
        
        if not session.mfa_verified_at:
            return False, "MFA verification timestamp missing"
        
        age = datetime.utcnow() - session.mfa_verified_at
        if age.total_seconds() > max_age_minutes * 60:
            return False, f"MFA verification older than {max_age_minutes} minutes"
        
        return True, None
    
    def _evaluate_custom_condition(
        self,
        condition: Dict[str, Any],
        session: MCPSession,
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate custom conditions"""
        
        condition_type = condition.get("type")
        
        if condition_type == "context_match":
            # Check if context values match
            field = condition.get("field")
            expected = condition.get("value")
            
            if field not in context:
                return False, f"Required context field '{field}' not provided"
            
            if context[field] != expected:
                return False, f"Context field '{field}' does not match expected value"
        
        elif condition_type == "user_attribute":
            # Check user attributes
            attribute = condition.get("attribute")
            expected = condition.get("value")
            
            user = session.user
            if not hasattr(user, attribute):
                return False, f"User attribute '{attribute}' not found"
            
            if getattr(user, attribute) != expected:
                return False, f"User attribute '{attribute}' does not match expected value"
        
        return True, None
    
    def _check_rate_limits(
        self,
        tenant_id: str,
        policy_id: int,
        resource_name: str
    ) -> Tuple[bool, Optional[str]]:
        """Check rate limits for a resource"""
        
        # Get applicable rate limit rules
        rules = self.db.query(MCPRateLimitRule).filter(
            MCPRateLimitRule.tenant_id == tenant_id,
            MCPRateLimitRule.policy_id == policy_id,
            MCPRateLimitRule.is_active == True
        ).all()
        
        for rule in rules:
            if self._match_resource_pattern(resource_name, rule.resource_pattern):
                # Check rate limit
                cache_key = f"{tenant_id}:{policy_id}:{rule.id}"
                
                # Simple in-memory rate limiting (should use Redis in production)
                if cache_key not in self._rate_limit_cache:
                    self._rate_limit_cache[cache_key] = {
                        "count": 0,
                        "window_start": datetime.utcnow()
                    }
                
                cache_entry = self._rate_limit_cache[cache_key]
                
                # Check if window has expired
                if (datetime.utcnow() - cache_entry["window_start"]).total_seconds() > rule.window_seconds:
                    # Reset window
                    cache_entry["count"] = 0
                    cache_entry["window_start"] = datetime.utcnow()
                
                # Check limit
                if cache_entry["count"] >= rule.max_requests:
                    return False, f"Rate limit exceeded: {rule.max_requests} requests per {rule.window_seconds} seconds"
                
                # Increment counter
                cache_entry["count"] += 1
        
        return True, None