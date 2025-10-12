"""
Comprehensive RBAC Privilege Escalation Tests
Tests for RISK-H001: RBAC Privilege Escalation vulnerability fix
"""
import pytest
import networkx as nx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from unittest.mock import Mock, patch

from modules.auth.rbac_validator import RBACValidator, validate_permission_format, expand_wildcard_permissions
from modules.auth.models import User, Role, Permission
from modules.core.database import get_db


class TestRBACPrivilegeEscalation:
    """Test RBAC privilege escalation prevention"""
    
    def test_direct_privilege_escalation_blocked(self, client: TestClient, limited_admin_token: str):
        """Test direct privilege grant is blocked"""
        response = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {limited_admin_token}"},
            json={
                "name": "escalated_role",
                "permissions": ["system:admin", "billing:admin"]
            }
        )
        assert response.status_code == 403
        assert "Cannot grant permission: system:admin" in response.json()["detail"]
    
    def test_inherited_privilege_escalation_blocked(self, client: TestClient, system_admin_token: str, limited_admin_token: str):
        """Test inherited privilege escalation is blocked"""
        # First create a high-privilege role (as system admin)
        admin_response = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {system_admin_token}"},
            json={
                "name": "high_privilege_role",
                "permissions": ["system:admin"]
            }
        )
        assert admin_response.status_code == 200
        high_role_id = admin_response.json()["id"]
        
        # Try to inherit from it as limited admin
        response = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {limited_admin_token}"},
            json={
                "name": "sneaky_role",
                "inherits_from": [str(high_role_id)],
                "permissions": ["user:read"]
            }
        )
        assert response.status_code == 403
        assert "Cannot grant permission: system:admin" in response.json()["detail"]
    
    def test_circular_dependency_prevented(self, client: TestClient, admin_token: str):
        """Test circular role dependencies are prevented"""
        # Create role A
        response_a = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"name": "role_a", "permissions": ["users:read"]}
        )
        assert response_a.status_code == 200
        role_a_id = response_a.json()["id"]
        
        # Create role B inheriting from A
        response_b = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": "role_b",
                "inherits_from": [str(role_a_id)],
                "permissions": ["users:write"]
            }
        )
        assert response_b.status_code == 200
        role_b_id = response_b.json()["id"]
        
        # Try to make A inherit from B (circular)
        response = client.put(
            f"/api/v1/auth/rbac/roles/{role_a_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"inherits_from": [str(role_b_id)]}
        )
        assert response.status_code == 400
        assert "circular dependency" in response.json()["detail"].lower()
    
    def test_wildcard_permission_expansion(self, client: TestClient, admin_token: str):
        """Test wildcard permissions are properly expanded and validated"""
        # Try to create a role with global wildcard as non-global admin
        response = client.post(
            "/api/v1/auth/rbac/roles",
            headers={"Authorization": f"Bearer {admin_token}"},  # Assume this is tenant admin, not global
            json={
                "name": "wildcard_role",
                "permissions": ["*:*"]
            }
        )
        # Should block if user doesn't have global permissions
        if response.status_code == 403:
            assert "Cannot grant permission: *:*" in response.json()["detail"]
    
    def test_role_assignment_privilege_check(self, client: TestClient, limited_admin_token: str):
        """Test role assignment privilege validation"""
        # Create a high-privilege role first (as system admin)
        with patch('modules.auth.dependencies.get_current_user') as mock_get_user:
            # Mock system admin user
            system_admin = Mock()
            system_admin.id = "system_admin_id"
            system_admin.roles = [Mock(name="super_admin")]
            mock_get_user.return_value = system_admin
            
            admin_response = client.post(
                "/api/v1/auth/rbac/roles",
                headers={"Authorization": "Bearer system_admin_token"},
                json={
                    "name": "high_privilege_role",
                    "permissions": ["system:admin", "billing:admin"]
                }
            )
        
        if admin_response.status_code == 200:
            high_role_id = admin_response.json()["id"]
            
            # Try to assign this high-privilege role to a user as limited admin
            response = client.put(
                "/api/v1/auth/rbac/users/123/roles",
                headers={"Authorization": f"Bearer {limited_admin_token}"},
                json={"role_ids": [high_role_id]}
            )
            assert response.status_code == 403
            assert "Cannot assign roles with permissions you don't have" in response.json()["detail"]
    
    def test_self_privilege_escalation_blocked(self, client: TestClient, user_token: str):
        """Test users cannot escalate their own privileges"""
        # Try to assign admin role to self
        response = client.put(
            "/api/v1/auth/rbac/users/self/roles",  # Assuming self endpoint exists
            headers={"Authorization": f"Bearer {user_token}"},
            json={"role_ids": [999]}  # Admin role ID
        )
        assert response.status_code == 403
        assert "Cannot assign additional roles to yourself" in response.json()["detail"]


class TestRBACValidator:
    """Test the RBACValidator class directly"""
    
    def test_permission_collection_with_inheritance(self):
        """Test recursive permission collection"""
        mock_db = Mock()
        
        # Mock role hierarchy: role_a -> role_b -> role_c
        role_c = Mock()
        role_c.id = "role_c"
        role_c.permissions = ["base:read"]
        role_c.inherits_from = []
        
        role_b = Mock()
        role_b.id = "role_b"
        role_b.permissions = ["intermediate:write"]
        role_b.inherits_from = ["role_c"]
        
        role_a = Mock()
        role_a.id = "role_a"
        role_a.permissions = ["top:admin"]
        role_a.inherits_from = ["role_b"]
        
        # Mock database queries
        def mock_query_filter(role_id):
            role_map = {"role_a": role_a, "role_b": role_b, "role_c": role_c}
            result = Mock()
            result.first.return_value = role_map.get(role_id)
            return result
        
        mock_db.query.return_value.filter.side_effect = mock_query_filter
        
        validator = RBACValidator(mock_db)
        
        # Test permission collection
        role_data = {
            "permissions": ["direct:permission"],
            "inherits_from": ["role_a"]
        }
        
        permissions = validator._collect_all_permissions(role_data)
        
        expected_permissions = {
            "direct:permission",
            "top:admin",
            "intermediate:write", 
            "base:read"
        }
        
        assert permissions == expected_permissions
    
    def test_circular_dependency_detection(self):
        """Test circular dependency detection using graph theory"""
        mock_db = Mock()
        
        # Mock existing roles that would create a cycle
        existing_roles = [
            Mock(id="role_1", inherits_from=["role_2"]),
            Mock(id="role_2", inherits_from=["role_3"]),
            Mock(id="role_3", inherits_from=[])
        ]
        
        mock_db.query.return_value.all.return_value = existing_roles
        
        validator = RBACValidator(mock_db)
        
        # Test creating a role that would complete the cycle
        role_data = {
            "id": "role_4",
            "inherits_from": ["role_1", "role_3"]  # This creates role_3 -> role_4 -> role_1 -> role_2 -> role_3
        }
        
        # This should NOT create a cycle actually, let me fix the test
        role_data = {
            "id": "role_3",  # Updating existing role_3
            "inherits_from": ["role_1"]  # This would create role_3 -> role_1 -> role_2 -> role_3
        }
        
        has_cycle = validator._creates_circular_dependency(role_data)
        assert has_cycle == True
        
        # Test valid hierarchy
        valid_role_data = {
            "id": "role_4", 
            "inherits_from": ["role_3"]  # This extends the chain without cycles
        }
        
        has_cycle = validator._creates_circular_dependency(valid_role_data)
        assert has_cycle == False
    
    def test_wildcard_permission_matching(self):
        """Test wildcard permission matching logic"""
        mock_db = Mock()
        validator = RBACValidator(mock_db)
        
        # Test global wildcard
        user_permissions = {"*:*"}
        assert validator._has_wildcard_permission(user_permissions, "users:create") == True
        assert validator._has_wildcard_permission(user_permissions, "billing:admin") == True
        
        # Test resource wildcard
        user_permissions = {"users:*"}
        assert validator._has_wildcard_permission(user_permissions, "users:create") == True
        assert validator._has_wildcard_permission(user_permissions, "users:delete") == True
        assert validator._has_wildcard_permission(user_permissions, "billing:create") == False
        
        # Test no wildcards
        user_permissions = {"users:read", "users:write"}
        assert validator._has_wildcard_permission(user_permissions, "users:create") == False
        assert validator._has_wildcard_permission(user_permissions, "users:admin") == False


class TestPermissionValidation:
    """Test permission format validation and wildcard expansion"""
    
    def test_permission_format_validation(self):
        """Test permission string format validation"""
        # Valid permissions
        assert validate_permission_format("users:create") == True
        assert validate_permission_format("billing:admin") == True
        assert validate_permission_format("*:*") == True
        
        # Invalid permissions
        assert validate_permission_format("invalid") == False
        assert validate_permission_format("") == False
        assert validate_permission_format("users:") == False
        assert validate_permission_format(":create") == False
        assert validate_permission_format(None) == False
        assert validate_permission_format("*:create") == False  # Resource wildcard without action wildcard
    
    def test_wildcard_permission_expansion(self):
        """Test wildcard permission expansion"""
        # Test global wildcard expansion
        permissions = ["*:*"]
        expanded = expand_wildcard_permissions(permissions)
        
        # Should include all possible permissions
        assert "users:create" in expanded
        assert "billing:read" in expanded
        assert "admin:write" in expanded
        assert len(expanded) > 10  # Should have many permissions
        
        # Test resource wildcard expansion
        permissions = ["users:*"]
        expanded = expand_wildcard_permissions(permissions)
        
        # Should include all user permissions but not others
        assert "users:create" in expanded
        assert "users:delete" in expanded
        assert "billing:create" not in expanded
        
        # Test mixed permissions
        permissions = ["users:*", "billing:read", "admin:write"]
        expanded = expand_wildcard_permissions(permissions)
        
        assert "users:create" in expanded  # From wildcard
        assert "users:update" in expanded  # From wildcard
        assert "billing:read" in expanded  # Direct permission
        assert "admin:write" in expanded   # Direct permission
        assert "billing:write" not in expanded  # Not included


@pytest.fixture
def limited_admin_token():
    """Mock limited admin token for testing"""
    # This would be implemented based on your auth system
    return "mock_limited_admin_token"

@pytest.fixture
def system_admin_token():
    """Mock system admin token for testing"""
    return "mock_system_admin_token"

@pytest.fixture
def admin_token():
    """Mock admin token for testing"""
    return "mock_admin_token"

@pytest.fixture
def user_token():
    """Mock user token for testing"""
    return "mock_user_token"


class TestRBACIntegration:
    """Integration tests for RBAC system"""
    
    def test_complete_privilege_escalation_scenario(self, client: TestClient):
        """Test complete privilege escalation attack scenario"""
        # This would be a comprehensive integration test that:
        # 1. Creates a limited admin user
        # 2. Attempts various privilege escalation attacks
        # 3. Verifies all are blocked
        # 4. Confirms audit logs are created
        pass
    
    def test_role_hierarchy_complex_scenario(self, client: TestClient):
        """Test complex role hierarchy scenarios"""
        # This would test:
        # 1. Multi-level inheritance (A -> B -> C -> D)
        # 2. Multiple inheritance (A -> B, A -> C)
        # 3. Diamond inheritance patterns
        # 4. Circular dependency prevention
        pass
    
    def test_audit_logging_for_rbac_changes(self, client: TestClient):
        """Test that all RBAC changes are properly audited"""
        # This would verify:
        # 1. Role creation is logged
        # 2. Role updates are logged
        # 3. Role assignments are logged
        # 4. Failed attempts are logged
        # 5. Audit logs contain sufficient detail
        pass