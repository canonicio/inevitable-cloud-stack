# Platform Forge Testing Guide

## Overview

Platform Forge employs a comprehensive testing strategy to ensure code quality, security, and reliability. Our test suite includes unit tests, integration tests, API tests, performance tests, and security-focused tests. This guide provides everything you need to understand, run, and contribute to the test suite.

### Test Philosophy

- **Security First**: All security-critical components have dedicated test coverage
- **Test-Driven Development**: New features should include tests
- **Real-World Scenarios**: Tests simulate actual usage patterns
- **Fast Feedback**: Unit tests run quickly, integration tests are thorough
- **Continuous Integration**: All tests run automatically on every commit

## Test Suite Structure

### Directory Organization

```
tests/
├── unit/                       # Fast, isolated unit tests
│   ├── test_security.py       # Core security utilities
│   ├── test_auth_*.py         # Authentication components
│   ├── test_billing_*.py      # Billing and Stripe integration
│   ├── test_admin_*.py        # Admin features and MFA
│   ├── test_privacy_*.py      # GDPR and privacy compliance
│   └── test_*_comprehensive.py # Comprehensive module tests
├── integration/                # Cross-module interaction tests
│   ├── test_cross_module_integration.py
│   └── test_billing_webhooks.py
├── api/                       # API endpoint tests
│   ├── test_auth_routes.py
│   ├── test_billing_routes.py
│   └── test_health.py
├── performance/               # Load and performance tests
│   └── test_load_performance.py
├── conftest.py               # Shared fixtures and configuration
└── fixtures.py               # Additional test fixtures
```

### Naming Conventions

- Test files: `test_<module>_<component>.py`
- Test classes: `Test<ComponentName>`
- Test methods: `test_<scenario>_<expected_result>`
- Comprehensive tests: `test_<module>_comprehensive.py`

## Test Coverage Summary

### Current Metrics

Based on our latest test run:

- **Total Test Files**: 37
- **Test Classes**: 33
- **Test Methods**: 957
- **Code Coverage Target**: 80% (enforced by pytest)
- **Critical Security Coverage**: 100%

### Module Coverage

| Module | Unit Tests | Integration | Security | Coverage |
|--------|------------|-------------|----------|----------|
| Core Security | ✅ Comprehensive | ✅ | ✅ | 100% |
| Authentication | ✅ Comprehensive | ✅ | ✅ | 95%+ |
| Billing | ✅ Comprehensive | ✅ | ✅ | 90%+ |
| Admin/MFA | ✅ Comprehensive | ✅ | ✅ | 95%+ |
| Privacy/GDPR | ✅ | ✅ | ✅ | 85%+ |
| Observability | ✅ | ✅ | ⚡ | 80%+ |
| Generator | ✅ Comprehensive | ⚡ | ✅ | 85%+ |

Legend: ✅ Complete | ⚡ Partial | ❌ Missing

## Running Tests

### Prerequisites

1. Install test dependencies:
```bash
pip install -r requirements.txt
pip install pytest pytest-cov pytest-asyncio pytest-mock
```

2. Set up test environment:
```bash
# For integration tests requiring PostgreSQL
docker-compose up -d postgres

# Set test environment variables
export DATABASE_URL="sqlite:///:memory:"  # For unit tests
export JWT_SECRET_KEY="test-secret-key"
export STRIPE_API_KEY="sk_test_fake"
export STRIPE_WEBHOOK_SECRET="whsec_test_fake"
```

### Running All Tests

```bash
# Run all tests with coverage
pytest

# Run with verbose output
pytest -v

# Run with specific coverage report
pytest --cov=modules --cov-report=html
```

### Running Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests
pytest -m integration

# Security tests
pytest -m security

# API tests
pytest -m api

# Skip slow tests
pytest -m "not slow"
```

### Running Individual Test Files

```bash
# Run specific test file
pytest tests/unit/test_security_comprehensive.py

# Run specific test class
pytest tests/unit/test_security_comprehensive.py::TestSecurityUtils

# Run specific test method
pytest tests/unit/test_security_comprehensive.py::TestSecurityUtils::test_sanitize_path_malicious_attempts
```

### Coverage Reports

```bash
# Generate HTML coverage report
pytest --cov=modules --cov-report=html
# Open htmlcov/index.html in browser

# Generate terminal coverage report
pytest --cov=modules --cov-report=term-missing

# Generate XML coverage report (for CI/CD)
pytest --cov=modules --cov-report=xml
```

## Key Test Scenarios

### 1. Security Test Scenarios

Our security tests cover critical vulnerabilities:

#### Path Traversal Protection
```python
def test_sanitize_path_malicious_attempts():
    """Prevents directory traversal attacks"""
    malicious_paths = [
        "../etc/passwd",
        "../../etc/passwd",
        "folder/../../../etc/passwd",
    ]
    for path in malicious_paths:
        with pytest.raises(SecurityError):
            SecurityUtils.sanitize_path(path)
```

#### SQL Injection Prevention
```python
def test_sql_injection_prevention():
    """Ensures parameterized queries prevent SQL injection"""
    malicious_input = "'; DROP TABLE users; --"
    # Test that ORM properly escapes input
    result = db.query(User).filter(User.email == malicious_input).first()
    assert result is None  # No SQL injection executed
```

#### Multi-Tenant Isolation
```python
def test_tenant_isolation():
    """Verifies data isolation between tenants"""
    # Create data for tenant1
    item1 = Item(name="Test", tenant_id="tenant1")
    
    # Try to access from tenant2 context
    with tenant_context("tenant2"):
        items = db.query(Item).all()
        assert len(items) == 0  # No cross-tenant data leak
```

### 2. Authentication Flow Tests

```python
def test_complete_auth_flow():
    """Tests registration, login, and token refresh"""
    # 1. Register user
    response = client.post("/api/auth/register", json={...})
    assert response.status_code == 201
    
    # 2. Login
    response = client.post("/api/auth/login", data={...})
    token = response.json()["access_token"]
    
    # 3. Access protected endpoint
    response = client.get("/api/users/me", 
                         headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
```

### 3. Billing Integration Tests

```python
def test_stripe_webhook_processing():
    """Tests secure webhook processing"""
    # Create webhook payload
    payload = create_stripe_event("customer.subscription.created")
    
    # Generate valid signature
    signature = generate_webhook_signature(payload, webhook_secret)
    
    # Process webhook
    response = client.post("/api/billing/webhooks/stripe",
                          data=payload,
                          headers={"Stripe-Signature": signature})
    assert response.status_code == 200
```

### 4. MFA Flow Tests

```python
def test_mfa_setup_and_verification():
    """Tests complete MFA setup and usage"""
    # 1. Setup MFA
    response = client.post("/api/admin/mfa/setup", headers=auth_headers)
    secret = response.json()["secret"]
    
    # 2. Verify with TOTP code
    code = generate_totp_code(secret)
    response = client.post("/api/admin/mfa/verify", 
                          json={"code": code},
                          headers=auth_headers)
    assert response.status_code == 200
```

## Performance Testing Guidelines

### Load Testing

Our performance tests validate response times under load:

```python
def test_api_performance_under_load():
    """Ensure API responds within acceptable time under load"""
    # Simulate 100 concurrent requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for _ in range(100):
            future = executor.submit(client.get, "/api/health")
            futures.append(future)
        
        # Verify all complete within 5 seconds
        results = [f.result() for f in futures]
        assert all(r.status_code == 200 for r in results)
```

### Performance Benchmarks

| Endpoint | Target Response Time | Max Concurrent Users |
|----------|---------------------|---------------------|
| Health Check | < 50ms | 1000 |
| User Login | < 200ms | 100 |
| API Read | < 100ms | 500 |
| API Write | < 300ms | 100 |
| Webhook Processing | < 500ms | 50 |

## CI/CD Integration

### GitHub Actions Configuration

Our CI/CD pipeline runs tests automatically:

```yaml
# .github/workflows/ci-cd.yml
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: platform_forge_test
    
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov
      
      - name: Run tests
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/platform_forge_test
        run: pytest
```

### Pre-commit Hooks

Configure pre-commit to run tests:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest
        language: system
        types: [python]
        pass_filenames: false
        always_run: true
```

## Contributing New Tests

### Test Writing Guidelines

1. **Follow AAA Pattern**:
   - **Arrange**: Set up test data and mocks
   - **Act**: Execute the code under test
   - **Assert**: Verify expected outcomes

2. **Use Descriptive Names**:
   ```python
   # Good
   def test_user_registration_with_existing_email_returns_409():
   
   # Bad
   def test_register_fail():
   ```

3. **Test Edge Cases**:
   - Null/empty inputs
   - Boundary values
   - Invalid data types
   - Concurrent access
   - Error conditions

4. **Mock External Services**:
   ```python
   @patch('stripe.Customer.create')
   def test_billing_integration(mock_stripe):
       mock_stripe.return_value = Mock(id="cus_123")
       # Test code here
   ```

5. **Use Fixtures for Common Setup**:
   ```python
   @pytest.fixture
   def authenticated_client(client, db):
       # Create user and return authenticated client
       return client_with_auth_headers
   ```

### Security Test Requirements

All new features must include security tests:

1. **Input Validation**: Test with malicious inputs
2. **Authorization**: Verify access controls
3. **Data Isolation**: Ensure tenant separation
4. **Rate Limiting**: Test rate limit enforcement
5. **Encryption**: Verify sensitive data encryption

## Troubleshooting Common Test Issues

### Issue: "Database is locked" (SQLite)

**Solution**: Ensure proper test isolation:
```python
@pytest.fixture(scope="function")  # Not "session"
def db():
    # Create fresh database for each test
```

### Issue: "Port already in use"

**Solution**: Use dynamic ports in tests:
```python
@pytest.fixture
def test_server():
    port = get_free_port()
    # Start server on dynamic port
```

### Issue: Flaky Integration Tests

**Solutions**:
1. Add proper waits:
   ```python
   # Wait for async operations
   await asyncio.sleep(0.1)
   ```

2. Use retries for external services:
   ```python
   @pytest.mark.flaky(reruns=3)
   def test_external_api():
   ```

3. Mock time-dependent code:
   ```python
   @freeze_time("2024-01-01")
   def test_time_sensitive():
   ```

### Issue: Slow Test Suite

**Solutions**:
1. Parallelize tests:
   ```bash
   pytest -n auto  # Run on all CPU cores
   ```

2. Use test markers:
   ```python
   @pytest.mark.slow
   def test_heavy_computation():
   ```

3. Profile slow tests:
   ```bash
   pytest --durations=10  # Show 10 slowest tests
   ```

## Known Limitations

1. **Generated Platform Tests**: Currently, tests for generated platforms must be written manually. Future versions will include test generation.

2. **E2E Browser Tests**: No Selenium/Playwright tests yet. API tests provide good coverage for now.

3. **Performance Baselines**: Performance benchmarks are guidelines. Actual performance depends on deployment environment.

4. **Test Data Management**: Large test datasets can slow down tests. Consider using factories or fixtures.

## Future Improvements

### Planned Enhancements

1. **Test Generation**: Automatically generate tests from manifests
2. **Property-Based Testing**: Add hypothesis tests for edge cases
3. **Mutation Testing**: Verify test effectiveness
4. **Load Test Automation**: Automated performance regression detection
5. **Visual Regression Tests**: For admin dashboards
6. **Contract Testing**: For API versioning
7. **Chaos Engineering**: Test failure scenarios

### Contributing

To contribute test improvements:

1. Check existing test coverage:
   ```bash
   pytest --cov=modules --cov-report=term-missing
   ```

2. Write tests for uncovered code

3. Ensure all tests pass:
   ```bash
   pytest
   ```

4. Submit PR with:
   - New/updated tests
   - Coverage improvement metrics
   - Documentation updates

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Testing Best Practices](https://testdriven.io/blog/testing-best-practices/)
- [FastAPI Testing Guide](https://fastapi.tiangolo.com/tutorial/testing/)
- [SQLAlchemy Testing](https://docs.sqlalchemy.org/en/14/orm/session_transaction.html)

## Support

For testing questions or issues:

1. Check this guide first
2. Review existing test examples
3. Open a GitHub issue with:
   - Test scenario description
   - Error messages
   - Minimal reproduction code