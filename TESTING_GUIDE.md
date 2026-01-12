# Testing Guide: Agent Trust Registry

**Last Updated:** 2025-01-27  
**Status:** Comprehensive Testing Guide

---

## Quick Start: Running All Tests

### Prerequisites

1. **Virtual Environment (Recommended)**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Run All Tests

```bash
# Run all tests with verbose output
pytest -v

# Run all tests with coverage report
pytest --cov=atr --cov-report=html --cov-report=term

# Run all tests and show print statements
pytest -v -s
```

---

## Test Suite Overview

### Test Files (19 test modules)

| Test File | What It Tests | Status |
|-----------|---------------|--------|
| `test_validators.py` | Agent name validation rules | ✅ Core |
| `test_lifecycle.py` | Agent registration, rotation, revocation | ✅ Core |
| `test_verify.py` | Certificate verification logic | ✅ Core |
| `test_cert_verification.py` | Certificate verification scenarios | ✅ Core |
| `test_hybrid_certs.py` | Dual certificate architecture (v0.4) | ✅ Phase 4 |
| `test_ra_service.py` | RA service layer (Phase 5) | ✅ Phase 5 |
| `test_ra_workflow.py` | Workflow engine (Phase 5) | ✅ Phase 5 |
| `test_ra_policy.py` | Policy engine (Phase 5) | ✅ Phase 5 |
| `test_ra_renewal.py` | Certificate renewal automation (Phase 5) | ✅ Phase 5 |
| `test_security_hsm.py` | HSM integration framework (Phase 7) | ✅ Phase 7 |
| `test_security_monitoring.py` | Security monitoring (Phase 7) | ✅ Phase 7 |
| `test_input_validation.py` | Input validation and security | ✅ Security |

---

## Testing by Feature/Phase

### 1. Core Functionality Tests

**Agent Name Validation**
```bash
pytest tests/test_validators.py -v
```
- Tests DNS-label format validation
- Tests length constraints (max 63 chars per label, 253 total)
- Tests invalid characters and formats

**Agent Lifecycle**
```bash
pytest tests/test_lifecycle.py -v
```
- Tests agent registration
- Tests certificate rotation
- Tests agent revocation
- Tests status transitions

**Certificate Verification**
```bash
pytest tests/test_verify.py -v
pytest tests/test_cert_verification.py -v
```
- Tests certificate verification logic
- Tests revoked certificate rejection
- Tests expired certificate rejection
- Tests valid certificate acceptance

### 2. Phase 4: Hybrid Certificate Architecture

**Dual Certificate Tests**
```bash
pytest tests/test_hybrid_certs.py -v
```
- Tests private certificate registration
- Tests dual certificate (private + public) registration
- Tests private certificate verification
- Tests public certificate verification

### 3. Phase 5: RA Orchestration

**RA Service Tests**
```bash
pytest tests/test_ra_service.py -v
```
- Tests RA service registration
- Tests RA service certificate rotation
- Tests RA service revocation
- Tests workflow integration

**Workflow Engine Tests**
```bash
pytest tests/test_ra_workflow.py -v
```
- Tests workflow execution
- Tests step success/failure handling
- Tests optional steps
- Tests skip conditions

**Policy Engine Tests**
```bash
pytest tests/test_ra_policy.py -v
```
- Tests policy evaluation
- Tests default rules (name format, max capabilities)
- Tests custom rules
- Tests policy enforcement

**Certificate Renewal Tests**
```bash
pytest tests/test_ra_renewal.py -v
```
- Tests finding expiring certificates
- Tests certificate renewal
- Tests automated renewal workflow
- Tests dry-run mode

### 4. Phase 7: Security Enhancements

**HSM Integration Tests**
```bash
pytest tests/test_security_hsm.py -v
```
- Tests file-based HSM (development)
- Tests HSM key generation
- Tests HSM key storage
- Tests HSM integration framework

**Security Monitoring Tests**
```bash
pytest tests/test_security_monitoring.py -v
```
- Tests security summary generation
- Tests anomaly detection
- Tests event counting
- Tests threshold enforcement

---

## Integration Testing

### End-to-End API Testing

**Start the API Server (in one terminal)**
```bash
# Set up environment variables (optional)
export DATABASE_URL="sqlite:///./atr.db"
export REDIS_URL="redis://localhost:6379/0"

# Run the API server
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

**Run API Tests (in another terminal)**
```bash
# Using curl for manual testing
curl http://localhost:8000/healthz

# Register an agent
curl -X POST http://localhost:8000/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "test-agent.example",
    "owner": "test-owner",
    "capabilities": ["read", "write"]
  }'

# List agents
curl http://localhost:8000/v1/agents

# Verify certificate
curl -X POST http://localhost:8000/v1/verify/cert \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n..."
  }'
```

**Using the CLI Demo**
```bash
python -m atr.cli.demo
```

This runs a complete lifecycle demo:
1. Register agent
2. Verify certificate
3. Rotate certificate
4. Verify new certificate
5. Revoke agent
6. Verify revocation

---

## Manual Testing Checklist

### Core Functionality

- [ ] **Agent Registration**
  - [ ] Register agent with valid name
  - [ ] Register agent with invalid name (should fail)
  - [ ] Register duplicate agent (should fail)
  - [ ] Verify certificate is issued
  - [ ] Verify certificate is valid

- [ ] **Certificate Verification**
  - [ ] Verify valid certificate (should succeed)
  - [ ] Verify revoked certificate (should fail)
  - [ ] Verify expired certificate (should fail)
  - [ ] Verify invalid certificate format (should fail)

- [ ] **Certificate Rotation**
  - [ ] Rotate active agent certificate
  - [ ] Verify old certificate is invalidated
  - [ ] Verify new certificate is valid
  - [ ] Rotate revoked agent (should fail)

- [ ] **Agent Revocation**
  - [ ] Revoke active agent
  - [ ] Verify certificate verification fails
  - [ ] Revoke already revoked agent (should fail)

### Phase 4: Hybrid Certificates

- [ ] **Dual Certificate Registration**
  - [ ] Register agent with private cert only
  - [ ] Register agent with public cert requested
  - [ ] Verify dual certificate type
  - [ ] Verify private certificate works
  - [ ] Verify public certificate works (if enabled)

### Phase 5: RA Orchestration

- [ ] **RA Service**
  - [ ] Register agent via RA service
  - [ ] Rotate certificate via RA service
  - [ ] Revoke agent via RA service
  - [ ] Verify workflow integration

- [ ] **Certificate Renewal**
  - [ ] Create agent with expiring certificate
  - [ ] Run renewal service (dry-run)
  - [ ] Run renewal service (actual renewal)
  - [ ] Verify certificate is renewed

- [ ] **Policy Engine**
  - [ ] Register agent with valid capabilities
  - [ ] Register agent with too many capabilities (should fail)
  - [ ] Register agent with invalid name (should fail)
  - [ ] Verify policy enforcement

### Phase 7: Security

- [ ] **Security Monitoring**
  - [ ] Generate security summary
  - [ ] Test anomaly detection
  - [ ] Verify event counting
  - [ ] Verify threshold enforcement

- [ ] **Rate Limiting**
  - [ ] Test rate limiting on API endpoints
  - [ ] Verify rate limit headers
  - [ ] Test per-domain rate limiting (if enabled)

---

## Performance Testing

### Load Testing (Basic)

**Using Apache Bench (ab)**
```bash
# Install ab (if not installed)
# macOS: brew install httpd
# Ubuntu: sudo apt-get install apache2-utils

# Test verification endpoint
ab -n 1000 -c 10 -p cert.json -T application/json \
  http://localhost:8000/v1/verify/cert
```

**Using curl with timing**
```bash
# Time a single verification
curl -w "\nTime: %{time_total}s\n" -X POST \
  http://localhost:8000/v1/verify/cert \
  -H "Content-Type: application/json" \
  -d @cert.json
```

### Performance Benchmarks

**Target Metrics (from Product Plan):**

| Release | Verification Latency (p95) | Throughput | Uptime |
|---------|---------------------------|------------|--------|
| v0.2 | <200ms | 1K QPS | 99% |
| v0.4 | <100ms | 5K QPS | 99.7% |
| v0.5 | <50ms | 10K+ QPS | 99.9% |
| v1.0 | <50ms (p99) | 50K+ QPS | 99.99% |

---

## Security Testing

### Input Validation Tests

```bash
pytest tests/test_input_validation.py -v
```

**Manual Security Checks:**
- [ ] Test SQL injection (should be prevented by ORM)
- [ ] Test XSS in agent names (should be sanitized)
- [ ] Test certificate format validation
- [ ] Test rate limiting enforcement
- [ ] Test API key authentication (if enabled)

### Certificate Security

- [ ] Verify certificate chain validation
- [ ] Verify fingerprint matching
- [ ] Verify revocation enforcement
- [ ] Verify expiration checking
- [ ] Test certificate tampering detection

---

## Database Testing

### Database Setup

```bash
# SQLite (default, no setup needed)
# Database file: atr.db (created automatically)

# PostgreSQL (optional)
# Set DATABASE_URL environment variable
export DATABASE_URL="postgresql://user:password@localhost/atr"

# Run migrations (if needed)
python migrations/add_hybrid_cert_columns.py
```

### Database Integrity

- [ ] Test database schema creation
- [ ] Test foreign key constraints
- [ ] Test unique constraints (agent_name)
- [ ] Test audit log integrity
- [ ] Test certificate serial number indexing

---

## CI/CD Testing (Future)

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run tests
        run: |
          pytest --cov=atr --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

---

## Test Coverage

### Generate Coverage Report

```bash
# Install coverage tool
pip install pytest-cov

# Run tests with coverage
pytest --cov=atr --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

### Coverage Targets

- **Core modules:** >90% coverage
- **API routes:** >80% coverage
- **PKI modules:** >85% coverage
- **RA modules:** >80% coverage
- **Security modules:** >75% coverage

---

## Debugging Failed Tests

### Run Single Test

```bash
# Run specific test file
pytest tests/test_lifecycle.py::test_register_agent -v

# Run specific test function
pytest tests/test_lifecycle.py::test_register_agent::test_basic_registration -v

# Run with debugging output
pytest tests/test_lifecycle.py -v -s --pdb
```

### Common Issues

**Issue: Database locked**
```bash
# Solution: Ensure no other process is using the database
# Or use in-memory database for tests (already configured)
```

**Issue: Certificate validation fails**
```bash
# Solution: Check certificate format and validity period
# Ensure CA certificates are properly initialized
```

**Issue: Redis connection fails**
```bash
# Solution: Ensure Redis is running, or disable Redis caching
export REDIS_ENABLED=false
```

---

## Testing Best Practices

1. **Isolation:** Each test should be independent and not rely on other tests
2. **Cleanup:** Tests should clean up after themselves (use fixtures)
3. **Deterministic:** Tests should produce consistent results
4. **Fast:** Unit tests should run quickly (<1s per test)
5. **Comprehensive:** Cover happy path, error cases, and edge cases
6. **Documentation:** Test names should clearly describe what is tested

---

## Quick Test Commands Reference

```bash
# Run all tests
pytest -v

# Run specific test file
pytest tests/test_lifecycle.py -v

# Run with coverage
pytest --cov=atr --cov-report=term

# Run with verbose output and print statements
pytest -v -s

# Run only failed tests
pytest --lf

# Run tests matching pattern
pytest -k "registration" -v

# Run tests in parallel (if pytest-xdist installed)
pytest -n auto

# Run with performance profiling (if pytest-profiling installed)
pytest --profile

# Run with HTML report
pytest --html=report.html --self-contained-html
```

---

## Next Steps

1. **Run all tests:** `pytest -v`
2. **Check coverage:** `pytest --cov=atr --cov-report=term`
3. **Run manual tests:** Use the CLI demo and API endpoints
4. **Review failing tests:** Fix any issues and re-run
5. **Update tests:** Add tests for new features as they're developed

---

## Resources

- **Test Files:** `tests/` directory
- **Examples:** `examples/` directory
- **CLI Demo:** `python -m atr.cli.demo`
- **API Docs:** `http://localhost:8000/docs` (when server is running)
- **Product Plan:** `PRODUCT_PLAN.md`
- **Implementation Plan:** `IMPLEMENTATION_PLAN.md`
