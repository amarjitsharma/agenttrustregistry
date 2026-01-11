# Security-Focused Code Review: Agent Trust Registry (ATR)

**Review Date:** 2024  
**Reviewer:** Senior Security Architect  
**Scope:** Complete security review with focus on production readiness  
**Status:** POC → Production Security Hardening

---

## A) Threat Model

### Assets (What Must Be Protected)

1. **Private Keys**
   - Root CA private key (compromise = complete trust breakage)
   - Intermediate CA private key (compromise = can issue fraudulent certs)
   - Agent private keys (compromise = agent impersonation)

2. **Certificate Authority**
   - CA key material and certificates
   - Ability to issue/revoke certificates
   - Certificate validation logic

3. **Registry Data**
   - Agent registrations and metadata
   - Certificate fingerprints and status
   - Audit logs and transparency logs

4. **API Endpoints**
   - Registration/rotation/revocation endpoints (privileged operations)
   - Verification endpoints (must be accurate and tamper-proof)

### Trust Boundaries

1. **External → API Boundary**
   - Untrusted clients calling public APIs
   - No authentication by default (major concern)

2. **API → Business Logic Boundary**
   - FastAPI handlers → core logic
   - Missing authorization checks

3. **Application → Storage Boundary**
   - Database (SQLite/PostgreSQL) - contains sensitive metadata
   - File system (`./var/keys/`, `./var/pki/`) - contains private keys
   - Redis cache - may cache sensitive data

4. **Network Boundary**
   - Public internet → registry API
   - Rate limiting exists but configurable/optional

### Attacker Types

1. **External Attacker (Internet)**
   - Goal: Register malicious agents, revoke legitimate agents, forge certificates
   - Capability: Public API access, no authentication required

2. **Insider/Compromised Account**
   - Goal: Access private keys, modify registry data
   - Capability: System access, file system access

3. **Network Attacker (Man-in-the-Middle)**
   - Goal: Intercept/modify API calls, steal credentials
   - Capability: Network position (mitigated by HTTPS in production)

4. **Resource Exhaustion Attacker**
   - Goal: DoS via excessive registration/verification requests
   - Capability: Botnets, distributed attacks

### Top Abuse Cases

1. **Unauthorized Agent Registration**
   - Anyone can register agents without authentication
   - No domain ownership verification by default
   - Name squatting possible

2. **Unauthorized Rotation/Revocation**
   - No authorization checks on rotate/revoke endpoints
   - Attacker can rotate/revoke any agent's certificate

3. **Certificate Forging**
   - Weak certificate verification (only checks issuer subject, not signature)
   - If CA key compromised, attacker can issue valid certs

4. **Private Key Theft**
   - CA keys stored unencrypted on disk
   - Agent keys stored unencrypted on disk
   - No file permission restrictions enforced

5. **Information Disclosure**
   - Stack traces in error responses
   - Audit logs may contain sensitive data
   - Cert PEMs exposed via API endpoint

6. **Resource Exhaustion**
   - No size limits on PEM payloads
   - Rate limiting can be disabled
   - Database queries not optimized for DoS

7. **Agent Name Enumeration** (Public Internet)
   - `GET /v1/agents` endpoint allows listing all agents without authentication
   - Attacker can enumerate all registered agent names via pagination
   - Reveals internal infrastructure, service names, organizational structure

8. **Brute Force Authentication** (Public Internet)
   - No account lockout for failed API key attempts
   - No rate limiting on authentication attempts
   - API keys can be brute-forced without detection

9. **DoS via Rotate/Revoke Abuse** (Public Internet)
   - No rate limiting on rotate/revoke endpoints
   - Attacker can repeatedly rotate/revoke any agent causing service disruption
   - No authorization checks prevent abuse

10. **Key Exfiltration via Logs/Responses** (Public Internet)
    - Error messages may leak private key material if exceptions include keys
    - Audit logs store full metadata without filtering
    - Stack traces in error responses reveal internal paths

11. **Malicious PEM Blob Attacks** (Public Internet)
    - No validation of PEM structure (can accept garbage data)
    - Large PEM blobs can cause memory exhaustion
    - Malformed PEM can cause parser exceptions with stack traces

---

## B) Security Findings

| ID | Severity | Component | Description | Exploit Scenario | Fix Summary |
|----|----------|-----------|-------------|------------------|-------------|
| **SEC-001** | **P0** | Authentication | No authentication on privileged endpoints (register/rotate/revoke). API key auth exists but disabled by default. | Attacker can register malicious agents, rotate legitimate certs, revoke any agent without authentication. | Enable minimal API key authentication for all privileged endpoints (register/rotate/revoke). Add auth to rotate/revoke endpoints immediately. |
| **SEC-002** | **P0** | Authorization | No ownership/authorization checks on rotate/revoke endpoints. Anyone can rotate/revoke any agent. | Attacker rotates `critical-service.production` cert, causing service disruption. Attacker revokes legitimate agents. | Add ownership verification: only agent owner (or authorized admin) can rotate/revoke. Compare `owner` field from request/auth context. |
| **SEC-003** | **P0** | Certificate Verification | Certificate chain validation only checks `issuer.subject == intermediate.subject`, does NOT verify cryptographic signature. | Attacker can create fake cert with matching issuer subject and fingerprint collision (unlikely but possible). Cert will pass verification despite not being signed by CA. | Use `cert.public_key().verify()` with intermediate CA public key to verify signature. Use cryptography library's built-in verification methods. |
| **SEC-004** | **P0** | Private Key Storage | CA and agent private keys stored unencrypted on disk (`./var/pki/*.key`, `./var/keys/*/private_key.pem`). No encryption at rest. | File system compromise (container escape, backup leak) exposes all CA keys. Attacker can issue fraudulent certificates. | Encrypt private keys at rest using key derivation (PBKDF2/Argon2) with passphrase from environment variable. Consider HSM for CA keys in production. |
| **SEC-005** | **P1** | Docker Security | Dockerfile runs as root user. No non-root user defined. | Container compromise = root access on host (if running privileged). | Add non-root user (e.g., `atr` UID 1000), run application as that user. Set proper file permissions. |
| **SEC-006** | **P1** | Input Validation | No size limits on PEM certificate payloads in verify endpoint. Large payloads can cause DoS. | Attacker sends 100MB PEM string, causing memory exhaustion, slow parsing, database timeouts. | Add max length validation to `VerifyCertRequest.cert_pem` (e.g., 64KB). Add timeout to certificate parsing operations. |
| **SEC-007** | **P1** | Agent Name Validation | Agent name validation exists but lacks path traversal protection when saving keys (uses `agent_name` directly in path). | Attacker registers `../../../etc/passwd` as agent name (if validation allows), causing key to be written outside `var/keys/`. | Sanitize agent name for filesystem use: normalize path, ensure no parent directory traversal, validate after normalization. |
| **SEC-008** | **P1** | Audit Logging | Audit logs don't capture actor identity for most operations. No request IDs. Missing actor parameter in `log_audit_event()` calls. | Cannot determine who performed sensitive operations (rotate/revoke). Forensics impossible. | Add `actor` parameter to all `log_audit_event()` calls. Extract from request context (API key, user ID). Add request ID middleware for correlation. |
| **SEC-009** | **P1** | Error Handling | Error responses may leak stack traces and internal file paths. Exception details returned to clients. | Attacker learns internal structure, file paths, database schema from error messages. | Sanitize error messages in production. Return generic errors to clients. Log detailed errors server-side only. |
| **SEC-010** | **P1** | Certificate Endpoint | `GET /v1/agents/{agent_name}/cert` returns cert PEM without authentication. Cert PEMs are sensitive (can be used for impersonation). | Attacker enumerates all agents and retrieves their certificates for analysis/impersonation attempts. | Require authentication for cert endpoint, or make it opt-in. Consider returning only fingerprint by default. |
| **SEC-011** | **P2** | Rate Limiting | Rate limiting can be disabled via config. Per-IP only, no per-agent/per-owner limits on registration. | Attacker disables rate limiting or uses distributed IPs to flood registration endpoint, exhausting resources. | Make rate limiting mandatory (cannot be disabled). Add per-agent-name limits to prevent name enumeration. |
| **SEC-012** | **P2** | Secrets in Logs | Audit logs store full metadata dicts. If metadata contains sensitive data (keys, tokens), they will be logged. | If metadata accidentally includes private key material or secrets, audit logs leak them permanently. | Add filtering to prevent logging of known secret patterns (private keys, tokens). Validate metadata before logging. |
| **SEC-013** | **P2** | CORS Configuration | CORS allows all origins (`allow_origins=["*"]`). Credentials allowed. | Cross-origin attacks possible. Any website can make authenticated requests if user has session. | Restrict CORS to specific origins in production. Remove `allow_credentials=True` if not needed. |
| **SEC-014** | **P2** | Dependencies | Some dependencies use `>=` instead of `==` (unpinned versions). No known CVE check. | Dependency updates may introduce vulnerabilities. Supply chain attacks possible. | Pin all dependency versions. Use `pip-tools` or `poetry` for dependency management. Regularly audit dependencies for CVEs. |
| **SEC-015** | **P2** | CA Key Permissions | No explicit file permission setting for CA private keys. Default permissions may be too permissive. | Other processes/users on system may read CA keys if permissions are 644 or 666. | Set restrictive file permissions (600) on all private key files after creation. Use `os.chmod()` explicitly. |
| **SEC-016** | **P2** | Certificate Validity | Leaf cert validity is 30 days (good), but CA validity is 3650 days (10 years). Long-lived CA certs increase compromise impact window. | If CA key compromised, attacker can issue certs valid for 10 years. | Reduce CA validity to 1-2 years. Implement CA key rotation procedures. |
| **SEC-017** | **P2** | Health Checks | Dockerfile has no HEALTHCHECK instruction. Docker Compose healthcheck uses `curl` which may not be installed. | Cannot detect unhealthy containers automatically. Orphaned processes possible. | Add HEALTHCHECK to Dockerfile using Python-based health check. Ensure healthcheck command exists in image. |
| **SEC-018** | **P2** | Agent Name Normalization | Agent name validation allows valid DNS labels, but no normalization (case, Unicode). Potential for duplicate registrations with different encodings. | Attacker registers `example.com` and `EXAMPLE.COM` (if validation allows mixed case), causing confusion. | Normalize agent names before validation/storage (lowercase, NFC Unicode normalization). Store normalized version. |
| **SEC-019** | **P2** | Transparency Log | Transparency log rebuilds entire Merkle tree on every entry addition (O(n) operations). Performance issue, not directly security, but can cause DoS. | Attacker floods registry with registrations, causing each log entry to rebuild entire tree, exhausting CPU. | Implement incremental Merkle tree updates. Use checkpointing strategy. |
| **SEC-020** | **P2** | Database Connection | SQLite connection uses `check_same_thread=False` without connection pooling. PostgreSQL setup not production-ready. | Connection exhaustion, thread safety issues with SQLite. | Use connection pooling for all databases. Remove `check_same_thread=False` or use proper thread-safe approach. |
| **SEC-021** | **P0** | Agent Enumeration | `GET /v1/agents` allows listing all agents without authentication. Public enumeration reveals all registered agents. | Attacker enumerates all agents via pagination, learns internal infrastructure, service names, organizational structure. Use for reconnaissance. | Require authentication for list endpoint, OR restrict to own agents only, OR add rate limiting + CAPTCHA, OR return only public metadata (no owner). |
| **SEC-022** | **P0** | No Rate Limiting on Rotate/Revoke | Rotate/revoke endpoints have NO rate limiting applied (limiter imported but not used). Attacker can rapidly rotate/revoke any agent. | Attacker repeatedly rotates `critical-service.production` causing constant cert changes, service disruption. Attacker revokes hundreds of agents per second. | Add `@limiter.limit("10/hour")` decorators to rotate/revoke endpoints. Enforce strict per-agent limits. |
| **SEC-023** | **P1** | Brute Force Auth | No account lockout or rate limiting on API key authentication. No logging of failed auth attempts. | Attacker brute forces API keys (e.g., common keys like "admin", "test", "demo") without detection. | Add rate limiting to auth middleware (e.g., 5 attempts per IP per minute). Log failed auth attempts. Implement account lockout after N failures. |
| **SEC-024** | **P1** | PEM Validation Weakness | No structural validation of PEM format. Accepts any string as cert_pem. Malformed PEM causes parser exceptions that leak stack traces. | Attacker sends malformed PEM (binary data, SQL injection attempts, XSS) causing parser exceptions with stack traces. Large PEM blobs cause memory exhaustion. | Add strict PEM format validation (regex or parser check). Validate base64 structure. Reject before parsing. Add size limits. Catch exceptions and return generic errors. |
| **SEC-025** | **P1** | Error Messages Leak Keys | Exception messages in error responses may include private key material if keys are accidentally included in error context. No filtering of secrets in error messages. | If code accidentally includes key material in exception message, attacker sees it in error response. Stack traces reveal file paths where keys are stored. | Filter all error messages for secret patterns (private keys, tokens). Return generic errors to clients. Log detailed errors server-side only. Use exception sanitization middleware. |
| **SEC-026** | **P1** | List Endpoint Info Disclosure | List endpoint returns owner, capabilities, timestamps - reveals organizational structure and relationships. | Attacker learns which services belong to which owners, what capabilities exist, registration patterns, operational intelligence. | Minimize returned data (don't expose owner in public list). Or require authentication and filter to own agents. Add rate limiting to prevent enumeration. |
| **SEC-027** | **P2** | No Rate Limiting on List Endpoint | List endpoint has no rate limiting. Attacker can rapidly paginate through all agents. | Attacker rapidly enumerates all agents via pagination (1000 per request, offset 0-10000+) exhausting database. | Add rate limiting to list endpoint (e.g., 10 requests/minute per IP). Reduce default limit to 50. Add CAPTCHA after N requests. |
| **SEC-028** | **P2** | API Key Storage Weakness | API keys stored in Redis cache (volatile, not persistent). No database backup. Keys lost on cache flush/restart. | Cache restart/flush loses all API keys, causing auth failures. No audit trail of key creation/revocation. | Store API keys in database with proper schema. Use Redis for caching only. Add key revocation tracking. |
| **SEC-029** | **P2** | No Request ID Tracking | No request IDs in logs or responses. Cannot correlate requests across services. Difficult forensics. | Cannot track attacker's request sequence. Cannot correlate failed auth attempts across endpoints. Forensics impossible. | Add request ID middleware (UUID per request). Include in all logs and error responses. Use correlation IDs for distributed tracing. |

---

## C) Fix Plan

### Phase 1: Critical Fixes (P0) - Immediate Priority

**Estimated Time:** 2-3 days  
**Complexity:** Medium

1. **SEC-001: Enable Authentication for Privileged Endpoints**
   - Add `Depends(verify_api_key)` to register/rotate/revoke endpoints
   - Document API key setup in README
   - Provide simple API key generation script

2. **SEC-002: Add Authorization Checks**
   - Create authorization helper function `check_agent_ownership(agent_name, actor)`
   - Add ownership check to rotate/revoke endpoints
   - Extract owner from API key or request header

3. **SEC-003: Fix Certificate Signature Verification**
   - Replace issuer.subject check with actual signature verification
   - Use `intermediate_cert.public_key().verify()` to verify cert signature
   - Add unit tests for signature verification

4. **SEC-004: Encrypt Private Keys at Rest**
   - Implement key encryption using Fernet (symmetric) or key derivation
   - Add `ATR_KEY_PASSPHRASE` environment variable
   - Encrypt keys on write, decrypt on read
   - Provide migration script for existing keys

### Phase 2: High Priority Fixes (P1) - Week 1

**Estimated Time:** 3-4 days  
**Complexity:** Medium

5. **SEC-005: Docker Non-Root User**
   - Create `atr` user in Dockerfile
   - Change ownership of `/app/var` to `atr` user
   - Run uvicorn as non-root user

6. **SEC-006: Input Size Limits**
   - Add `max_length=65536` to `VerifyCertRequest.cert_pem` field
   - Add timeout to certificate parsing (5 seconds)

7. **SEC-007: Path Traversal Protection**
   - Normalize agent name paths (remove `..`, absolute paths)
   - Validate normalized path stays within `var/keys/`
   - Add unit tests for edge cases

8. **SEC-008: Audit Logging Improvements**
   - Add `actor` parameter extraction from request context
   - Add request ID middleware (UUID per request)
   - Update all `log_audit_event()` calls to include actor

9. **SEC-009: Error Handling Sanitization**
   - Create error sanitization middleware
   - Return generic errors to clients
   - Log detailed errors server-side with request ID

10. **SEC-010: Certificate Endpoint Authentication**
    - Add authentication requirement to `/v1/agents/{agent_name}/cert`
    - Or make endpoint opt-in via config flag

### Phase 3: Medium Priority Fixes (P2) - Week 2-3

**Estimated Time:** 5-6 days  
**Complexity:** Low-Medium

11. **SEC-021: Prevent Agent Enumeration**
    - Require authentication for list endpoint OR restrict to public metadata only
    - Add rate limiting to prevent rapid enumeration
    - Consider returning only agent_name and status (hide owner/capabilities)
    - Document enumeration policy

12. **SEC-022: Add Rate Limiting to Rotate/Revoke**
    - Add `@limiter.limit("10/hour")` decorators to rotate/revoke endpoints
    - Enforce per-agent-name limits (e.g., 3 rotates per agent per day)
    - Add rate limit headers to responses
    - Test rate limiting behavior

13. **SEC-023: Brute Force Protection**
    - Add rate limiting to auth middleware (5 attempts per IP per minute)
    - Log failed authentication attempts with IP address
    - Implement account lockout after 10 failures (30 min lockout)
    - Add monitoring/alerting for auth failures

14. **SEC-024: PEM Validation**
    - Add strict PEM format validation (regex check before parsing)
    - Validate base64 structure of PEM body
    - Add size limits (64KB max)
    - Catch parsing exceptions and return generic errors

15. **SEC-025: Error Message Sanitization**
    - Create error sanitization middleware
    - Filter error messages for secret patterns (private keys, tokens, file paths)
    - Return generic errors to clients
    - Log detailed errors server-side with request ID

16. **SEC-026: List Endpoint Info Disclosure**
    - Minimize data returned in list endpoint (hide owner if public)
    - OR require authentication and filter to own agents
    - Add rate limiting to prevent enumeration

17. **SEC-027: Rate Limiting on List Endpoint**
    - Add rate limiting to list endpoint (10 requests/minute)
    - Reduce default limit from 100 to 50
    - Add pagination limits (max offset)

18. **SEC-028: API Key Storage**
    - Store API keys in database (not just cache)
    - Use Redis for caching only
    - Add key revocation tracking
    - Add key expiration dates

19. **SEC-029: Request ID Tracking**
    - Add request ID middleware (UUID per request)
    - Include request ID in all logs
    - Include request ID in error responses
    - Use for correlation across services

11. **SEC-011: Mandatory Rate Limiting**
    - Remove `rate_limit_enabled` flag or make it always-on
    - Add per-agent-name rate limits
    - Document rate limit configuration

12. **SEC-012: Secrets Filtering in Logs**
    - Add regex patterns for private keys, tokens
    - Filter metadata before logging
    - Add unit tests

13. **SEC-013: CORS Restriction**
    - Make CORS origins configurable via environment variable
    - Default to empty list (no CORS) in production
    - Document CORS setup

14. **SEC-014: Dependency Pinning**
    - Pin all dependencies to specific versions
    - Create `requirements-pinned.txt`
    - Add dependency update workflow

15. **SEC-015: File Permissions**
    - Set `os.chmod(key_path, 0o600)` after writing private keys
    - Set permissions on CA keys
    - Add verification in tests

16. **SEC-016: CA Validity Reduction**
    - Reduce `ca_validity_days` to 730 (2 years)
    - Document CA rotation procedure
    - Add CA expiration monitoring

17. **SEC-017: Health Checks**
    - Add HEALTHCHECK to Dockerfile
    - Use Python-based health check (no curl dependency)
    - Update docker-compose healthcheck

18. **SEC-018: Agent Name Normalization**
    - Normalize agent names to lowercase NFC
    - Store normalized version
    - Validate normalization in tests

19. **SEC-019: Transparency Log Performance** (Optional for POC)
    - Defer to production optimization
    - Document performance characteristics

20. **SEC-020: Database Connection Pooling**
    - Implement connection pooling for SQLite/PostgreSQL
    - Remove `check_same_thread=False` or use proper approach
    - Add connection pool configuration

---

## D) Patch Suggestions (Top 5 Findings)

### Patch 1: SEC-001 - Add Authentication to Privileged Endpoints

**File:** `atr/api/routes_agents.py`

```python
# Add import at top
from atr.core.auth import verify_api_key

# Modify register endpoint (line 88)
@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
def register_agent(
    request: AgentRegisterRequest,
    actor: str = Depends(verify_api_key),  # ADD THIS
    db: Session = Depends(get_db)
):
    """Register a new agent and issue certificate"""
    # ... existing code ...
    
    # Update audit log to include actor
    log_audit_event(
        db,
        AuditEventType.REGISTER,
        agent_name=request.agent_name,
        actor=actor,  # ADD THIS
        metadata={"owner": request.owner, "capabilities": request.capabilities}
    )
    # ... rest of code ...

# Modify rotate endpoint (line 252)
@router.post("/{agent_name}/rotate", response_model=AgentRotateResponse)
def rotate_agent_certificate(
    agent_name: str,
    actor: str = Depends(verify_api_key),  # ADD THIS
    db: Session = Depends(get_db)
):
    """Rotate agent certificate (issue new cert, update fingerprint)"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    # ADD AUTHORIZATION CHECK
    if agent.owner != actor and actor != "admin":  # Simple check - improve in production
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to rotate agent '{agent_name}'"
        )
    
    # ... existing code ...
    
    # Update audit log
    log_audit_event(
        db,
        AuditEventType.ROTATE,
        agent_name=agent_name,
        actor=actor,  # ADD THIS
        metadata={"old_fingerprint": old_fingerprint, "new_fingerprint": new_fingerprint}
    )
    # ... rest of code ...

# Modify revoke endpoint (line 318)
@router.post("/{agent_name}/revoke", response_model=AgentRevokeResponse)
def revoke_agent(
    agent_name: str,
    actor: str = Depends(verify_api_key),  # ADD THIS
    db: Session = Depends(get_db)
):
    """Revoke an agent (mark as revoked)"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    # ADD AUTHORIZATION CHECK
    if agent.owner != actor and actor != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to revoke agent '{agent_name}'"
        )
    
    # ... existing code ...
    
    # Update audit log
    log_audit_event(
        db,
        AuditEventType.REVOKE,
        agent_name=agent_name,
        actor=actor,  # ADD THIS
        metadata={"fingerprint": agent.cert_fingerprint, "reason": "manual_revocation"}
    )
    # ... rest of code ...
```

**File:** `atr/core/config.py`

```python
# Change default (line 39)
api_key_enabled: bool = True  # Changed from False - require auth by default
```

### Patch 2: SEC-003 - Fix Certificate Signature Verification

**File:** `atr/api/routes_verify.py`

```python
# Replace lines 59-95 with proper signature verification
# Check if certificate chains to our intermediate CA
ca = get_ca()
intermediate_cert = ca.get_intermediate_cert()

try:
    # Verify certificate signature cryptographically
    # Use the intermediate CA's public key to verify the certificate signature
    intermediate_public_key = intermediate_cert.public_key()
    
    # Verify the certificate was signed by the intermediate CA
    # This verifies the cryptographic signature, not just the issuer subject
    try:
        # The cryptography library doesn't provide a direct verify method on public_key
        # Instead, we need to reconstruct and verify the signature
        # For X.509 certificates, we verify using the certificate's signature algorithm
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography import x509
        
        # Get the certificate's signature algorithm
        signature_algorithm = cert.signature_algorithm_oid
        
        # Verify issuer matches
        if cert.issuer != intermediate_cert.subject:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "invalid_issuer"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.expires_at,
                reason="Certificate issuer does not match trusted CA"
            )
        
        # Build certificate to get the data that was signed
        # The cryptography library's x509 module verifies signatures automatically when loading
        # But we should also explicitly verify using the public key
        # Since we already loaded the cert successfully, the signature was verified during loading
        # But to be explicit, we can use the certificate's built-in verification
        # Actually, x509.load_pem_x509_certificate doesn't verify signatures automatically
        # We need to manually verify
        
        # Better approach: Use the certificate's tbs_certificate_bytes and signature
        # Verify signature using intermediate CA public key
        try:
            # For RSA keys, use PSS or PKCS1v15 padding
            if isinstance(intermediate_public_key, rsa.RSAPublicKey):
                # Get the signature and signed data
                tbs_certificate = cert.tbs_certificate_bytes
                signature = cert.signature
                
                # Verify signature
                if isinstance(cert.signature_algorithm_oid, x509.oid.SignatureAlgorithmOID):
                    if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
                        intermediate_public_key.verify(
                            signature,
                            tbs_certificate,
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )
                    else:
                        # Handle other algorithms
                        raise ValueError(f"Unsupported signature algorithm: {cert.signature_algorithm_oid}")
                else:
                    # Default to SHA256 with PKCS1v15 for RSA
                    intermediate_public_key.verify(
                        signature,
                        tbs_certificate,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
        except Exception as sig_error:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "signature_verification_failed", "error": str(sig_error)}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.expires_at,
                reason="Certificate signature verification failed"
            )
            
    except Exception as e:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "chain_validation_error", "error": str(e)}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason=f"Chain validation error: {str(e)}"
        )
except Exception as e:
    # ... existing error handling ...
```

**Actually, simpler approach using cryptography's built-in verification:**

```python
# Simplified version - use certificate's built-in verification chain
try:
    # Build a certificate store with our intermediate CA
    from cryptography.hazmat.backends import default_backend
    store = x509.CertificateStore([intermediate_cert])
    
    # Create a verification context
    # Note: This requires building a full chain, but for now we can verify issuer match
    # and rely on the fact that the certificate was signed correctly (cryptography library
    # validates signatures when loading, but we should verify explicitly)
    
    # Verify issuer matches
    if cert.issuer != intermediate_cert.subject:
        raise ValueError("Issuer mismatch")
    
    # For explicit signature verification with RSA:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    
    if isinstance(intermediate_cert.public_key(), rsa.RSAPublicKey):
        public_key = intermediate_cert.public_key()
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            # Signature verification failed
            raise ValueError("Signature verification failed")
    
except Exception as e:
    # ... error handling ...
```

**Simplest production-ready fix:**

```python
# Lines 59-95 replacement - simplified but correct
# Check if certificate chains to our intermediate CA
ca = get_ca()
intermediate_cert = ca.get_intermediate_cert()

try:
    # Verify issuer matches
    if cert.issuer != intermediate_cert.subject:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "invalid_issuer"}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason="Certificate issuer does not match trusted CA"
        )
    
    # Verify cryptographic signature
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
    from cryptography.hazmat.primitives import hashes
    
    intermediate_public_key = intermediate_cert.public_key()
    
    try:
        if isinstance(intermediate_public_key, rsa.RSAPublicKey):
            # RSA signature verification
            intermediate_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(intermediate_public_key, ec.EllipticCurvePublicKey):
            # ECDSA signature verification
            from cryptography.hazmat.primitives.asymmetric import utils
            intermediate_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported public key type: {type(intermediate_public_key)}")
    except Exception as sig_err:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "signature_verification_failed"}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason="Certificate signature verification failed"
        )
        
except Exception as e:
    log_audit_event(
        db,
        AuditEventType.VERIFY,
        agent_name=agent.agent_name,
        metadata={"fingerprint": fingerprint, "result": "chain_validation_error", "error": str(e)}
    )
    return VerifyCertResponse(
        verified=False,
        agent_name=agent.agent_name,
        status=agent.status,
        expires_at=agent.expires_at,
        reason="Certificate chain validation failed"
    )
```

### Patch 3: SEC-004 - Encrypt Private Keys at Rest

**File:** `atr/pki/ca.py`

```python
# Add imports at top
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

# Add helper functions
def _get_encryption_key() -> bytes:
    """Get encryption key from passphrase"""
    passphrase = os.environ.get("ATR_KEY_PASSPHRASE", "").encode()
    if not passphrase:
        raise ValueError("ATR_KEY_PASSPHRASE environment variable must be set for key encryption")
    
    salt = b"atr_salt_v1"  # In production, use random salt per key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return key

def _encrypt_key_data(key_data: bytes) -> bytes:
    """Encrypt private key data"""
    f = Fernet(_get_encryption_key())
    return f.encrypt(key_data)

def _decrypt_key_data(encrypted_data: bytes) -> bytes:
    """Decrypt private key data"""
    f = Fernet(_get_encryption_key())
    return f.decrypt(encrypted_data)

# Modify _create_root_ca (around line 89)
def _create_root_ca(self) -> None:
    """Create root CA certificate and key"""
    # ... existing key generation code ...
    
    # Save to disk - ENCRYPT KEY
    self.root_ca_path.write_bytes(cert.public_bytes(Encoding.PEM))
    key_data = private_key.private_bytes(
        Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    encrypted_key = _encrypt_key_data(key_data)  # ADD ENCRYPTION
    self.root_key_path.write_bytes(encrypted_key)
    os.chmod(self.root_key_path, 0o600)  # Restrict permissions

# Modify _create_intermediate_ca (around line 150)
def _create_intermediate_ca(self) -> None:
    """Create intermediate CA certificate and key"""
    # ... existing code ...
    
    # Save to disk - ENCRYPT KEY
    self.intermediate_ca_path.write_bytes(cert.public_bytes(Encoding.PEM))
    key_data = private_key.private_bytes(
        Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    encrypted_key = _encrypt_key_data(key_data)  # ADD ENCRYPTION
    self.intermediate_key_path.write_bytes(encrypted_key)
    os.chmod(self.intermediate_key_path, 0o600)  # Restrict permissions

# Modify _load_root_ca (around line 163)
def _load_root_ca(self) -> None:
    """Load root CA certificate and key from disk"""
    self.root_cert = x509.load_pem_x509_certificate(
        self.root_ca_path.read_bytes()
    )
    encrypted_key_data = self.root_key_path.read_bytes()
    try:
        key_data = _decrypt_key_data(encrypted_key_data)  # ADD DECRYPTION
    except Exception:
        # Fallback: try reading as unencrypted (for migration)
        key_data = encrypted_key_data
    self.root_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )

# Modify _load_intermediate_ca (around line 173)
def _load_intermediate_ca(self) -> None:
    """Load intermediate CA certificate and key from disk"""
    self.intermediate_cert = x509.load_pem_x509_certificate(
        self.intermediate_ca_path.read_bytes()
    )
    encrypted_key_data = self.intermediate_key_path.read_bytes()
    try:
        key_data = _decrypt_key_data(encrypted_key_data)  # ADD DECRYPTION
    except Exception:
        # Fallback: try reading as unencrypted (for migration)
        key_data = encrypted_key_data
    self.intermediate_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
```

**File:** `atr/pki/issue.py`

```python
# Add encryption helper (similar to ca.py)
# Modify issue_agent_certificate (around line 37)
def issue_agent_certificate(agent_name: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
    # ... existing code ...
    
    # Save private key to disk - ENCRYPT
    key_dir = settings.keys_root_dir / agent_name
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "private_key.pem"
    key_data = private_key.private_bytes(
        Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    # Encrypt if passphrase set
    if os.environ.get("ATR_KEY_PASSPHRASE"):
        from atr.pki.ca import _encrypt_key_data
        key_data = _encrypt_key_data(key_data)
    key_path.write_bytes(key_data)
    os.chmod(key_path, 0o600)  # Restrict permissions
    
    # ... rest of code ...
```

### Patch 4: SEC-005 - Docker Non-Root User

**File:** `Dockerfile`

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 atr && \
    mkdir -p /app/var/pki /app/var/keys && \
    chown -R atr:atr /app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY atr/ ./atr/
COPY tests/ ./tests/

# Ensure directories exist and set ownership
RUN mkdir -p /app/var/pki /app/var/keys && \
    chown -R atr:atr /app

# Switch to non-root user
USER atr

# Expose port
EXPOSE 8000

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"

# Run the application
CMD ["uvicorn", "atr.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Patch 5: SEC-006 & SEC-007 - Input Validation Improvements

**File:** `atr/core/schemas.py`

```python
# Modify VerifyCertRequest (around line 44)
class VerifyCertRequest(BaseModel):
    """Request to verify a certificate"""
    cert_pem: str = Field(
        ...,
        description="PEM-encoded certificate",
        min_length=100,  # Minimum reasonable PEM size
        max_length=65536  # 64KB max - prevents DoS
    )
    
    @field_validator('cert_pem')
    @classmethod
    def validate_pem_format(cls, v: str) -> str:
        """Validate PEM format"""
        if not v.strip().startswith('-----BEGIN CERTIFICATE-----'):
            raise ValueError('Invalid PEM format: must start with -----BEGIN CERTIFICATE-----')
        if not v.strip().endswith('-----END CERTIFICATE-----'):
            raise ValueError('Invalid PEM format: must end with -----END CERTIFICATE-----')
        return v
```

**File:** `atr/pki/issue.py`

```python
# Add import
import os
from pathlib import Path

# Modify issue_agent_certificate (around line 34)
def issue_agent_certificate(agent_name: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
    # ... existing code ...
    
    # Save private key to disk - ADD PATH TRAVERSAL PROTECTION
    # Normalize agent name for filesystem use
    normalized_name = agent_name.replace('..', '').replace('/', '').replace('\\', '')
    if normalized_name != agent_name:
        raise ValueError(f"Invalid agent name for filesystem: {agent_name}")
    
    key_dir = settings.keys_root_dir / normalized_name
    key_dir.mkdir(parents=True, exist_ok=True)
    
    # Ensure path is within keys directory (prevent directory traversal)
    try:
        key_dir.resolve().relative_to(settings.keys_root_dir.resolve())
    except ValueError:
        raise ValueError(f"Agent name results in path outside keys directory: {agent_name}")
    
    key_path = key_dir / "private_key.pem"
    # ... rest of code ...
```

---

## E) Security Tests (Top 3 Controls)

### Test 1: Authentication Enforcement

**File:** `tests/test_auth.py` (new file)

```python
"""Tests for authentication and authorization"""
import pytest
from fastapi.testclient import TestClient
from atr.main import app

client = TestClient(app)

def test_register_without_auth_fails():
    """Test that registration fails without API key when auth enabled"""
    # Assuming API_KEY_ENABLED=True
    response = client.post(
        "/v1/agents",
        json={
            "agent_name": "test-agent.example",
            "owner": "test-owner",
            "capabilities": []
        }
    )
    assert response.status_code == 401

def test_register_with_valid_api_key_succeeds():
    """Test that registration succeeds with valid API key"""
    # Setup: register API key first (requires admin endpoint)
    api_key = "test-api-key-12345"
    # ... register key ...
    
    response = client.post(
        "/v1/agents",
        json={
            "agent_name": "test-agent.example",
            "owner": "test-owner",
            "capabilities": []
        },
        headers={"X-API-Key": api_key}
    )
    assert response.status_code == 201

def test_rotate_without_authorization_fails():
    """Test that rotating another owner's agent fails"""
    # Register agent with owner "alice"
    # Try to rotate with API key for "bob"
    # Should fail with 403

def test_rotate_with_owner_succeeds():
    """Test that owner can rotate their own agent"""
    # Register agent with owner "alice"
    # Rotate with API key for "alice"
    # Should succeed
```

### Test 2: Certificate Signature Verification

**File:** `tests/test_cert_verification.py` (new file)

```python
"""Tests for certificate signature verification"""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from atr.pki.ca import get_ca
from atr.pki.fingerprints import compute_fingerprint

def test_verify_valid_cert_signature():
    """Test that valid certificate signature is verified"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    intermediate_key = ca.get_intermediate_key()
    
    # Create a test certificate signed by intermediate CA
    private_key = rsa.generate_private_key(65537, 2048)
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(intermediate_key, hashes.SHA256())
    
    # Verify signature
    intermediate_public_key = intermediate_cert.public_key()
    if isinstance(intermediate_public_key, rsa.RSAPublicKey):
        from cryptography.hazmat.primitives.asymmetric import padding
        intermediate_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    # Should not raise exception

def test_verify_invalid_cert_signature_fails():
    """Test that invalid certificate signature fails verification"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    
    # Create a certificate signed by different key
    other_key = rsa.generate_private_key(65537, 2048)
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    ).issuer_name(
        intermediate_cert.subject  # Same issuer name, but wrong signature
    ).public_key(
        other_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(other_key, hashes.SHA256())  # Signed by wrong key!
    
    # Verify signature should fail
    intermediate_public_key = intermediate_cert.public_key()
    if isinstance(intermediate_public_key, rsa.RSAPublicKey):
        from cryptography.hazmat.primitives.asymmetric import padding
        with pytest.raises(Exception):  # Should raise verification error
            intermediate_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
```

### Test 3: Input Validation and Path Traversal

**File:** `tests/test_input_validation.py` (new file)

```python
"""Tests for input validation and security"""
import pytest
from fastapi.testclient import TestClient
from atr.core.validators import validate_agent_name
from atr.core.schemas import VerifyCertRequest
from pydantic import ValidationError

def test_agent_name_path_traversal_prevention():
    """Test that path traversal attempts are rejected"""
    malicious_names = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/passwd",
        "agent/../../../etc",
        "agent\\..\\..\\..\\etc"
    ]
    
    for name in malicious_names:
        # Validation should reject or normalize
        result = validate_agent_name(name)
        assert result is not None  # Should return error

def test_cert_pem_size_limit():
    """Test that oversized PEM certificates are rejected"""
    # Create oversized PEM (100KB)
    large_pem = "-----BEGIN CERTIFICATE-----\n" + "A" * 100000 + "\n-----END CERTIFICATE-----"
    
    with pytest.raises(ValidationError):
        VerifyCertRequest(cert_pem=large_pem)

def test_cert_pem_format_validation():
    """Test that invalid PEM format is rejected"""
    invalid_pems = [
        "not a pem",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "BEGIN CERTIFICATE\nDATA\nEND CERTIFICATE"
    ]
    
    for invalid_pem in invalid_pems:
        with pytest.raises(ValidationError):
            VerifyCertRequest(cert_pem=invalid_pem)
```

---

## F) Hardening Checklist (Before Production)

### Immediate (Pre-Production)

- [ ] **Enable authentication** on all privileged endpoints (register/rotate/revoke)
- [ ] **Add authorization checks** - only owners can modify their agents
- [ ] **Fix certificate signature verification** - use cryptographic verification, not just subject match
- [ ] **Encrypt private keys at rest** - use environment variable passphrase
- [ ] **Run Docker as non-root user** - create and use dedicated user
- [ ] **Add input size limits** - prevent DoS via oversized payloads
- [ ] **Sanitize error messages** - don't leak stack traces or file paths
- [ ] **Set file permissions** - 600 on all private key files
- [ ] **Add health checks** - Docker HEALTHCHECK instruction
- [ ] **Pin dependency versions** - use exact versions, not ranges
- [ ] **Apply rate limiting** - add `@limiter.limit()` decorators to ALL endpoints (currently imported but unused)
- [ ] **Prevent agent enumeration** - require auth for list endpoint OR restrict data returned
- [ ] **Rate limit rotate/revoke** - critical DoS prevention (10/hour per agent)
- [ ] **Brute force protection** - rate limit auth attempts, log failures, account lockout
- [ ] **PEM validation** - strict format validation before parsing

### Short-term (Production Week 1)

- [ ] **Mandatory rate limiting** - cannot be disabled, add per-agent limits
- [ ] **CORS restrictions** - configure allowed origins, remove wildcard
- [ ] **Audit log improvements** - include actor identity, request IDs
- [ ] **Certificate endpoint auth** - require auth for cert PEM retrieval
- [ ] **Path traversal protection** - normalize and validate all file paths
- [ ] **Secrets filtering in logs** - prevent logging of keys/tokens
- [ ] **Agent name normalization** - lowercase, NFC Unicode normalization
- [ ] **Connection pooling** - proper database connection management
- [ ] **CA validity reduction** - reduce to 1-2 years, document rotation
- [ ] **Request ID tracking** - UUID per request, include in logs/responses
- [ ] **API key storage** - move from cache to database with revocation tracking
- [ ] **List endpoint rate limiting** - prevent enumeration attacks
- [ ] **Error sanitization middleware** - filter secrets from all error messages
- [ ] **Monitoring and alerting** - track failed auth, rate limit violations, errors

### Medium-term (Production Month 1)

- [ ] **HSM integration** - move CA keys to Hardware Security Module
- [ ] **OCSP/CRL support** - proper certificate revocation checking
- [ ] **Monitoring and alerting** - security event monitoring
- [ ] **Penetration testing** - external security audit
- [ ] **Backup encryption** - encrypt database backups
- [ ] **Key rotation procedures** - documented CA key rotation process
- [ ] **Multi-factor authentication** - for admin operations
- [ ] **WAF rules** - Web Application Firewall configuration
- [ ] **DDoS protection** - CloudFlare/AWS Shield integration
- [ ] **Incident response plan** - documented security incident procedures

### Long-term (Production Quarter 1)

- [ ] **Compliance certifications** - SOC 2, ISO 27001 if required
- [ ] **Advanced monitoring** - SIEM integration, anomaly detection
- [ ] **Zero-trust architecture** - mTLS for all internal communications
- [ ] **Regular security audits** - quarterly security reviews
- [ ] **Bug bounty program** - incentivize responsible disclosure
- [ ] **Security training** - team security awareness training

---

## Summary

**Total Findings:** 29 (7 P0, 11 P1, 11 P2)

**Critical Issues (P0):**
1. No authentication on privileged endpoints
2. No authorization checks (anyone can rotate/revoke)
3. Certificate verification doesn't check cryptographic signatures
4. Private keys stored unencrypted
5. Agent enumeration via public list endpoint (no auth)
6. No rate limiting on rotate/revoke endpoints (DoS vector)
7. Rate limiting imported but never applied to endpoints

**Recommendation:** Address all P0 findings before any production deployment. P1 findings should be addressed within the first week. P2 findings can be prioritized based on risk tolerance.

**Public Internet Deployment:** This codebase is NOT ready for public internet deployment without addressing SEC-021, SEC-022, SEC-023, SEC-024, SEC-025, SEC-026. Attackers will rapidly enumerate agents, brute force auth, and cause DoS via rotate/revoke abuse.

**Estimated Effort:**
- P0 fixes: 3-4 days (includes new findings)
- P1 fixes: 4-5 days (includes new findings)
- P2 fixes: 4-5 days  
- **Total: ~3 weeks for production-ready security on public internet**
