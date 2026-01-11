# Public Internet Deployment: Additional Security Findings

This document supplements `SECURITY_REVIEW.md` with findings specific to **public internet deployment** scenarios where attackers can:
- Enumerate agent names
- Upload malicious PEM blobs
- Brute force endpoints
- Exploit weak authentication
- Abuse rotate/revoke for DoS
- Attempt key exfiltration via logs/responses

## Additional Findings for Public Internet

### SEC-021: Agent Name Enumeration (P0 - CRITICAL)

**Component:** `atr/api/routes_agents.py:35-85`

**Description:** The `GET /v1/agents` endpoint allows unauthenticated listing of all registered agents with pagination. Attacker can enumerate all agents by iterating through offsets.

**Current Code:**
```python
@router.get("", response_model=AgentListResponse)
def list_agents(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    ...
):
    """List all agents with optional filtering and pagination"""
    # NO AUTHENTICATION REQUIRED
    # NO RATE LIMITING APPLIED
```

**Exploit Scenario:**
```bash
# Attacker enumerates all agents
for offset in {0..10000}; do
  curl "http://registry.example.com/v1/agents?limit=1000&offset=$offset" | jq '.agents[].agent_name'
done

# Learns:
# - All registered agent names
# - Organizational structure (owners)
# - Service capabilities
# - Registration patterns
# - Internal infrastructure layout
```

**Impact:**
- **Reconnaissance:** Attacker learns internal infrastructure
- **Targeting:** Identifies high-value agents for attacks
- **Privacy:** Exposes organizational structure
- **Resource Exhaustion:** Database load from enumeration

**Fix:**
1. **Option A (Recommended):** Require authentication, filter to own agents only
2. **Option B:** Restrict public list to minimal data (agent_name, status only - hide owner/capabilities)
3. **Option C:** Add CAPTCHA after N requests
4. **Option D:** Add strict rate limiting (5 requests/hour per IP) + authentication

**Patch:**
```python
@router.get("", response_model=AgentListResponse)
@limiter.limit("10/minute")  # ADD RATE LIMITING
def list_agents(
    actor: str = Depends(verify_api_key),  # ADD AUTHENTICATION
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=100, description="Maximum number of results"),  # REDUCE DEFAULT
    offset: int = Query(default=0, ge=0, le=1000, description="Pagination offset"),  # MAX OFFSET
    ...
):
    """List agents (restricted to own agents when authenticated)"""
    query = db.query(Agent)
    
    # Filter to own agents if not admin
    if actor != "admin":
        query = query.filter(Agent.owner == actor)
    
    # ... rest of code ...
```

---

### SEC-022: No Rate Limiting on Rotate/Revoke (P0 - CRITICAL)

**Component:** `atr/api/routes_agents.py:252-357`

**Description:** Rotate and revoke endpoints have NO rate limiting applied. Limiter is imported but never used. Attacker can rapidly rotate/revoke any agent causing DoS.

**Current Code:**
```python
limiter = get_rate_limiter()  # Imported but NEVER USED

@router.post("/{agent_name}/rotate", response_model=AgentRotateResponse)
def rotate_agent_certificate(agent_name: str, db: Session = Depends(get_db)):
    # NO RATE LIMITING
    # NO AUTHENTICATION
    # NO AUTHORIZATION
```

**Exploit Scenario:**
```bash
# Attacker causes DoS by rapidly rotating critical service
while true; do
  curl -X POST "http://registry.example.com/v1/agents/critical-service.production/rotate"
  sleep 0.1  # 10 requests/second
done

# Result:
# - Constant certificate changes
# - Service disruption (cert mismatch)
# - Database load
# - CA key wear (if using HSM)
# - Cache invalidation storms
```

**Impact:**
- **DoS:** Service disruption via constant cert rotation
- **Resource Exhaustion:** Database, CA key operations, DNS updates
- **Operational Impact:** Legitimate services cannot maintain stable certs

**Fix:**
1. Add strict rate limiting (10/hour per agent, 5/hour per IP)
2. Add authentication requirement
3. Add authorization checks (owner-only)
4. Add per-agent-name rate limiting

**Patch:**
```python
@router.post("/{agent_name}/rotate", response_model=AgentRotateResponse)
@limiter.limit("10/hour", key_func=lambda: f"rotate:{request.path_params['agent_name']}")  # PER-AGENT LIMIT
@limiter.limit("50/hour")  # PER-IP LIMIT
def rotate_agent_certificate(
    agent_name: str,
    actor: str = Depends(verify_api_key),  # ADD AUTH
    request: Request,  # For rate limiting
    db: Session = Depends(get_db)
):
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_name}' not found")
    
    # ADD AUTHORIZATION CHECK
    if agent.owner != actor and actor != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # ... rest of code ...
```

---

### SEC-023: Brute Force Authentication (P1 - HIGH)

**Component:** `atr/core/auth.py:16-55`

**Description:** No rate limiting on API key authentication. No account lockout. No logging of failed attempts. Attacker can brute force API keys.

**Current Code:**
```python
def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    # NO RATE LIMITING
    # NO LOGGING OF FAILED ATTEMPTS
    # NO ACCOUNT LOCKOUT
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    valid_key = cache.get(f"api_key:{key_hash}")
    
    if not valid_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
        # NO LOGGING
        # NO RATE LIMIT CHECK
```

**Exploit Scenario:**
```python
# Attacker brute forces common API keys
common_keys = ["admin", "test", "demo", "api", "key", "secret", ...]
for key in common_keys:
    for variant in [key, key.upper(), key + "123", ...]:
        response = requests.get(
            "http://registry.example.com/v1/agents",
            headers={"X-API-Key": variant}
        )
        if response.status_code != 401:
            print(f"FOUND KEY: {variant}")
            break
```

**Impact:**
- **Account Compromise:** Weak keys can be brute forced
- **Enumeration:** Identify valid API keys
- **Privilege Escalation:** Access to privileged endpoints

**Fix:**
1. Add rate limiting to auth middleware (5 attempts per IP per minute)
2. Log failed authentication attempts with IP address
3. Implement account lockout after N failures (10 failures = 30 min lockout)
4. Use strong, randomly generated API keys (reject weak keys)

**Patch:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

auth_limiter = Limiter(key_func=get_remote_address)

def verify_api_key(api_key: Optional[str] = Security(api_key_header), request: Request = None) -> str:
    # Rate limit auth attempts
    if request:
        try:
            auth_limiter.limit("5/minute")(lambda: None)()  # Rate limit check
        except RateLimitExceeded:
            log_failed_auth(get_remote_address(request), "rate_limited")
            raise HTTPException(status_code=429, detail="Too many auth attempts")
    
    if not api_key:
        log_failed_auth(get_remote_address(request) if request else "unknown", "no_key")
        raise HTTPException(status_code=401, detail="API key required")
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    valid_key = cache.get(f"api_key:{key_hash}")
    
    if not valid_key:
        # LOG FAILED ATTEMPT
        log_failed_auth(get_remote_address(request) if request else "unknown", "invalid_key")
        
        # CHECK LOCKOUT
        if is_locked_out(key_hash):
            raise HTTPException(status_code=423, detail="Account locked due to too many failed attempts")
        
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return valid_key.get("owner", "authenticated")
```

---

### SEC-024: PEM Validation Weakness (P1 - HIGH)

**Component:** `atr/core/schemas.py:44-46`, `atr/api/routes_verify.py:34-41`

**Description:** No structural validation of PEM format. Accepts any string. Malformed PEM causes parser exceptions with stack traces.

**Current Code:**
```python
class VerifyCertRequest(BaseModel):
    cert_pem: str = Field(..., description="PEM-encoded certificate")
    # NO MAX_LENGTH
    # NO FORMAT VALIDATION

@router.post("/verify/cert")
def verify_certificate(request: VerifyCertRequest, db: Session = Depends(get_db)):
    try:
        cert = x509.load_pem_x509_certificate(request.cert_pem.encode('utf-8'))
    except Exception as e:
        return VerifyCertResponse(
            verified=False,
            reason=f"Invalid certificate format: {str(e)}"  # LEAKS STACK TRACE
        )
```

**Exploit Scenario:**
```bash
# Attacker sends malformed PEM causing parser exceptions
curl -X POST "http://registry.example.com/v1/verify/cert" \
  -H "Content-Type: application/json" \
  -d '{"cert_pem": "binary\x00\x01\x02...100MB..."}'

# Or SQL injection attempt
curl -X POST "http://registry.example.com/v1/verify/cert" \
  -d '{"cert_pem": "-----BEGIN CERTIFICATE-----\n\'; DROP TABLE agents; --\n-----END CERTIFICATE-----"}'

# Result: Stack trace in error response reveals internal paths
```

**Impact:**
- **Memory Exhaustion:** Large PEM blobs (100MB+) cause OOM
- **Information Disclosure:** Stack traces reveal file paths, internal structure
- **DoS:** Parser exceptions consume CPU
- **Potential Injection:** If parser has vulnerabilities

**Fix:**
1. Add max_length validation (64KB)
2. Add strict PEM format validation (regex) before parsing
3. Validate base64 structure
4. Catch exceptions and return generic errors
5. Add timeout to parsing operations

**Patch:**
```python
import re
from pydantic import field_validator

PEM_PATTERN = re.compile(
    r'^-----BEGIN CERTIFICATE-----\n'
    r'([A-Za-z0-9+\/=\s\n]+)\n'
    r'-----END CERTIFICATE-----\s*$'
)

class VerifyCertRequest(BaseModel):
    cert_pem: str = Field(
        ...,
        description="PEM-encoded certificate",
        min_length=100,
        max_length=65536  # 64KB max
    )
    
    @field_validator('cert_pem')
    @classmethod
    def validate_pem_format(cls, v: str) -> str:
        """Validate PEM format before parsing"""
        if not PEM_PATTERN.match(v):
            raise ValueError('Invalid PEM format: must be valid certificate PEM')
        
        # Validate base64 structure
        import base64
        pem_body = v.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0].strip()
        try:
            base64.b64decode(pem_body.replace('\n', '').replace(' ', ''))
        except Exception:
            raise ValueError('Invalid PEM: base64 decode failed')
        
        return v

@router.post("/verify/cert")
def verify_certificate(request: VerifyCertRequest, db: Session = Depends(get_db)):
    try:
        cert = x509.load_pem_x509_certificate(request.cert_pem.encode('utf-8'))
    except Exception as e:
        # LOG ERROR SERVER-SIDE
        logger.error(f"Certificate parsing failed: {e}", exc_info=True)
        
        # RETURN GENERIC ERROR
        return VerifyCertResponse(
            verified=False,
            reason="Invalid certificate format"  # Generic, no stack trace
        )
```

---

### SEC-025: Error Messages Leak Keys (P1 - HIGH)

**Component:** `atr/api/routes_agents.py:134-138`, All exception handlers

**Description:** Exception messages in error responses may include private key material if keys are accidentally included in error context. No filtering of secrets.

**Current Code:**
```python
try:
    private_key, cert, fingerprint = issue_agent_certificate(request.agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
except Exception as e:
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Failed to issue certificate: {str(e)}"  # MAY INCLUDE KEY MATERIAL
    )
```

**Exploit Scenario:**
```python
# If code accidentally includes key in exception:
# exception = ValueError(f"Key error: {private_key.private_bytes(...)}")
# Attacker sees private key in error response
```

**Impact:**
- **Key Exfiltration:** Private keys leaked in error responses
- **Information Disclosure:** Internal paths, stack traces
- **Reconnaissance:** Learn internal structure

**Fix:**
1. Create error sanitization middleware
2. Filter error messages for secret patterns (private keys, tokens)
3. Return generic errors to clients
4. Log detailed errors server-side only

**Patch:**
```python
import re
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

# Secret patterns to filter
SECRET_PATTERNS = [
    r'-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----',
    r'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----',
    r'-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----',
    r'/var/keys/.*?\.key',
    r'/var/pki/.*?\.key',
    r'api[_-]?key["\s:=]+([a-zA-Z0-9_-]{20,})',
    r'token["\s:=]+([a-zA-Z0-9_-]{20,})',
]

def sanitize_error_message(msg: str) -> str:
    """Remove secrets from error messages"""
    sanitized = msg
    for pattern in SECRET_PATTERNS:
        sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.DOTALL | re.IGNORECASE)
    return sanitized

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Sanitize all exceptions before returning to client"""
    # Log detailed error server-side
    logger.error(f"Unhandled exception: {exc}", exc_info=True, extra={"request_id": request.state.request_id})
    
    # Return sanitized error
    error_detail = sanitize_error_message(str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request.state.request_id}
    )
```

---

### SEC-026: List Endpoint Info Disclosure (P1 - HIGH)

**Component:** `atr/api/routes_agents.py:65-78`

**Description:** List endpoint returns owner, capabilities, timestamps - reveals organizational structure and relationships.

**Current Response:**
```json
{
  "agents": [
    {
      "agent_name": "payment-service.acme.com",
      "owner": "acme-finance",
      "capabilities": ["process_payment", "refund"],
      "created_at": "2024-01-15T10:30:00Z",
      ...
    }
  ]
}
```

**Exploit Scenario:**
```bash
# Attacker learns:
# - Which services belong to which teams (owner)
# - What capabilities exist (attack surface)
# - Registration patterns (new services, inactive services)
# - Organizational structure (team names, relationships)
```

**Impact:**
- **Reconnaissance:** Learn organizational structure
- **Targeting:** Identify high-value targets
- **Privacy:** Expose internal relationships

**Fix:**
1. Hide owner in public list (require auth for owner info)
2. Minimize returned data (agent_name, status only)
3. OR require authentication and filter to own agents

**Patch:**
```python
class AgentPublicResponse(BaseModel):
    """Public agent metadata (minimal data)"""
    agent_name: str
    status: AgentStatus
    cert_fingerprint: str
    expires_at: datetime
    # NO owner, NO capabilities, NO created_at

@router.get("", response_model=AgentListResponse)
def list_agents(
    actor: Optional[str] = Depends(verify_api_key_optional),  # Optional auth
    db: Session = Depends(get_db),
    ...
):
    query = db.query(Agent)
    
    # If authenticated, return full data for own agents
    if actor and actor != "anonymous":
        query = query.filter(Agent.owner == actor)
        response_model = AgentResponse  # Full data
    else:
        response_model = AgentPublicResponse  # Minimal data
    
    # ... rest of code ...
```

---

## Summary of Public Internet Findings

**New Critical Findings (P0):**
- SEC-021: Agent enumeration (no auth on list endpoint)
- SEC-022: No rate limiting on rotate/revoke (DoS vector)

**New High Priority (P1):**
- SEC-023: Brute force auth (no rate limiting, no lockout)
- SEC-024: Weak PEM validation (DoS, info disclosure)
- SEC-025: Error messages leak keys (key exfiltration)
- SEC-026: Info disclosure in list endpoint

**Recommendation:** This codebase is **NOT ready for public internet deployment** without addressing all P0 findings and the new P1 findings above. Attackers will rapidly exploit these vulnerabilities.

**Priority Actions:**
1. Apply rate limiting to ALL endpoints (currently imported but unused)
2. Require authentication for list/rotate/revoke endpoints
3. Add authorization checks (owner-only operations)
4. Add brute force protection (rate limit + lockout)
5. Sanitize all error messages
6. Validate PEM format strictly
7. Minimize data returned in public endpoints
