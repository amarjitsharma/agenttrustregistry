# Agent Trust Registry (ATR) — POC

A lightweight proof-of-concept for an **Agent Trust Registry**: a DNS-like naming + cryptographic identity + lifecycle governance service for autonomous agents.

This project is inspired by the emerging “agentic identity / agent naming” space and explores how a registry can go beyond names to deliver **verifiable trust at internet scale**.

## What this is
**ATR** allows you to:
- Register an agent name (e.g. `order-bot.acme`)
- Issue a cryptographic identity (keypair + X.509 certificate)
- Publish trust metadata (capabilities, owner, status, expiry)
- Rotate credentials
- Revoke identities
- Verify a presented agent certificate/token against registry state

## What this is NOT
- Not a production CA
- Not full DNS integration
- Not AI deciding access
- Not a UI-heavy product (API + CLI for speed)

---

## Key Ideas

### 1) Naming is table-stakes; trust is the product
Agent identity is only meaningful when it is:
- **Cryptographically verifiable**
- **Time-bounded**
- **Revocable**
- **Auditable**

### 2) Lifecycle is where most trust systems fail
Crypto rarely fails. Operations fail:
- expired certs
- missing rotation
- unclear ownership
- lack of audit trails

---

## Architecture (POC)

- **FastAPI** service exposes registry and verification endpoints
- **SQLite** by default (PostgreSQL optional)
- **Local CA** (dev root + intermediate) for issuing leaf certs
- **Audit log** for registry actions
- **CLI** to drive the end-to-end demo

High-level components:
- `registry-api`: agent CRUD + lifecycle operations
- `pki`: local CA + cert issuance + rotation
- `verifier`: validates agent proof (cert or signed token) + registry status
- `cli`: scripted flows to demo register → verify → rotate → revoke

---

## Data Model (conceptual)

Agent Record:
- `agent_name` (string, unique)
- `owner` (string)
- `capabilities` (json array)
- `status` (`active` | `revoked`)
- `cert_fingerprint` (string)
- `issued_at` (timestamp)
- `expires_at` (timestamp)
- `created_at`, `updated_at`

Audit Event:
- `event_type` (register/rotate/revoke/verify)
- `actor` (who initiated)
- `agent_name`
- `metadata` (json)
- `timestamp`

---

## Version Features

### v0.3: Trust & Discovery (Current)

**New in v0.3:**
- ✅ **Transparency Logs**: Merkle tree-based cryptographic audit trail
  - Automatic logging of all operations (register, rotate, revoke, verify)
  - Inclusion proof generation and verification
  - Log browser UI for viewing entries
  - API endpoints for log access and proofs
- ✅ **Domain Validation**: Ownership verification framework
  - WHOIS integration (basic)
  - DNS TXT challenge validation
  - Multi-method validation workflow
- ✅ **Async Processing**: Background task framework (foundation)
  - Certificate issuance queue structure
  - Background worker framework

### v0.2: MVP Launch

**Features:**
- ✅ **DNS Integration**: Basic TXT record provisioning (Route53, Cloudflare, or local)
- ✅ **Redis Caching**: Agent metadata and DNS responses cached for improved performance
- ✅ **Rate Limiting**: Per-IP rate limiting (configurable limits)
- ✅ **API Authentication**: Basic API key authentication (optional)
- ✅ **Production Infrastructure**: Redis support, improved error handling

For detailed implementation roadmap, see [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

---

## API Endpoints

### Registry
- `GET /v1/agents`  
  List all agents with filtering and pagination
  - Query params: `owner`, `status`, `capability`, `limit`, `offset`
- `POST /v1/agents`  
  Register an agent + issue credentials
- `GET /v1/agents/{agent_name}`  
  Fetch agent trust metadata
- `POST /v1/agents/{agent_name}/rotate`  
  Rotate identity (new cert)
- `POST /v1/agents/{agent_name}/revoke`  
  Revoke identity (status=revoked)

### Verification
- `POST /v1/verify/cert`  
  Verify a presented certificate and check registry status (active, unexpired)
- `GET /v1/resolve/{agent_name}`  
  “Resolve” agent name to trust metadata (like a lookup)

### Health / Ops
- `GET /healthz`
- `GET /readyz`

---

## Quickstart

### Requirements
- Python 3.11+
- (Optional) Docker and docker-compose
- (Optional) Redis (for caching and rate limiting in v0.2+)

### Local Setup

1. **Create virtual environment and install dependencies:**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. **Initialize database:**
The database will be created automatically on first run. For SQLite (default), no additional setup is needed.

3. **Start Redis (optional, for v0.2+ features):**
```bash
# Using Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or install Redis locally (varies by OS)
# macOS: brew install redis && redis-server
# Ubuntu: sudo apt-get install redis-server && redis-server
```

4. **Configure environment variables (optional):**
Create a `.env` file for v0.2+ features:
```bash
# Redis (for caching and rate limiting)
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=true

# DNS Provider (optional - use "local" for development)
DNS_PROVIDER=local
# For Route53:
# DNS_PROVIDER=route53
# ROUTE53_HOSTED_ZONE_ID=your_zone_id
# ROUTE53_AWS_ACCESS_KEY_ID=your_key
# ROUTE53_AWS_SECRET_ACCESS_KEY=your_secret
# ROUTE53_AWS_REGION=us-east-1
# For Cloudflare:
# DNS_PROVIDER=cloudflare
# CLOUDFLARE_API_TOKEN=your_token
# CLOUDFLARE_ZONE_ID=your_zone_id

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# API Authentication (optional)
API_KEY_ENABLED=false
```

5. **Start the API server:**
```bash
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`
- **Web UI**: `http://localhost:8000/` (interactive interface)
- API docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/healthz`

### Using Docker

**Build and run with docker-compose (includes Redis):**
```bash
docker-compose up --build
```

The API will be available at `http://localhost:8000`
- **Web UI**: `http://localhost:8000/` (interactive interface)
- Redis: `localhost:6379` (for caching and rate limiting)

**To use PostgreSQL instead of SQLite:**
```bash
# Start with PostgreSQL profile
docker-compose --profile postgres up --build

# Set DATABASE_URL in your environment
export DATABASE_URL=postgresql://atr:atr_password@localhost:5432/atr
```

---

## Web UI

A modern web interface is available at the root endpoint (`http://localhost:8000/`) providing:

- **Agent Browser**: View all registered agents with filtering capabilities
  - Filter by owner, status, or capability
  - Real-time agent status and certificate information
  - Quick actions (rotate, revoke)

- **Agent Registration**: Simple form to register new agents
  - Input validation and error handling
  - Success confirmation with certificate fingerprint

- **Certificate Verification**: Verify agent certificates
  - Paste certificate PEM for verification
  - View verification results with detailed status

The UI is a single-page application built with vanilla JavaScript, providing a clean and responsive interface for managing the Agent Trust Registry.

---

## Demo

### CLI Demo Script

Run the end-to-end lifecycle demo:

```bash
# Make sure the API server is running first
python -m atr.cli.demo
```

This will demonstrate:
1. **Register** a new agent
2. **Verify** the agent's certificate
3. **Rotate** the certificate
4. **Verify** again (with new certificate)
5. **Revoke** the agent
6. **Verify** one more time (should fail)

### Manual API Demo

**1. Register an agent:**
```bash
curl -X POST "http://localhost:8000/v1/agents" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "my-agent.example",
    "owner": "alice",
    "capabilities": ["read", "write"]
  }'
```

**2. List all agents:**
```bash
# List all agents
curl "http://localhost:8000/v1/agents"

# Filter by owner
curl "http://localhost:8000/v1/agents?owner=alice"

# Filter by status
curl "http://localhost:8000/v1/agents?status=active"

# Filter by capability
curl "http://localhost:8000/v1/agents?capability=translate"

# Combine filters with pagination
curl "http://localhost:8000/v1/agents?owner=alice&status=active&limit=20&offset=0"
```

**3. Get agent metadata:**
```bash
curl "http://localhost:8000/v1/agents/my-agent.example"
```

**4. Resolve agent:**
```bash
curl "http://localhost:8000/v1/resolve/my-agent.example"
```

**5. Rotate certificate:**
```bash
curl -X POST "http://localhost:8000/v1/agents/my-agent.example/rotate"
```

**6. Verify certificate:**
```bash
# First, get the certificate PEM (from database or agent's storage)
# Then verify it:
curl -X POST "http://localhost:8000/v1/verify/cert" \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

**7. Revoke agent:**
```bash
curl -X POST "http://localhost:8000/v1/agents/my-agent.example/revoke"
```

---

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Test coverage includes:
- Agent name validation (edge cases)
- Register/rotate/revoke behaviors
- Certificate verification (success and failure cases)
- Revoked agent verification failure
- Expired certificate verification failure

---

## Project Structure

```
agent-trust-registry/
├── atr/
│   ├── main.py                 # FastAPI application
│   ├── api/
│   │   ├── routes_agents.py    # Agent lifecycle endpoints
│   │   ├── routes_verify.py   # Verification endpoints
│   │   └── routes_health.py   # Health check endpoints
│   ├── core/
│   │   ├── config.py          # Configuration management
│   │   ├── db.py              # Database session management
│   │   ├── models.py          # SQLAlchemy models
│   │   ├── schemas.py         # Pydantic schemas
│   │   ├── validators.py      # Input validation
│   │   ├── audit.py           # Audit logging
│   │   └── security.py        # Security utilities
│   ├── pki/
│   │   ├── ca.py              # Certificate Authority
│   │   ├── issue.py           # Certificate issuance
│   │   └── fingerprints.py    # Fingerprint utilities
│   ├── cli/
│   │   └── demo.py            # CLI demo script
│   └── static/
│       └── index.html         # Web UI (single-page application)
├── tests/
│   ├── test_validators.py    # Validator tests
│   ├── test_lifecycle.py     # Lifecycle tests
│   └── test_verify.py        # Verification tests
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── README.md
```

---

## Configuration

Configuration is managed via environment variables or `.env` file:

### Core Settings
- `DATABASE_URL`: Database connection string (default: `sqlite:///./atr.db`)
- `PKI_ROOT_DIR`: Directory for CA certificates (default: `./var/pki`)
- `KEYS_ROOT_DIR`: Directory for agent private keys (default: `./var/keys`)
- `HOST`: Server host (default: `0.0.0.0`)
- `PORT`: Server port (default: `8000`)
- `CA_VALIDITY_DAYS`: CA certificate validity (default: `3650`)
- `CERT_VALIDITY_DAYS`: Agent certificate validity (default: `30`)

### v0.2 MVP Settings

**Redis (Caching & Rate Limiting):**
- `REDIS_URL`: Redis connection URL (default: `redis://localhost:6379/0`)
- `REDIS_ENABLED`: Enable Redis caching (default: `true`)

**DNS Provider:**
- `DNS_PROVIDER`: DNS provider type - `local`, `route53`, or `cloudflare` (default: `local`)
- For Route53:
  - `ROUTE53_HOSTED_ZONE_ID`: AWS Route53 hosted zone ID
  - `ROUTE53_AWS_ACCESS_KEY_ID`: AWS access key ID
  - `ROUTE53_AWS_SECRET_ACCESS_KEY`: AWS secret access key
  - `ROUTE53_AWS_REGION`: AWS region (default: `us-east-1`)
- For Cloudflare:
  - `CLOUDFLARE_API_TOKEN`: Cloudflare API token
  - `CLOUDFLARE_ZONE_ID`: Cloudflare zone ID

**Rate Limiting:**
- `RATE_LIMIT_ENABLED`: Enable rate limiting (default: `true`)
- `RATE_LIMIT_PER_MINUTE`: Requests per minute per IP (default: `60`)
- `RATE_LIMIT_PER_HOUR`: Requests per hour per IP (default: `1000`)

**API Authentication:**
- `API_KEY_ENABLED`: Enable API key authentication (default: `false`)
- `API_KEY_HEADER`: Header name for API key (default: `X-API-Key`)

### v0.3 Settings

**Transparency Log:**
- `TRANSPARENCY_LOG_ENABLED`: Enable transparency log (default: `true`)

**Domain Validation:**
- `DOMAIN_VALIDATION_ENABLED`: Enable domain validation (default: `false`)

**Async Processing:**
- `ASYNC_PROCESSING_ENABLED`: Enable async processing (default: `false`)

---

## Security Notes

⚠️ **This is a proof-of-concept, not production-ready:**

- Private keys are stored in `./var/keys/` (gitignored)
- CA certificates are stored in `./var/pki/` (gitignored)
- Default certificate validity is 30 days (short for demo)
- No secrets or hardcoded credentials in git-tracked files
- Certificate chain validation is simplified for POC

**For production use, consider:**
- Proper key management (HSM, key vault)
- Full certificate chain validation
- CRL/OCSP for revocation checking
- Rate limiting and authentication
- Proper logging and monitoring

---

## Development

**Run with auto-reload:**
```bash
uvicorn atr.main:app --reload
```

**Run tests with coverage:**
```bash
pytest tests/ --cov=atr --cov-report=html
```

**Check code style:**
```bash
# Install dev dependencies
pip install black flake8 mypy

# Format code
black atr/ tests/

# Lint
flake8 atr/ tests/

# Type check
mypy atr/
```

---

## Future Implementation Roadmap

Based on industry best practices and emerging standards (see [GoDaddy's Agent Name Service Registry](https://www.godaddy.com/resources/news/building-trust-at-internet-scale-godaddys-agent-name-service-registry-for-the-agentic-ai-marketplace)), the following enhancements are planned for production-scale deployment:

### Phase 1: DNS Integration & Discovery (High Priority)

**Goal:** Enable DNS-based agent discovery and resolution

**Required Changes:**
- [ ] Implement DNS record provisioning (TXT, SRV records)
  - `_ans._tcp.{agent_name}` SRV records for service discovery
  - `{agent_name}` TXT records with capability metadata
- [ ] Integrate with DNS providers (Route53, Cloudflare, etc.)
- [ ] Add DNSSEC signing for record integrity
- [ ] Implement DNS resolver in `/v1/resolve/{agent_name}` endpoint
  - Query DNS first, fallback to database
  - Cache DNS responses with TTL awareness
- [ ] Support both API and DNS resolution methods

**Benefits:** Decentralized discovery, reduced API load, standard internet protocols

### Phase 2: Transparency Logs (High Priority)

**Goal:** Implement cryptographically verifiable audit trail

**Required Changes:**
- [ ] Implement Merkle tree-based transparency log
  - Each registration/rotation/revocation creates log entry
  - Build Merkle tree with periodic checkpoints
  - Publish tree roots and inclusion proofs
- [ ] Add log verification endpoints:
  - `GET /v1/log/entry/{entry_id}` - Retrieve log entry with proof
  - `GET /v1/log/consistency/{old_root}/{new_root}` - Consistency proof
  - `GET /v1/log/inclusion/{entry_id}/{root}` - Inclusion proof
- [ ] Implement log monitoring:
  - Periodic checkpoint publication (e.g., every hour)
  - Monitor for log inconsistencies
  - Provide log browser/explorer interface

**Benefits:** Immutability, tamper detection, auditability, compliance

### Phase 3: Domain Validation & Customer Verification (Medium Priority)

**Goal:** Ensure legitimate ownership and prevent name squatting

**Required Changes:**
- [ ] Implement domain validation workflow
  - Require agent names to match owned domains
  - Integrate with domain registrars (WHOIS, DNS TXT records, Domain Connect API)
  - Support validation via DNS TXT record challenge
- [ ] Add customer verification workflow
  - Multi-step registration: domain validation → customer verification → agent registration
  - Store domain ownership proof in agent metadata
  - Periodic re-validation of domain ownership
- [ ] Implement domain-based access control
  - Agents can only register under domains they own
  - Support subdomain delegation (e.g., `*.agents.example.com`)

**Benefits:** Prevents name squatting, ensures legitimate ownership, builds trust

### Phase 4: Hybrid Certificate Architecture (Medium Priority)

**Goal:** Separate public TLS and private identity certificates

**Required Changes:**
- [ ] Implement dual certificate model
  - Public TLS certificate: For HTTPS/mTLS communication (standard CA)
  - Private identity certificate: For agent-to-agent authentication (our CA)
- [ ] Add certificate linking
  - Store both certificate fingerprints in agent record
  - Link public and private certs via metadata
  - Support certificate chain validation for both
- [ ] Enhance verification endpoint
  - Verify public cert for transport security
  - Verify private cert for agent identity
  - Support both verification modes in API

**Benefits:** Separation of concerns, compatibility with existing TLS infrastructure, stronger identity verification

### Phase 5: Registration Authority (RA) Orchestration (Medium Priority)

**Goal:** Add RA layer for validation and automation

**Required Changes:**
- [ ] Implement RA service layer
  - RA validates requests before processing
  - RA orchestrates multi-step workflows (domain validation, certificate issuance, DNS provisioning)
  - RA handles policy enforcement and rate limiting
- [ ] Add automated lifecycle management
  - Automatic certificate renewal before expiry
  - Proactive rotation reminders
  - Automated revocation on domain expiration
- [ ] Implement policy engine
  - Configurable registration policies
  - Rate limits per customer/domain
  - Capability restrictions and validation

**Benefits:** Operational automation, policy enforcement, reduced manual intervention

### Phase 6: Scalability & Performance (High Priority)

**Goal:** Support internet-scale deployment

**Required Changes:**
- [ ] Database scaling
  - Read replicas for read-heavy operations (resolve, verify)
  - Partitioning by agent name hash
  - Separate audit log database (time-series optimized)
- [ ] Caching layer
  - Redis for hot agent metadata (resolve operations)
  - Cache DNS responses with TTL
  - Cache certificate chain validation results
- [ ] Async processing
  - Queue-based certificate issuance (don't block registration)
  - Async DNS provisioning
  - Background job for certificate renewal checks
- [ ] CDN integration
  - Serve public agent metadata via CDN
  - Cache transparency log checkpoints
  - Edge caching for resolve endpoints

**Benefits:** High availability, low latency, horizontal scalability

### Phase 7: Security Enhancements (High Priority)

**Goal:** Production-grade security

**Required Changes:**
- [ ] Rate limiting and DDoS protection
  - Per-IP rate limits on registration/verification
  - Per-domain rate limits
  - Integration with Cloudflare/AWS Shield
- [ ] Key management
  - HSM integration for CA private keys
  - Key rotation for CA certificates
  - Secure key storage (AWS KMS, HashiCorp Vault)
- [ ] Certificate revocation
  - Implement CRL (Certificate Revocation List)
  - Support OCSP (Online Certificate Status Protocol)
  - Real-time revocation checking
- [ ] Monitoring and alerting
  - Anomaly detection (unusual registration patterns)
  - Failed verification monitoring
  - Certificate expiry alerts

**Benefits:** Protection against attacks, secure key management, real-time revocation

### Phase 8: Standards Compliance (Low Priority)

**Goal:** Align with emerging industry standards

**Required Changes:**
- [ ] IETF ANS draft compliance
  - Align agent name format with IETF specifications
  - Implement recommended DNS record types
  - Support standard discovery protocols
- [ ] OWASP GenAI ANS guidelines
  - Follow security best practices from OWASP
  - Implement recommended validation checks
  - Support OWASP-defined metadata fields
- [ ] A2A/MCP protocol integration
  - Support agent-to-agent communication protocols
  - Provide protocol-specific discovery endpoints
  - Enable seamless agent interoperability

**Benefits:** Industry alignment, interoperability, compliance

### Implementation Priority

**Immediate (High Impact, Moderate Effort):**
1. DNS Integration (TXT records for discovery)
2. Transparency Logs (Merkle trees)
3. Domain Validation (prevent squatting)

**Short-term (High Impact, Higher Effort):**
4. Hybrid Certificates
5. RA Orchestration Layer
6. Database Scaling and Caching

**Long-term (Foundation for Scale):**
7. Full DNSSEC Integration
8. HSM Key Management
9. Standards Compliance (IETF, OWASP)

### References

- [GoDaddy's Agent Name Service Registry](https://www.godaddy.com/resources/news/building-trust-at-internet-scale-godaddys-agent-name-service-registry-for-the-agentic-ai-marketplace) - Production implementation reference
- IETF ANS Draft - Emerging naming standards
- OWASP GenAI ANS Guidelines - Security best practices
- A2A/MCP Protocols - Agent-to-agent communication standards

### Implementation Effort Estimate

For detailed implementation planning, see [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) which includes:
- Phase-by-phase effort breakdown
- Timeline estimates (18-24 months total)
- Team composition requirements (6-8 engineers)
- Infrastructure costs ($1.5M - $2.5M total)
- Risk mitigation strategies
- Phased rollout recommendations

**Quick Summary:**
- **Total Timeline:** 18-24 months
- **Team Size:** 6-8 full-time engineers
- **Total Cost:** $1.5M - $2.5M
- **Recommended Approach:** Phased MVP rollout (6 months) followed by iterative enhancements

---

## Architecture Diagram

```mermaid
flowchart TB
  %% =========================
  %% Agent Trust Registry (ATR)
  %% =========================

  subgraph Clients["Clients"]
    CLI["CLI Demo\n(atr cli)"]
    Agent["Agent Runtime\n(AI Agent / Tool Runner)"]
  end

  subgraph ATR["Agent Trust Registry API (FastAPI)"]
    AgentsAPI["Agents API\n/list /register /rotate /revoke /get"]
    ResolveAPI["Resolve API\n/resolve/{agent_name}"]
    VerifyAPI["Verify API\n/verify/cert"]
    WebUI["Web UI\n(interactive interface)"]
    AuditSvc["Audit Logger\n(register/rotate/revoke/verify)"]
  end

  subgraph PKI["PKI Service (Local CA for POC)"]
    RootCA["Dev Root CA\n(off-path, long-lived)"]
    IntCA["Intermediate CA\n(issues leaf certs)"]
    Issuer["Cert Issuer\n(X.509 + SAN=agent_name)\nFingerprinting"]
    KeyStore["Key Material (POC)\n./var/keys/<agent>/\n.gitignored"]
  end

  subgraph Data["Data Stores"]
    RegistryDB["Registry DB\nSQLite (default) / Postgres (optional)\nAgent metadata + active fingerprint"]
    AuditDB["Audit Log Table\nappend-only events"]
  end

  subgraph Verifier["Verification Logic"]
    ChainCheck["Chain Validation\n(cert chains to Intermediate)"]
    StatusCheck["Registry Check\n(active + not expired + fingerprint match)"]
    Decision["Decision\nverified=true/false + reason"]
  end

  %% Flows
  CLI -->|Register/Rotate/Revoke| AgentsAPI
  WebUI -->|Browse/Manage| AgentsAPI
  Agent -->|Present cert (PEM)\n(or mTLS in future)| VerifyAPI

  AgentsAPI --> Issuer
  Issuer --> IntCA
  Issuer --> KeyStore
  Issuer -->|cert + fingerprint| RegistryDB

  ResolveAPI --> RegistryDB

  VerifyAPI --> ChainCheck
  VerifyAPI --> StatusCheck
  ChainCheck --> Decision
  StatusCheck --> Decision
  StatusCheck --> RegistryDB

  AgentsAPI --> AuditSvc
  VerifyAPI --> AuditSvc
  AuditSvc --> AuditDB

  %% Notes
  Decision -->|Response:\nagent_name, verified,\nstatus, expires_at, reason| Clients
```

---

## License

This is a proof-of-concept project for demonstration purposes.