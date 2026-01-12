# UI Demo Guide: Agent Trust Registry

**Last Updated:** 2025-01-27  
**Status:** Complete UI Demo Instructions

---

## Quick Start: Launching the UI

### Step 1: Start the API Server

```bash
# Activate virtual environment (if not already active)
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Start the FastAPI server
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

The server will start and you'll see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### Step 2: Open the Web UI

**Open your browser and navigate to:**
```
http://localhost:8000
```

You should see the **Agent Trust Registry** web interface!

---

## UI Features Demo

### 1. **Agent Browser Tab**

**What it shows:**
- List of all registered agents
- Filter by owner, status, or capability
- Real-time agent status and certificate information
- Quick actions (view certificate, rotate, revoke)

**How to demo:**
1. Click the **"Agent Browser"** tab (or it's already open)
2. If no agents exist, you'll see "No agents found"
3. After registering agents, they'll appear here with:
   - Agent name
   - Owner
   - Status (Active/Revoked)
   - Certificate fingerprint
   - Expiration date
   - Capabilities

**Features:**
- **Filter Agents:** Use the filter dropdowns at the top
- **Get Certificate:** Click "Get Certificate" button on any agent card
  - This will fetch the certificate PEM
  - Automatically switches to "Verify Certificate" tab
  - Pastes the certificate into the verification form

---

### 2. **Register Agent Tab**

**What it does:**
- Register a new agent with cryptographic identity
- Issue a certificate automatically
- Store agent metadata in the registry

**How to demo:**
1. Click the **"Register Agent"** tab
2. Fill in the form:
   - **Agent Name:** `my-demo-agent.example` (must be DNS-label format)
   - **Owner:** `demo@example.com`
   - **Capabilities:** `read,write` (comma-separated)
   - **Request Public Cert:** (optional) Check if you want dual certificates
3. Click **"Register Agent"** button
4. Wait for response (usually <5 seconds)
5. Success message shows:
   - Certificate fingerprint
   - Agent status (Active)
   - Expiration date

**Example registration:**
```
Agent Name: order-bot.acme
Owner: security-team@acme.com
Capabilities: process-orders,verify-payments
Request Public Cert: (unchecked for private cert only)
```

**What happens:**
- ✅ Agent is registered in the database
- ✅ Certificate is issued by the local CA
- ✅ Private key is stored in `./var/keys/{agent_name}/`
- ✅ Agent metadata is cached (if Redis enabled)
- ✅ DNS TXT record created (if DNS provider configured)
- ✅ Audit event logged

---

### 3. **Verify Certificate Tab**

**What it does:**
- Verify an agent's certificate against the registry
- Check certificate validity, status, and expiration
- Validate certificate chain

**How to demo:**

**Option A: Using "Get Certificate" button (easiest)**
1. Go to **Agent Browser** tab
2. Find an agent you registered
3. Click **"Get Certificate"** button on the agent card
4. You'll automatically switch to **"Verify Certificate"** tab
5. Certificate PEM is already pasted in the textarea
6. Click **"Verify Certificate"** button
7. See verification result:
   - ✅ **Verified:** Agent is active, certificate is valid
   - ❌ **Not Verified:** Shows reason (expired, revoked, invalid, etc.)

**Option B: Manual certificate paste**
1. Click the **"Verify Certificate"** tab
2. Paste a certificate PEM into the textarea:
   ```
   -----BEGIN CERTIFICATE-----
   MIIDXTCCAkWgAwIBAgIJAK... (certificate content)
   -----END CERTIFICATE-----
   ```
3. Click **"Verify Certificate"** button
4. See verification result

**Verification checks:**
- ✅ Certificate chains to trusted CA
- ✅ Fingerprint matches registry
- ✅ Agent status is Active
- ✅ Certificate is not expired
- ✅ Certificate format is valid

---

### 4. **Transparency Log Tab** (v0.3+)

**What it shows:**
- Immutable audit trail of all operations
- Merkle tree root hash
- Log entries with cryptographic proofs

**How to demo:**
1. Click the **"Transparency Log"** tab
2. View log entries:
   - Timestamp
   - Event type (Register/Rotate/Revoke/Verify)
   - Agent name
   - Event details
3. View Merkle root hash (updates with each new entry)
4. Generate inclusion proof for any entry

**Features:**
- **Refresh Log:** Click to reload entries
- **Get Root Hash:** View current Merkle tree root
- **Inclusion Proof:** Verify an entry's inclusion in the log

---

## Complete Demo Flow

### Demo Scenario: Agent Lifecycle

**1. Register an Agent**
```
1. Open UI: http://localhost:8000
2. Click "Register Agent" tab
3. Fill form:
   - Agent Name: demo-agent-2025.example
   - Owner: demo@example.com
   - Capabilities: read,write,monitor
4. Click "Register Agent"
5. ✅ Success! Note the certificate fingerprint
```

**2. Browse Agents**
```
1. Click "Agent Browser" tab
2. See your newly registered agent
3. View agent details (status, fingerprint, expiration)
4. Use filters to search (if you have multiple agents)
```

**3. Verify Certificate**
```
1. On agent card, click "Get Certificate"
2. Automatically switches to "Verify Certificate" tab
3. Certificate PEM is already pasted
4. Click "Verify Certificate"
5. ✅ Verified! Agent is active and certificate is valid
```

**4. Rotate Certificate** (via API or UI)
```
1. Keep the agent name: demo-agent-2025.example
2. Use API: POST /v1/agents/demo-agent-2025.example/rotate
   OR wait for UI rotation button (if implemented)
3. Get new certificate
4. Verify new certificate works
5. Verify old certificate fails
```

**5. Revoke Agent**
```
1. Use API: POST /v1/agents/demo-agent-2025.example/revoke
   OR use UI revoke button (if implemented)
2. Get certificate again
3. Try to verify
4. ❌ Verification fails: Agent is revoked
```

**6. View Transparency Log**
```
1. Click "Transparency Log" tab
2. See all operations:
   - Register event for demo-agent-2025.example
   - Rotate event (if you rotated)
   - Revoke event (if you revoked)
   - Verify events
3. View Merkle root hash
```

---

## API Demo (Complementary to UI)

While testing the UI, you can also use the API directly:

### Using curl

```bash
# Register an agent
curl -X POST http://localhost:8000/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "api-demo-agent.example",
    "owner": "api-user@example.com",
    "capabilities": ["read", "write"]
  }'

# List all agents
curl http://localhost:8000/v1/agents

# Get specific agent
curl http://localhost:8000/v1/agents/api-demo-agent.example

# Get agent certificate
curl http://localhost:8000/v1/agents/api-demo-agent.example/cert

# Rotate certificate
curl -X POST http://localhost:8000/v1/agents/api-demo-agent.example/rotate

# Revoke agent
curl -X POST http://localhost:8000/v1/agents/api-demo-agent.example/revoke

# Verify certificate
curl -X POST http://localhost:8000/v1/verify/cert \
  -H "Content-Type: application/json" \
  -d '{
    "cert_pem": "-----BEGIN CERTIFICATE-----\n..."
  }'
```

### Using the API Docs (Interactive)

1. Navigate to: `http://localhost:8000/docs`
2. Interactive Swagger UI
3. Try out all endpoints directly in the browser
4. See request/response examples

---

## Common Demo Scenarios

### Scenario 1: New User Onboarding

**Goal:** Show how easy it is to register and verify an agent

```
1. Register: demo-onboarding.example
2. Get certificate automatically
3. Verify certificate immediately
4. Show transparency log entry
```

**Time:** <2 minutes

---

### Scenario 2: Security Incident Response

**Goal:** Show certificate rotation and revocation

```
1. Show existing agent (order-bot.acme)
2. Detect compromise (simulated)
3. Rotate certificate (new cert issued)
4. Verify old cert fails
5. Verify new cert works
6. Show audit trail
```

**Time:** <3 minutes

---

### Scenario 3: Enterprise Fleet Management

**Goal:** Show managing multiple agents

```
1. Register multiple agents:
   - order-bot.acme
   - payment-processor.acme
   - inventory-manager.acme
2. Browse all agents
3. Filter by owner or capability
4. Verify multiple certificates
5. Show transparency log for all operations
```

**Time:** <5 minutes

---

## Troubleshooting

### UI Not Loading

**Check:**
1. Is the server running? Check terminal for `Uvicorn running on http://0.0.0.0:8000`
2. Can you access `http://localhost:8000/healthz`?
3. Check browser console for errors (F12)

**Fix:**
```bash
# Restart the server
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

### No Agents Showing

**Check:**
1. Have you registered any agents?
2. Check the API: `curl http://localhost:8000/v1/agents`

**Fix:**
```bash
# Register a test agent via API
curl -X POST http://localhost:8000/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "test-agent.example",
    "owner": "test@example.com",
    "capabilities": ["test"]
  }'
```

### Certificate Verification Fails

**Check:**
1. Is the certificate PEM complete? (includes BEGIN/END lines)
2. Is the agent active? Check agent status
3. Is the certificate expired? Check expiration date

**Fix:**
- Use "Get Certificate" button to ensure correct format
- Register a new agent if needed
- Check certificate expiration date

### Transparency Log Empty

**Check:**
1. Is transparency logging enabled? Check settings
2. Have you performed any operations (register, rotate, revoke)?

**Fix:**
- Enable transparency logs in configuration
- Perform operations to generate log entries
- Refresh the log browser

---

## Tips for Great Demos

### Before Demo

1. **Clean Database (Optional):**
   ```bash
   # Remove existing database for fresh start
   rm atr.db  # SQLite only
   ```

2. **Start Fresh Server:**
   ```bash
   uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
   ```

3. **Prepare Agent Names:**
   - Use realistic names: `order-bot.acme`, `payment-processor.example`
   - Avoid test names: `test-agent-123`

### During Demo

1. **Tell a Story:**
   - Start with a business problem (agent identity management)
   - Show how ATR solves it (registration, verification, lifecycle)

2. **Show Key Features:**
   - ✅ Easy registration (<5 seconds)
   - ✅ Instant verification (<100ms)
   - ✅ Lifecycle management (rotate, revoke)
   - ✅ Audit trails (transparency log)

3. **Demonstrate Trust:**
   - Show certificate fingerprints
   - Show cryptographic verification
   - Show immutable audit logs

### After Demo

1. **Show the API:**
   - Open `http://localhost:8000/docs`
   - Show interactive API documentation
   - Demonstrate programmatic access

2. **Show Architecture:**
   - Explain PKI-backed certificates
   - Show Merkle tree for transparency
   - Explain lifecycle automation

---

## Quick Reference

| Feature | UI Tab | API Endpoint |
|---------|--------|--------------|
| List Agents | Agent Browser | `GET /v1/agents` |
| Register Agent | Register Agent | `POST /v1/agents` |
| Verify Certificate | Verify Certificate | `POST /v1/verify/cert` |
| Get Certificate | Agent Browser → Get Cert | `GET /v1/agents/{name}/cert` |
| Rotate Certificate | (API only) | `POST /v1/agents/{name}/rotate` |
| Revoke Agent | (API only) | `POST /v1/agents/{name}/revoke` |
| View Log | Transparency Log | `GET /v1/transparency/log` |
| Health Check | N/A | `GET /healthz` |

---

## Next Steps

1. **Start the server:** `uvicorn atr.main:app --reload`
2. **Open the UI:** `http://localhost:8000`
3. **Register an agent:** Fill the form and submit
4. **Verify the certificate:** Use "Get Certificate" button
5. **Explore the features:** Try filters, transparency log, etc.

**Have fun demoing! 🚀**
