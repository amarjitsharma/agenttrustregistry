# UI Testing Guide for v0.2 MVP

## Quick Start

### 1. Start the Server

The server should already be running. If not, start it:

```bash
# Activate virtual environment
source .venv/bin/activate

# Start the server
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Open the Web UI

Open your browser and navigate to:
```
http://localhost:8000
```

## Testing v0.2 MVP Features

### Feature 1: Agent Registration (with DNS Integration)

1. **Navigate to the registration form** in the UI
2. **Register a new agent:**
   - Agent Name: `test-agent.example`
   - Owner: `test-owner`
   - Capabilities: `read, write` (comma-separated)
3. **Click "Register Agent"**
4. **Verify:**
   - Agent appears in the agent list
   - Certificate fingerprint is displayed
   - Status shows as "ACTIVE"
   - **Behind the scenes:** DNS TXT record is created (local provider = no-op, but code path is tested)

### Feature 2: Agent List with Caching

1. **View the agent list** (main page)
2. **Test caching:**
   - Refresh the page multiple times
   - Open browser DevTools → Network tab
   - Verify subsequent requests are faster (cached by Redis)
3. **Test filtering:**
   - Filter by owner
   - Filter by status (ACTIVE/REVOKED)
   - Filter by capability
4. **Test pagination:**
   - Register multiple agents
   - Test pagination controls

### Feature 3: Agent Details (Cached)

1. **Click on an agent name** to view details
2. **Verify:**
   - Agent metadata is displayed
   - Certificate information is shown
   - **Behind the scenes:** Response is cached in Redis for 5 minutes

### Feature 4: Certificate Verification

1. **Navigate to the verification section**
2. **Get a certificate:**
   - Find an agent in the list
   - Copy the certificate PEM (if displayed)
   - Or get it via API: `GET /v1/agents/{agent_name}`
3. **Paste the certificate PEM** into the verification form
4. **Click "Verify Certificate"**
5. **Verify:**
   - Verification result shows `verified: true` for active agents
   - Shows agent name, status, expiry
   - Shows reason if verification fails

### Feature 5: Certificate Rotation

1. **Find an agent** in the list
2. **Click "Rotate" button** (if available in UI)
   Or use the API directly:
   ```bash
   curl -X POST http://localhost:8000/v1/agents/{agent_name}/rotate
   ```
3. **Verify:**
   - New certificate fingerprint is generated
   - Agent details updated
   - **Behind the scenes:** 
     - DNS TXT record is updated
     - Cache is invalidated
     - Old cache entries are cleared

### Feature 6: Agent Revocation

1. **Find an agent** in the list
2. **Click "Revoke" button** (if available in UI)
   Or use the API directly:
   ```bash
   curl -X POST http://localhost:8000/v1/agents/{agent_name}/revoke
   ```
3. **Verify:**
   - Agent status changes to "REVOKED"
   - Certificate verification now fails
   - **Behind the scenes:**
     - Cache is invalidated
     - DNS records remain (could be cleaned up in future)

### Feature 7: DNS-Based Resolution (via API)

The `/v1/resolve/{agent_name}` endpoint supports DNS resolution. Test it:

```bash
# Resolve an agent (checks DNS first, then database)
curl http://localhost:8000/v1/resolve/test-agent.example
```

**Behind the scenes:**
- Checks DNS TXT records first (if DNS provider configured)
- Falls back to database lookup
- Response is cached for 5 minutes

### Feature 8: Rate Limiting

1. **Open browser DevTools → Network tab**
2. **Make multiple rapid requests:**
   - Refresh the agent list multiple times quickly
   - Or use curl to make rapid requests:
   ```bash
   for i in {1..70}; do curl -s http://localhost:8000/v1/agents > /dev/null && echo "Request $i"; done
   ```
3. **Verify:**
   - After 60 requests/minute, you should see rate limit errors (429)
   - Error message: "Rate limit exceeded"

## Testing with Browser DevTools

### 1. Network Tab

- **Open DevTools** (F12 or Cmd+Option+I)
- **Go to Network tab**
- **Filter by "Fetch/XHR"**
- **Test caching:**
  - Make a request to `/v1/agents/{agent_name}`
  - Check response headers for cache indicators
  - Make the same request again - should be faster

### 2. Console Tab

- **Open Console tab**
- **Check for errors**
- **Test API calls directly:**
  ```javascript
  // Fetch agents
  fetch('http://localhost:8000/v1/agents')
    .then(r => r.json())
    .then(console.log);
  
  // Fetch specific agent
  fetch('http://localhost:8000/v1/agents/test-agent.example')
    .then(r => r.json())
    .then(console.log);
  ```

### 3. Application Tab (Storage)

- **Check if any data is cached locally**
- **Check cookies/session storage**

## Testing v0.2 Features via API (for comparison)

While testing in the UI, you can also test directly via API:

### Test Caching

```bash
# First request (misses cache)
time curl -s http://localhost:8000/v1/agents/test-agent.example > /dev/null

# Second request (hits cache - should be faster)
time curl -s http://localhost:8000/v1/agents/test-agent.example > /dev/null
```

### Test DNS Resolution

```bash
# Resolve via DNS + cache
curl http://localhost:8000/v1/resolve/test-agent.example | jq
```

### Test Rate Limiting

```bash
# Make 70 requests rapidly
for i in {1..70}; do 
  curl -s -w "\nStatus: %{http_code}\n" http://localhost:8000/v1/agents | tail -1
  sleep 0.1
done
```

After ~60 requests, you should see `429 Too Many Requests`.

## Verification Checklist

- [ ] Agent registration works
- [ ] Agent list displays correctly
- [ ] Filtering works (owner, status, capability)
- [ ] Pagination works
- [ ] Agent details load (cached)
- [ ] Certificate verification works
- [ ] Certificate rotation works (via API)
- [ ] Agent revocation works (via API)
- [ ] DNS resolution works (via API)
- [ ] Rate limiting works (429 errors after limit)
- [ ] Cache speeds up repeated requests
- [ ] All features work without breaking existing functionality

## Troubleshooting

### Server Not Running
```bash
# Check if server is running
curl http://localhost:8000/healthz

# Start server
uvicorn atr.main:app --reload --host 0.0.0.0 --port 8000
```

### Redis Not Available
- The app will work without Redis (uses in-memory fallback)
- Caching won't persist across restarts
- Rate limiting will use in-memory storage

### DNS Provider Not Configured
- Default is "local" (no-op)
- To test Route53/Cloudflare, configure credentials in `.env`
- See README.md for configuration details

## Next Steps

After UI testing, you may want to:
1. Test with Redis enabled (start Redis server)
2. Test with Route53/Cloudflare DNS providers
3. Enable API key authentication
4. Load test rate limiting
5. Test cache invalidation scenarios
