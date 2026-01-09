"""CLI demo script for agent lifecycle"""
import sys
import httpx
import json
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from atr.core.config import settings
from atr.core.db import SessionLocal
from atr.core.models import Agent


# Use localhost instead of 0.0.0.0 for client connections
BASE_URL = f"http://localhost:{settings.port}"


def print_step(step: str):
    """Print a step header"""
    print(f"\n{'='*60}")
    print(f"STEP: {step}")
    print(f"{'='*60}\n")


def print_response(response: httpx.Response, label: str = "Response"):
    """Print HTTP response"""
    print(f"{label}:")
    print(f"  Status: {response.status_code}")
    try:
        data = response.json()
        print(f"  Body: {json.dumps(data, indent=2, default=str)}")
    except:
        print(f"  Body: {response.text}")


def register_agent(client: httpx.Client, agent_name: str, owner: str) -> Optional[dict]:
    """Register a new agent"""
    print_step("1. REGISTER AGENT")
    
    payload = {
        "agent_name": agent_name,
        "owner": owner,
        "capabilities": ["read", "write"]
    }
    
    response = client.post(f"{BASE_URL}/v1/agents", json=payload)
    print_response(response, "Register Response")
    
    if response.status_code == 201:
        return response.json()
    else:
        print(f"ERROR: Failed to register agent")
        return None


def get_agent_cert_from_db(agent_name: str) -> Optional[str]:
    """Get agent certificate PEM from database (for demo purposes)"""
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
        if agent:
            return agent.cert_pem
        return None
    finally:
        db.close()


def verify_certificate(client: httpx.Client, cert_pem: str) -> dict:
    """Verify a certificate"""
    print_step("2. VERIFY CERTIFICATE")
    
    payload = {"cert_pem": cert_pem}
    response = client.post(f"{BASE_URL}/v1/verify/cert", json=payload)
    print_response(response, "Verify Response")
    
    return response.json()


def get_agent(client: httpx.Client, agent_name: str) -> Optional[dict]:
    """Get agent metadata"""
    response = client.get(f"{BASE_URL}/v1/agents/{agent_name}")
    
    if response.status_code == 200:
        return response.json()
    return None


def rotate_certificate(client: httpx.Client, agent_name: str) -> Optional[dict]:
    """Rotate agent certificate"""
    print_step("3. ROTATE CERTIFICATE")
    
    response = client.post(f"{BASE_URL}/v1/agents/{agent_name}/rotate")
    print_response(response, "Rotate Response")
    
    if response.status_code == 200:
        return response.json()
    return None


def revoke_agent(client: httpx.Client, agent_name: str) -> Optional[dict]:
    """Revoke an agent"""
    print_step("4. REVOKE AGENT")
    
    response = client.post(f"{BASE_URL}/v1/agents/{agent_name}/revoke")
    print_response(response, "Revoke Response")
    
    if response.status_code == 200:
        return response.json()
    return None


def main():
    """Run the demo lifecycle"""
    agent_name = "demo-agent.example"
    owner = "demo-user"
    
    print("\n" + "="*60)
    print("AGENT TRUST REGISTRY - CLI DEMO")
    print("="*60)
    print(f"\nAgent Name: {agent_name}")
    print(f"Owner: {owner}")
    print(f"Base URL: {BASE_URL}\n")
    
    with httpx.Client(timeout=30.0) as client:
        # Step 1: Register
        agent_data = register_agent(client, agent_name, owner)
        if not agent_data:
            print("ERROR: Registration failed. Exiting.")
            sys.exit(1)
        
        # Get the certificate PEM from the agent data
        # Actually, cert_pem is in the DB but not returned in AgentResponse
        # We need to either:
        # 1. Get it from the DB directly
        # 2. Read it from the key directory
        # 3. Modify the API to return it (but that's not secure for production)
        # For demo, let's read it from the registry's stored cert
        
        # Get agent again to ensure we have latest data
        agent_data = get_agent(client, agent_name)
        if not agent_data:
            print("ERROR: Could not retrieve agent. Exiting.")
            sys.exit(1)
        
        # For verification, we need the actual cert PEM
        # In a real scenario, the agent would present its cert
        # For demo, we'll need to get it from somewhere
        # Let's check if we can get it from resolve endpoint or modify approach
        
        # Actually, let's use the resolve endpoint to get cert fingerprint
        # and then we can verify using a cert we generate locally for demo
        # OR we can store the cert_pem in a way we can access it
        
        # Better approach: After registration, the cert is stored in DB
        # We can create a helper to get cert from DB or from file system
        # For now, let's assume we can get it via a modified flow
        
        # Step 2: Verify certificate
        cert_pem = get_agent_cert_from_db(agent_name)
        if cert_pem:
            verify_result = verify_certificate(client, cert_pem)
            if verify_result.get("verified"):
                print("✓ Certificate verification SUCCESS")
            else:
                print(f"✗ Certificate verification FAILED: {verify_result.get('reason')}")
        else:
            print("WARNING: Could not retrieve certificate from database")
        
        # Step 3: Rotate
        rotate_data = rotate_certificate(client, agent_name)
        if not rotate_data:
            print("ERROR: Rotation failed. Exiting.")
            sys.exit(1)
        
        # Step 4: Verify after rotation
        cert_pem = get_agent_cert_from_db(agent_name)
        if cert_pem:
            verify_result = verify_certificate(client, cert_pem)
            if verify_result.get("verified"):
                print("✓ Certificate verification SUCCESS (after rotation)")
            else:
                print(f"✗ Certificate verification FAILED: {verify_result.get('reason')}")
        
        # Step 5: Revoke
        revoke_data = revoke_agent(client, agent_name)
        if not revoke_data:
            print("ERROR: Revocation failed. Exiting.")
            sys.exit(1)
        
        # Step 6: Verify after revocation (should fail)
        cert_pem = get_agent_cert_from_db(agent_name)
        if cert_pem:
            verify_result = verify_certificate(client, cert_pem)
            if not verify_result.get("verified"):
                print(f"✓ Certificate verification correctly FAILED (revoked): {verify_result.get('reason')}")
            else:
                print("✗ ERROR: Certificate verification should have failed but didn't!")
    
    print("\n" + "="*60)
    print("DEMO COMPLETE")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
