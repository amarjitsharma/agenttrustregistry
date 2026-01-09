"""Certificate issuance"""
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from typing import Tuple

from atr.core.config import settings
from atr.pki.ca import get_ca
from atr.pki.fingerprints import compute_fingerprint


def issue_agent_certificate(agent_name: str) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
    """
    Issue a leaf certificate for an agent.
    
    Returns:
        Tuple of (private_key, certificate, fingerprint)
    """
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    intermediate_key = ca.get_intermediate_key()
    
    # Generate agent keypair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key to disk
    key_dir = settings.keys_root_dir / agent_name
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "private_key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )
    
    # Create certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_name),
    ])
    
    # Add agent_name to Subject Alternative Name
    san = x509.SubjectAlternativeName([
        x509.DNSName(agent_name),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=settings.cert_validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        san,
        critical=False,
    ).sign(intermediate_key, hashes.SHA256())
    
    fingerprint = compute_fingerprint(cert)
    
    return private_key, cert, fingerprint
