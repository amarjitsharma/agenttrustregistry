"""Public certificate issuance via ACME (Let's Encrypt)"""
from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from atr.core.config import settings
from atr.pki.fingerprints import compute_fingerprint


class PublicCertificateIssuer:
    """Issues public TLS certificates via ACME protocol (Let's Encrypt)"""
    
    def __init__(self):
        self.acme_directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # Production
        # For staging/testing: "https://acme-staging-v02.api.letsencrypt.org/directory"
        self.acme_enabled = getattr(settings, 'acme_enabled', False)
        self.acme_account_email = getattr(settings, 'acme_account_email', None)
        self.acme_account_key_path = settings.pki_root_dir / "acme_account.key"
        
    def issue_public_certificate(
        self, 
        agent_name: str,
        domain: Optional[str] = None
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
        """
        Issue a public TLS certificate via ACME (Let's Encrypt).
        
        Note: This is a simplified implementation. Full ACME requires:
        - Account registration
        - Order creation
        - Challenge validation (HTTP-01, DNS-01, or TLS-ALPN-01)
        - Certificate download
        
        For POC, we'll use a mock/stub implementation that simulates the process.
        In production, integrate with certbot or acme-python library.
        
        Args:
            agent_name: Agent name (used as domain if domain not provided)
            domain: Optional domain name (defaults to agent_name)
            
        Returns:
            Tuple of (private_key, certificate, fingerprint)
            
        Raises:
            NotImplementedError: If ACME is not fully implemented
        """
        if not self.acme_enabled:
            raise ValueError("ACME/Let's Encrypt integration is not enabled")
        
        # For POC, we'll create a certificate that looks like a public cert
        # but is actually signed by our intermediate CA (simulated public CA)
        # In production, this would be a real Let's Encrypt certificate
        
        # Use domain or agent_name
        cert_domain = domain or agent_name
        
        # Generate keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate (simulated public CA certificate)
        # In production, this would come from Let's Encrypt via ACME
        from atr.pki.ca import get_ca
        ca = get_ca()
        intermediate_cert = ca.get_intermediate_cert()
        intermediate_key = ca.get_intermediate_key()
        
        # Create certificate with public CA-like characteristics
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cert_domain),
        ])
        
        san = x509.SubjectAlternativeName([
            x509.DNSName(cert_domain),
        ])
        
        # Simulate longer validity (Let's Encrypt issues 90-day certs)
        validity_days = 90
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            intermediate_cert.subject  # In production, this would be Let's Encrypt's CA
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
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
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        ).add_extension(
            san,
            critical=False,
        ).sign(intermediate_key, hashes.SHA256())
        
        fingerprint = compute_fingerprint(cert)
        
        return private_key, cert, fingerprint
    
    def renew_public_certificate(
        self,
        agent_name: str,
        current_cert: x509.Certificate
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
        """
        Renew a public certificate before expiration.
        
        Args:
            agent_name: Agent name
            current_cert: Current public certificate
            
        Returns:
            Tuple of (private_key, certificate, fingerprint)
        """
        # Extract domain from current cert
        try:
            domain = current_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except (IndexError, AttributeError):
            domain = agent_name
        
        return self.issue_public_certificate(agent_name, domain)


def issue_public_certificate(agent_name: str, domain: Optional[str] = None) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, str]:
    """
    Convenience function to issue a public certificate.
    
    Args:
        agent_name: Agent name
        domain: Optional domain name
        
    Returns:
        Tuple of (private_key, certificate, fingerprint)
    """
    issuer = PublicCertificateIssuer()
    return issuer.issue_public_certificate(agent_name, domain)
