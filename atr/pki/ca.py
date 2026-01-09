"""Certificate Authority management"""
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from typing import Tuple, Optional

from atr.core.config import settings


class CA:
    """Local Certificate Authority"""
    
    def __init__(self):
        self.root_ca_path = settings.pki_root_dir / "root_ca.pem"
        self.root_key_path = settings.pki_root_dir / "root_ca.key"
        self.intermediate_ca_path = settings.pki_root_dir / "intermediate_ca.pem"
        self.intermediate_key_path = settings.pki_root_dir / "intermediate_ca.key"
        
        self.root_cert: Optional[x509.Certificate] = None
        self.root_key: Optional[rsa.RSAPrivateKey] = None
        self.intermediate_cert: Optional[x509.Certificate] = None
        self.intermediate_key: Optional[rsa.RSAPrivateKey] = None
        
        self._ensure_ca_exists()
    
    def _ensure_ca_exists(self) -> None:
        """Create root and intermediate CA if they don't exist"""
        if not self.root_ca_path.exists() or not self.root_key_path.exists():
            self._create_root_ca()
        
        if not self.intermediate_ca_path.exists() or not self.intermediate_key_path.exists():
            self._create_intermediate_ca()
        
        self._load_ca()
    
    def _create_root_ca(self) -> None:
        """Create root CA certificate and key"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ATR Dev Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ATR Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=settings.ca_validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # Save to disk
        self.root_ca_path.write_bytes(cert.public_bytes(Encoding.PEM))
        self.root_key_path.write_bytes(
            private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )
    
    def _create_intermediate_ca(self) -> None:
        """Create intermediate CA certificate and key"""
        # Load root CA
        if not self.root_cert or not self.root_key:
            self._load_root_ca()
        
        # Generate intermediate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate signed by root
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ATR Dev Intermediate CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ATR Intermediate CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.root_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=settings.ca_validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(self.root_key, hashes.SHA256())
        
        # Save to disk
        self.intermediate_ca_path.write_bytes(cert.public_bytes(Encoding.PEM))
        self.intermediate_key_path.write_bytes(
            private_key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
        )
    
    def _load_root_ca(self) -> None:
        """Load root CA certificate and key from disk"""
        self.root_cert = x509.load_pem_x509_certificate(
            self.root_ca_path.read_bytes()
        )
        self.root_key = serialization.load_pem_private_key(
            self.root_key_path.read_bytes(),
            password=None
        )
    
    def _load_intermediate_ca(self) -> None:
        """Load intermediate CA certificate and key from disk"""
        self.intermediate_cert = x509.load_pem_x509_certificate(
            self.intermediate_ca_path.read_bytes()
        )
        self.intermediate_key = serialization.load_pem_private_key(
            self.intermediate_key_path.read_bytes(),
            password=None
        )
    
    def _load_ca(self) -> None:
        """Load both root and intermediate CA"""
        self._load_root_ca()
        self._load_intermediate_ca()
    
    def get_intermediate_cert(self) -> x509.Certificate:
        """Get intermediate CA certificate"""
        return self.intermediate_cert
    
    def get_intermediate_key(self) -> rsa.RSAPrivateKey:
        """Get intermediate CA private key"""
        return self.intermediate_key


# Global CA instance
_ca_instance: Optional[CA] = None


def get_ca() -> CA:
    """Get or create the global CA instance"""
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = CA()
    return _ca_instance
