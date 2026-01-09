"""Security utilities"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509


def compute_fingerprint(cert: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint of a certificate"""
    return cert.fingerprint(hashes.SHA256()).hex().upper()
