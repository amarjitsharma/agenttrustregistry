"""Fingerprint utilities"""
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def compute_fingerprint(cert: x509.Certificate) -> str:
    """Compute SHA-256 fingerprint of a certificate"""
    return cert.fingerprint(hashes.SHA256()).hex().upper()
