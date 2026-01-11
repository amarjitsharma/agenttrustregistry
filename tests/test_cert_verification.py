"""Tests for certificate signature verification"""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from atr.pki.ca import get_ca
from atr.pki.fingerprints import compute_fingerprint


def test_verify_valid_cert_signature():
    """Test that valid certificate signature is verified"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    intermediate_key = ca.get_intermediate_key()
    
    # Create a test certificate signed by intermediate CA
    private_key = rsa.generate_private_key(65537, 2048)
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-signature.example")])
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
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
        critical=True
    ).sign(intermediate_key, hashes.SHA256())
    
    # Verify signature using intermediate CA's public key
    intermediate_public_key = intermediate_cert.public_key()
    assert isinstance(intermediate_public_key, rsa.RSAPublicKey)
    
    # Verify signature - should not raise exception
    intermediate_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # If we reach here, verification succeeded


def test_verify_invalid_cert_signature_fails():
    """Test that invalid certificate signature fails verification"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    
    # Create a certificate signed by different key (wrong key)
    wrong_key = rsa.generate_private_key(65537, 2048)
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-invalid.example")])
    ).issuer_name(
        intermediate_cert.subject  # Same issuer name, but wrong signature
    ).public_key(
        wrong_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
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
        critical=True
    ).sign(wrong_key, hashes.SHA256())  # Signed by wrong key!
    
    # Verify signature using intermediate CA's public key should fail
    intermediate_public_key = intermediate_cert.public_key()
    assert isinstance(intermediate_public_key, rsa.RSAPublicKey)
    
    # Verify signature should raise exception (InvalidSignature)
    from cryptography.exceptions import InvalidSignature
    with pytest.raises(InvalidSignature):
        intermediate_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )


def test_verify_cert_with_wrong_issuer_fails():
    """Test that certificate with wrong issuer subject fails"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    intermediate_key = ca.get_intermediate_key()
    
    # Create certificate with wrong issuer subject
    wrong_key = rsa.generate_private_key(65537, 2048)
    wrong_issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA")
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-wrong-issuer.example")])
    ).issuer_name(
        wrong_issuer  # Wrong issuer
    ).public_key(
        wrong_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(wrong_key, hashes.SHA256())
    
    # Issuer should not match
    assert cert.issuer != intermediate_cert.subject


def test_cert_signature_verification_vs_subject_match():
    """Test that signature verification is different from subject match"""
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    intermediate_key = ca.get_intermediate_key()
    
    # Create a valid certificate
    private_key = rsa.generate_private_key(65537, 2048)
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-subject-match.example")])
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).sign(intermediate_key, hashes.SHA256())
    
    # Subject match should pass
    assert cert.issuer == intermediate_cert.subject
    
    # Signature verification should also pass
    intermediate_public_key = intermediate_cert.public_key()
    assert isinstance(intermediate_public_key, rsa.RSAPublicKey)
    intermediate_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # Both checks should pass for valid certificate
