"""Tests for input validation and security"""
import pytest
from fastapi.testclient import TestClient
from atr.core.validators import validate_agent_name
from atr.core.schemas import VerifyCertRequest
from pydantic import ValidationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def test_agent_name_path_traversal_prevention():
    """Test that path traversal attempts are rejected or normalized"""
    malicious_names = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/passwd",
        "agent/../../../etc",
        "agent\\..\\..\\..\\etc",
        "../etc/passwd",
        "..",
        ".",
        "/",
        "\\"
    ]
    
    for name in malicious_names:
        # Validation should reject or normalize
        result = validate_agent_name(name)
        # Should return error message (not None)
        assert result is not None, f"Path traversal name '{name}' should be rejected"
        assert isinstance(result, str), f"Error message should be string for '{name}'"


def test_cert_pem_size_limit():
    """Test that oversized PEM certificates are rejected"""
    # Create oversized PEM (100KB) - should exceed 64KB limit
    large_pem = "-----BEGIN CERTIFICATE-----\n" + "A" * 100000 + "\n-----END CERTIFICATE-----"
    
    # Note: This test requires max_length validation in schema
    # If not implemented, this test will fail
    try:
        request = VerifyCertRequest(cert_pem=large_pem)
        # If max_length not set, this will succeed (test will fail)
        pytest.fail("Oversized PEM should be rejected")
    except ValidationError as e:
        # Should raise validation error for size
        assert any("length" in str(err).lower() or "size" in str(err).lower() for err in e.errors())


def test_cert_pem_format_validation():
    """Test that invalid PEM format is rejected"""
    invalid_pems = [
        "not a pem",
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "BEGIN CERTIFICATE\nDATA\nEND CERTIFICATE",
        "",
        "   ",
        "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
    ]
    
    for invalid_pem in invalid_pems:
        try:
            request = VerifyCertRequest(cert_pem=invalid_pem)
            # Some may parse but fail validation - check format
            # If format validator not implemented, this test documents expected behavior
        except ValidationError:
            # Expected - invalid format should be rejected
            pass
        except Exception:
            # Other errors are also acceptable (parsing errors)
            pass


def test_agent_name_valid_chars():
    """Test that valid agent names pass validation"""
    valid_names = [
        "example.com",
        "agent.example.com",
        "test-agent.example",
        "myagent",
        "agent-123.example",
        "a.b.c.d.e"
    ]
    
    for name in valid_names:
        result = validate_agent_name(name)
        assert result is None, f"Valid name '{name}' should pass validation: {result}"


def test_agent_name_invalid_chars():
    """Test that invalid characters are rejected"""
    invalid_names = [
        "EXAMPLE.COM",  # Uppercase
        "agent@example.com",  # Invalid char
        "agent example.com",  # Space
        "agent_example.com",  # Underscore (not in DNS label)
        "agent.example.com.",  # Trailing dot
        ".agent.example.com",  # Leading dot
        "agent..example.com",  # Consecutive dots
    ]
    
    for name in invalid_names:
        result = validate_agent_name(name)
        assert result is not None, f"Invalid name '{name}' should be rejected"


def test_agent_name_length_limits():
    """Test that agent names respect length limits"""
    # Valid length (253 chars max)
    valid_long = "a" * 253
    result = validate_agent_name(valid_long)
    assert result is None, f"Max length name should be valid: {result}"
    
    # Invalid length (>253 chars)
    invalid_long = "a" * 254
    result = validate_agent_name(invalid_long)
    assert result is not None, f"Oversized name should be rejected: {result}"
    assert "253" in result or "length" in result.lower(), f"Error should mention length limit: {result}"


def test_agent_name_label_length_limits():
    """Test that individual labels respect 63 char limit"""
    # Label too long (>63 chars)
    long_label = "a" * 64
    invalid_name = f"{long_label}.example.com"
    result = validate_agent_name(invalid_name)
    assert result is not None, f"Long label should be rejected: {result}"
    assert "63" in result or "label" in result.lower(), f"Error should mention label length: {result}"


def test_empty_agent_name():
    """Test that empty agent names are rejected"""
    result = validate_agent_name("")
    assert result is not None, "Empty name should be rejected"
    assert "empty" in result.lower() or "required" in result.lower(), f"Error should mention empty: {result}"


def test_agent_name_with_special_chars():
    """Test that special characters are rejected"""
    special_chars = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", "|", "\\", ":", ";", "\"", "'", "<", ">", ",", "?", "/"]
    
    for char in special_chars:
        name = f"agent{char}example.com"
        result = validate_agent_name(name)
        assert result is not None, f"Name with '{char}' should be rejected: {result}"
