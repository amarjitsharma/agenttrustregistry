"""Tests for input validators"""
import pytest
from atr.core.validators import validate_agent_name


def test_valid_agent_names():
    """Test valid agent name formats"""
    valid_names = [
        "agent",
        "my-agent",
        "agent.example",
        "agent-123.example",
        "a",
        "a" * 63 + ".example",  # Max label length (63) with domain
        "agent123",
        "agent.example.com",
        # Test max total length with multiple labels
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60,  # 253 chars total
    ]
    
    for name in valid_names:
        result = validate_agent_name(name)
        assert result is None, f"'{name}' should be valid but got: {result}"


def test_invalid_agent_names():
    """Test invalid agent name formats"""
    invalid_cases = [
        ("", "empty string"),
        ("AGENT", "uppercase"),
        ("agent_underscore", "underscore"),
        (".agent", "leading dot"),
        ("agent.", "trailing dot"),
        ("agent..example", "consecutive dots"),
        ("agent/example", "slash"),
        ("agent example", "space"),
        ("agent@example", "at sign"),
        ("a" * 254, "too long"),
        ("-agent", "leading hyphen"),
        ("agent-", "trailing hyphen"),
    ]
    
    for name, reason in invalid_cases:
        result = validate_agent_name(name)
        assert result is not None, f"'{name}' should be invalid ({reason}) but validation passed"


def test_label_length_limit():
    """Test that individual labels respect 63 character limit"""
    # Valid: 63 chars per label
    valid_long_label = "a" * 63 + ".example"
    assert validate_agent_name(valid_long_label) is None
    
    # Invalid: 64 chars in a label
    invalid_long_label = "a" * 64 + ".example"
    result = validate_agent_name(invalid_long_label)
    assert result is not None
    assert "63" in result
