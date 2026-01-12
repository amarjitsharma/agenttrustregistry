"""Tests for RA Policy Engine (v0.4)"""
import pytest
from typing import Dict, Any

from atr.ra.policy import (
    PolicyEngine, PolicyRule, PolicyAction,
    PolicyResult, get_policy_engine
)


def test_policy_engine_add_rule():
    """Test adding policy rules"""
    engine = PolicyEngine()
    
    def condition(context: Dict[str, Any]) -> bool:
        return context.get("test", False)
    
    rule = PolicyRule(
        name="test_rule",
        action=PolicyAction.ALLOW,
        condition=condition
    )
    
    engine.add_rule(rule)
    assert len(engine.rules) == 1
    assert engine.rules[0].name == "test_rule"


def test_policy_engine_evaluation_allow():
    """Test policy evaluation with ALLOW action"""
    engine = PolicyEngine()
    
    def condition(context: Dict[str, Any]) -> bool:
        return context.get("allow", False)
    
    rule = PolicyRule(
        name="allow_rule",
        action=PolicyAction.ALLOW,
        condition=condition
    )
    
    engine.add_rule(rule)
    
    context = {"allow": True}
    result = engine.evaluate(context)
    
    assert result.allowed is True
    assert result.denied is False


def test_policy_engine_evaluation_deny():
    """Test policy evaluation with DENY action"""
    engine = PolicyEngine()
    
    def condition(context: Dict[str, Any]) -> bool:
        return context.get("deny", False)
    
    rule = PolicyRule(
        name="deny_rule",
        action=PolicyAction.DENY,
        condition=condition,
        message="Access denied"
    )
    
    engine.add_rule(rule)
    
    context = {"deny": True}
    result = engine.evaluate(context)
    
    assert result.allowed is False
    assert result.denied is True
    assert len(result.messages) > 0


def test_policy_engine_evaluation_warn():
    """Test policy evaluation with WARN action"""
    engine = PolicyEngine()
    
    def condition(context: Dict[str, Any]) -> bool:
        return context.get("warn", False)
    
    rule = PolicyRule(
        name="warn_rule",
        action=PolicyAction.WARN,
        condition=condition,
        message="Warning message"
    )
    
    engine.add_rule(rule)
    
    context = {"warn": True}
    result = engine.evaluate(context)
    
    assert result.allowed is True
    assert len(result.warnings) > 0
    assert "Warning message" in result.warnings


def test_policy_engine_default_policies():
    """Test default policy engine"""
    engine = get_policy_engine()
    
    # Default policies should be loaded
    assert len(engine.rules) > 0
    
    # Test with empty context (should fail validation)
    context = {}
    result = engine.evaluate(context)
    
    # Should have denial due to missing required fields
    assert result.denied is True or len(result.requirements) > 0


def test_policy_engine_priority():
    """Test policy rule priority ordering"""
    engine = PolicyEngine()
    
    def condition1(context: Dict[str, Any]) -> bool:
        return True
    
    def condition2(context: Dict[str, Any]) -> bool:
        return True
    
    rule1 = PolicyRule(
        name="low_priority",
        action=PolicyAction.ALLOW,
        condition=condition1,
        priority=100
    )
    
    rule2 = PolicyRule(
        name="high_priority",
        action=PolicyAction.DENY,
        condition=condition2,
        priority=10
    )
    
    # Add in reverse order
    engine.add_rule(rule1)
    engine.add_rule(rule2)
    
    # Should be sorted by priority (lower number = higher priority)
    assert engine.rules[0].priority == 10
    assert engine.rules[1].priority == 100
