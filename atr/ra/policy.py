"""Basic Policy Engine for RA Orchestration (v0.4)

This module provides a basic policy engine for evaluating rules and policies
during agent registration, certificate issuance, and lifecycle operations.
"""
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime


class PolicyAction(str, Enum):
    """Policy action types"""
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE = "require"


@dataclass
class PolicyRule:
    """Represents a policy rule"""
    name: str
    action: PolicyAction
    condition: Callable[[Dict[str, Any]], bool]
    message: Optional[str] = None
    priority: int = 100  # Lower number = higher priority


@dataclass
class PolicyResult:
    """Result of policy evaluation"""
    allowed: bool
    denied: bool
    warnings: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)


class PolicyEngine:
    """Basic policy engine for rule evaluation"""
    
    def __init__(self):
        self.rules: List[PolicyRule] = []
    
    def add_rule(self, rule: PolicyRule):
        """Add a policy rule"""
        self.rules.append(rule)
        # Sort by priority (lower number = higher priority)
        self.rules.sort(key=lambda r: r.priority)
    
    def evaluate(self, context: Dict[str, Any]) -> PolicyResult:
        """
        Evaluate all policies against the given context.
        
        Args:
            context: Context data for policy evaluation
            
        Returns:
            PolicyResult with evaluation results
        """
        result = PolicyResult(allowed=True, denied=False)
        
        for rule in self.rules:
            try:
                if rule.condition(context):
                    if rule.action == PolicyAction.ALLOW:
                        result.allowed = True
                    elif rule.action == PolicyAction.DENY:
                        result.denied = True
                        result.allowed = False
                        if rule.message:
                            result.messages.append(rule.message)
                    elif rule.action == PolicyAction.WARN:
                        if rule.message:
                            result.warnings.append(rule.message)
                    elif rule.action == PolicyAction.REQUIRE:
                        if rule.message:
                            result.requirements.append(rule.message)
            except Exception as e:
                # Rule evaluation error - log but don't fail
                result.warnings.append(f"Policy rule '{rule.name}' evaluation error: {str(e)}")
        
        return result
    
    def clear_rules(self):
        """Clear all policy rules"""
        self.rules.clear()


# Pre-defined policy rules
def create_default_policies() -> List[PolicyRule]:
    """Create default policy rules"""
    rules = []
    
    # Agent name validation rule
    def validate_agent_name(context: Dict[str, Any]) -> bool:
        agent_name = context.get('agent_name', '')
        # Basic validation - name should not be empty
        return not agent_name or len(agent_name.strip()) == 0
    
    rules.append(PolicyRule(
        name="agent_name_required",
        action=PolicyAction.DENY,
        condition=validate_agent_name,
        message="Agent name is required",
        priority=10
    ))
    
    # Owner validation rule
    def validate_owner(context: Dict[str, Any]) -> bool:
        owner = context.get('owner', '')
        return not owner or len(owner.strip()) == 0
    
    rules.append(PolicyRule(
        name="owner_required",
        action=PolicyAction.DENY,
        condition=validate_owner,
        message="Owner is required",
        priority=20
    ))
    
    return rules


# Global policy engine instance
_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    """Get or create global policy engine instance with default rules"""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
        # Add default rules
        for rule in create_default_policies():
            _policy_engine.add_rule(rule)
    return _policy_engine
