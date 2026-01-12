"""Tests for RA Workflow Engine (v0.4)"""
import pytest
from datetime import datetime
from typing import Dict, Any

from atr.ra.workflow import (
    WorkflowEngine, WorkflowContext, WorkflowStep,
    WorkflowStatus, WorkflowStepStatus
)


def test_workflow_engine_registration():
    """Test workflow engine registration"""
    engine = WorkflowEngine()
    
    def step1(context: WorkflowContext) -> Dict[str, Any]:
        return {"step1": "completed"}
    
    def step2(context: WorkflowContext) -> Dict[str, Any]:
        return {"step2": "completed"}
    
    steps = [
        WorkflowStep(name="step1", handler=step1),
        WorkflowStep(name="step2", handler=step2),
    ]
    
    engine.register_workflow("test_workflow", steps)
    
    assert "test_workflow" in engine.workflows
    assert len(engine.workflows["test_workflow"]) == 2


def test_workflow_engine_execution():
    """Test workflow engine execution"""
    engine = WorkflowEngine()
    
    def step1(context: WorkflowContext) -> Dict[str, Any]:
        context.data["step1_result"] = "done"
        return {"step1": "completed"}
    
    def step2(context: WorkflowContext) -> Dict[str, Any]:
        context.data["step2_result"] = "done"
        return {"step2": "completed"}
    
    steps = [
        WorkflowStep(name="step1", handler=step1),
        WorkflowStep(name="step2", handler=step2),
    ]
    
    engine.register_workflow("test_workflow", steps)
    
    context = WorkflowContext(workflow_id="test-123")
    result = engine.execute_workflow("test_workflow", context)
    
    assert result["status"] == WorkflowStatus.COMPLETED.value
    assert len(result["steps"]) == 2
    assert all(step["status"] == WorkflowStepStatus.COMPLETED.value for step in result["steps"])


def test_workflow_engine_failure():
    """Test workflow engine failure handling"""
    engine = WorkflowEngine()
    
    def step1(context: WorkflowContext) -> Dict[str, Any]:
        return {"step1": "completed"}
    
    def step2_fail(context: WorkflowContext) -> Dict[str, Any]:
        raise ValueError("Step failed")
    
    steps = [
        WorkflowStep(name="step1", handler=step1, required=True),
        WorkflowStep(name="step2", handler=step2_fail, required=True),
    ]
    
    engine.register_workflow("test_workflow", steps)
    
    context = WorkflowContext(workflow_id="test-123")
    result = engine.execute_workflow("test_workflow", context)
    
    assert result["status"] == WorkflowStatus.FAILED.value
    assert len(result["steps"]) == 2
    assert result["steps"][0]["status"] == WorkflowStepStatus.COMPLETED.value
    assert result["steps"][1]["status"] == WorkflowStepStatus.FAILED.value
    assert len(result["errors"]) > 0


def test_workflow_engine_optional_step_failure():
    """Test workflow engine with optional step failure"""
    engine = WorkflowEngine()
    
    def step1(context: WorkflowContext) -> Dict[str, Any]:
        return {"step1": "completed"}
    
    def step2_fail(context: WorkflowContext) -> Dict[str, Any]:
        raise ValueError("Step failed")
    
    steps = [
        WorkflowStep(name="step1", handler=step1, required=True),
        WorkflowStep(name="step2", handler=step2_fail, required=False),
        WorkflowStep(name="step3", handler=step1, required=True),
    ]
    
    engine.register_workflow("test_workflow", steps)
    
    context = WorkflowContext(workflow_id="test-123")
    result = engine.execute_workflow("test_workflow", context)
    
    # Should complete despite optional step failure
    assert result["status"] == WorkflowStatus.COMPLETED.value
    assert result["steps"][1]["status"] == WorkflowStepStatus.SKIPPED.value
