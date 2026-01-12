"""Simplified Workflow Engine for RA Orchestration (v0.4)

This module provides a simplified workflow engine for multi-step operations
like agent registration, certificate renewal, and revocation.
"""
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field


class WorkflowStatus(str, Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStepStatus(str, Enum):
    """Individual step status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """Represents a single step in a workflow"""
    name: str
    handler: Callable
    required: bool = True
    retry_count: int = 0
    max_retries: int = 3
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class WorkflowContext:
    """Context data passed through workflow steps"""
    workflow_id: str
    agent_name: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)


class WorkflowEngine:
    """Simplified workflow engine for orchestration"""
    
    def __init__(self):
        self.workflows: Dict[str, List[WorkflowStep]] = {}
    
    def register_workflow(self, workflow_name: str, steps: List[WorkflowStep]):
        """Register a workflow with its steps"""
        self.workflows[workflow_name] = steps
    
    def execute_workflow(
        self,
        workflow_name: str,
        context: WorkflowContext,
        on_error: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Execute a workflow with given context.
        
        Args:
            workflow_name: Name of the workflow to execute
            context: Workflow context with data
            on_error: Optional error handler callback
            
        Returns:
            Dict with workflow execution results
        """
        if workflow_name not in self.workflows:
            raise ValueError(f"Workflow '{workflow_name}' not found")
        
        steps = self.workflows[workflow_name]
        context.data['workflow_status'] = WorkflowStatus.RUNNING.value
        
        for step in steps:
            step.status = WorkflowStepStatus.RUNNING
            step.started_at = datetime.utcnow()
            
            try:
                # Execute step handler
                result = step.handler(context)
                step.result = result if isinstance(result, dict) else {"result": result}
                step.status = WorkflowStepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                context.results[step.name] = step.result
                
            except Exception as e:
                step.error = str(e)
                step.status = WorkflowStepStatus.FAILED
                step.completed_at = datetime.utcnow()
                context.errors.append(f"Step '{step.name}' failed: {str(e)}")
                
                if step.required:
                    # Required step failed - stop workflow
                    context.data['workflow_status'] = WorkflowStatus.FAILED.value
                    if on_error:
                        on_error(step, context, e)
                    break
                else:
                    # Optional step failed - continue
                    step.status = WorkflowStepStatus.SKIPPED
                    continue
        
        # Determine final status
        if context.data.get('workflow_status') != WorkflowStatus.FAILED.value:
            if all(s.status in [WorkflowStepStatus.COMPLETED, WorkflowStepStatus.SKIPPED] for s in steps):
                context.data['workflow_status'] = WorkflowStatus.COMPLETED.value
            else:
                context.data['workflow_status'] = WorkflowStatus.FAILED.value
        
        return {
            "workflow_id": context.workflow_id,
            "status": context.data['workflow_status'],
            "steps": [
                {
                    "name": step.name,
                    "status": step.status.value,
                    "error": step.error,
                    "started_at": step.started_at.isoformat() if step.started_at else None,
                    "completed_at": step.completed_at.isoformat() if step.completed_at else None,
                }
                for step in steps
            ],
            "results": context.results,
            "errors": context.errors
        }


# Global workflow engine instance
_workflow_engine: Optional[WorkflowEngine] = None


def get_workflow_engine() -> WorkflowEngine:
    """Get or create global workflow engine instance"""
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine
