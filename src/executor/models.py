"""Executor layer Pydantic models.

This module extends governance models with execution-focused structures:
- ExecutionContext: Runtime context for plan execution
- StepResult: Outcome of a single execution step
- ExecutionState: Full state machine for plan execution
- RecoveryAction: What to do when a step fails
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.governance.models import ExecutionPlan, PlannedAction, GovernanceDecision


class ExecutionMode(str, Enum):
    """How the plan should be executed."""
    
    # Governance drives execution, calls tools directly
    GOVERNANCE_DRIVEN = "governance_driven"
    
    # Plan is injected into LLM context, LLM executes
    AGENT_GUIDED = "agent_guided"
    
    # Hybrid: governance executes, LLM consulted for decisions
    HYBRID = "hybrid"


class StepStatus(str, Enum):
    """Status of a single execution step."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"  # Blocked by governance
    AWAITING_APPROVAL = "awaiting_approval"
    RECOVERED = "recovered"  # Failed but recovered


class RecoveryStrategy(str, Enum):
    """Strategy for handling step failures."""
    
    FAIL_FAST = "fail_fast"  # Stop execution immediately
    RETRY = "retry"  # Retry the same step
    SKIP = "skip"  # Skip and continue
    ALTERNATIVE = "alternative"  # Try alternative step
    REPLAN = "replan"  # Generate new sub-plan
    HUMAN_INTERVENTION = "human_intervention"  # Wait for human


class StepResult(BaseModel):
    """Outcome of executing a single step."""
    
    model_config = ConfigDict(frozen=True)
    
    sequence: int = Field(ge=0)
    status: StepStatus
    started_at: str
    completed_at: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    
    # Tool execution details
    tool_name: str
    tool_args: dict[str, Any]
    tool_result: Any | None = None
    error: str | None = None
    
    # Governance checks
    governance_decision: GovernanceDecision | None = None
    governance_reason: str | None = None
    
    # Recovery details
    retry_count: int = Field(default=0, ge=0)
    recovery_action: RecoveryStrategy | None = None


class ExecutionContext(BaseModel):
    """Runtime context passed through execution."""
    
    model_config = ConfigDict(frozen=True)
    
    plan_id: str
    session_id: str
    user_id: str
    token: str
    
    # Execution configuration
    mode: ExecutionMode = ExecutionMode.GOVERNANCE_DRIVEN
    max_retries: int = Field(default=3, ge=0)
    timeout_seconds: int = Field(default=300, ge=1)
    fail_on_governance_block: bool = True
    
    # User-provided operational knowledge
    constraints: list[str] = Field(default_factory=list)
    preferences: dict[str, Any] = Field(default_factory=dict)


class ConditionalBranch(BaseModel):
    """A conditional branch in the execution plan."""
    
    model_config = ConfigDict(frozen=True)
    
    condition: str  # Expression to evaluate
    if_true: list[int]  # Sequence numbers to execute if true
    if_false: list[int] = Field(default_factory=list)  # Sequence numbers if false


class RecoveryPath(BaseModel):
    """Recovery path for a failed step."""
    
    model_config = ConfigDict(frozen=True)
    
    trigger_step: int  # Which step this recovers from
    trigger_errors: list[str] = Field(default_factory=list)  # Error patterns that trigger this
    strategy: RecoveryStrategy
    
    # For RETRY strategy
    max_retries: int = Field(default=3, ge=1)
    backoff_ms: int = Field(default=1000, ge=0)
    
    # For ALTERNATIVE strategy
    alternative_steps: list[PlannedAction] = Field(default_factory=list)
    
    # For REPLAN strategy
    replan_constraints: list[str] = Field(default_factory=list)


class EnhancedExecutionPlan(BaseModel):
    """Execution plan with conditionals, recovery, and operational knowledge.
    
    Extends the base ExecutionPlan with:
    - Conditional branches
    - Recovery paths
    - User-provided constraints
    - Execution mode preferences
    """
    
    model_config = ConfigDict(frozen=True)
    
    # Base plan
    base_plan: ExecutionPlan
    
    # Enhanced execution semantics
    conditionals: list[ConditionalBranch] = Field(default_factory=list)
    recovery_paths: list[RecoveryPath] = Field(default_factory=list)
    
    # User operational knowledge
    description: str | None = None  # Human-readable description
    constraints: list[str] = Field(default_factory=list)  # Must-have constraints
    preferences: list[str] = Field(default_factory=list)  # Nice-to-have preferences
    
    # Execution configuration
    default_mode: ExecutionMode = ExecutionMode.GOVERNANCE_DRIVEN
    allow_mode_override: bool = False
    require_preview: bool = True  # User must preview before execution
    
    @property
    def plan_id(self) -> str:
        return self.base_plan.plan_id
    
    @property
    def actions(self) -> list[PlannedAction]:
        return self.base_plan.actions


class ExecutionState(BaseModel):
    """Full state machine for plan execution."""
    
    plan_id: str
    session_id: str
    context: ExecutionContext
    
    # Current position
    current_sequence: int = Field(default=0, ge=0)
    status: StepStatus = StepStatus.PENDING
    
    # History
    step_results: list[StepResult] = Field(default_factory=list)
    
    # Timestamps
    started_at: str | None = None
    completed_at: str | None = None
    
    # Summary
    total_steps: int = Field(ge=0)
    completed_steps: int = Field(default=0, ge=0)
    failed_steps: int = Field(default=0, ge=0)
    skipped_steps: int = Field(default=0, ge=0)
    
    def is_complete(self) -> bool:
        """Check if execution is complete."""
        return self.current_sequence >= self.total_steps or self.status in (
            StepStatus.COMPLETED,
            StepStatus.FAILED,
            StepStatus.BLOCKED,
        )
    
    def get_progress(self) -> float:
        """Get execution progress as percentage."""
        if self.total_steps == 0:
            return 100.0
        return (self.completed_steps / self.total_steps) * 100


class PlanPreview(BaseModel):
    """Preview of execution plan for user review."""
    
    model_config = ConfigDict(frozen=True)
    
    plan_id: str
    description: str | None
    
    # What will happen
    steps: list[dict[str, Any]]  # Simplified step descriptions
    total_steps: int
    estimated_duration_seconds: int | None
    
    # Risk summary
    risk_level: str
    risk_factors: list[str]
    
    # What user can control
    constraints_applied: list[str]
    editable_parameters: list[str] = Field(default_factory=list)
    
    # Approval required?
    requires_approval: bool
    approval_reason: str | None = None
