"""Executor layer for plan-driven execution.

This module provides:
- PlanBuilder: Builds enhanced execution plans from intent
- ExecutionEngine: Drives plan execution step by step
- Executor: Main facade that ties everything together

The executor layer extends the governance layer to make plans
a driving force behind execution, not just a validation mechanism.

Key concepts:
- EnhancedExecutionPlan: Plan with conditionals, recovery, constraints
- ExecutionMode: GOVERNANCE_DRIVEN, AGENT_GUIDED, or HYBRID
- OperationalKnowledge: User-provided knowledge about how to execute
- PlanPreview: Preview for user review before execution

Example usage:
    from src.executor import Executor, ExecutorConfig
    
    config = ExecutorConfig(
        db_path="data/executor.db",
        secret="your-secret-key",
        policy_path="config/governance-policies.json",
        patterns_path="config/intent-patterns.json",
    )
    
    executor = Executor(config, tool_executor)
    
    # Build plan with operational knowledge
    plan = executor.build_plan(
        request_body={"tools": [...]},
        user_id="user-123",
        operational_knowledge={
            "constraints": ["Do not delete files"],
            "preferences": ["Prefer read-only operations"],
            "execution_mode": "governance_driven",
        },
    )
    
    # Preview for user
    preview = executor.preview(plan)
    print(preview.description)
    print(f"Risk: {preview.risk_level}")
    
    # Execute after approval
    state = await executor.execute(plan, user_id="user-123")
"""

from src.executor.models import (
    ConditionalBranch,
    EnhancedExecutionPlan,
    ExecutionContext,
    ExecutionMode,
    ExecutionState,
    PlanPreview,
    RecoveryPath,
    RecoveryStrategy,
    StepResult,
    StepStatus,
)

from src.executor.builder import (
    OperationalKnowledge,
    PlanBuilder,
)

from src.executor.engine import (
    AgentContextInjector,
    ExecutionEngine,
    ExecutionError,
    GovernanceBlockedError,
    ToolExecutorAdapter,
)

from src.executor.facade import (
    Executor,
    ExecutorConfig,
)

__all__ = [
    # Models
    "ConditionalBranch",
    "EnhancedExecutionPlan",
    "ExecutionContext",
    "ExecutionMode",
    "ExecutionState",
    "PlanPreview",
    "RecoveryPath",
    "RecoveryStrategy",
    "StepResult",
    "StepStatus",
    # Builder
    "OperationalKnowledge",
    "PlanBuilder",
    # Engine
    "AgentContextInjector",
    "ExecutionEngine",
    "ExecutionError",
    "GovernanceBlockedError",
    "ToolExecutorAdapter",
    # Facade
    "Executor",
    "ExecutorConfig",
]
