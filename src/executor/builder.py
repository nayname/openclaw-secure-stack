"""Plan builder for the executor layer.

This module provides the PlanBuilder class for:
- Taking classified intent and building enhanced execution plans
- Incorporating user operational knowledge (constraints, preferences)
- Adding conditional branches and recovery paths
- Generating previews for user review
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from src.governance.models import (
    ExecutionPlan,
    Intent,
    IntentCategory,
    PlannedAction,
)
from src.governance.planner import PlanGenerator
from src.executor.models import (
    ConditionalBranch,
    EnhancedExecutionPlan,
    ExecutionMode,
    PlanPreview,
    RecoveryPath,
    RecoveryStrategy,
)


# Default recovery strategies by intent category
DEFAULT_RECOVERY_STRATEGIES: dict[IntentCategory, RecoveryStrategy] = {
    IntentCategory.FILE_READ: RecoveryStrategy.SKIP,
    IntentCategory.FILE_WRITE: RecoveryStrategy.RETRY,
    IntentCategory.FILE_DELETE: RecoveryStrategy.FAIL_FAST,
    IntentCategory.NETWORK_REQUEST: RecoveryStrategy.RETRY,
    IntentCategory.CODE_EXECUTION: RecoveryStrategy.FAIL_FAST,
    IntentCategory.SKILL_INVOCATION: RecoveryStrategy.RETRY,
    IntentCategory.SYSTEM_COMMAND: RecoveryStrategy.FAIL_FAST,
    IntentCategory.UNKNOWN: RecoveryStrategy.FAIL_FAST,
}


class OperationalKnowledge(dict):
    """User-provided operational knowledge for plan construction.
    
    This is a typed dict-like container for:
    - constraints: Hard requirements that must be satisfied
    - preferences: Soft requirements that should be satisfied if possible
    - recovery_hints: User guidance on how to handle failures
    - execution_mode: Preferred execution mode
    """
    
    @property
    def constraints(self) -> list[str]:
        return self.get("constraints", [])
    
    @property
    def preferences(self) -> list[str]:
        return self.get("preferences", [])
    
    @property
    def recovery_hints(self) -> dict[str, str]:
        return self.get("recovery_hints", {})
    
    @property
    def execution_mode(self) -> ExecutionMode | None:
        mode = self.get("execution_mode")
        if mode:
            return ExecutionMode(mode)
        return None
    
    @property
    def require_preview(self) -> bool:
        return self.get("require_preview", True)
    
    @property
    def max_retries(self) -> int:
        return self.get("max_retries", 3)


class PlanBuilder:
    """Builds enhanced execution plans from intent and operational knowledge.
    
    The builder:
    1. Uses the base PlanGenerator to create an ExecutionPlan
    2. Enhances it with conditionals, recovery paths, constraints
    3. Generates a preview for user review
    4. Allows user to edit parameters before execution
    """
    
    def __init__(self, base_planner: PlanGenerator) -> None:
        """Initialize the plan builder.
        
        Args:
            base_planner: The underlying governance plan generator.
        """
        self._base_planner = base_planner
    
    def build(
        self,
        intent: Intent,
        request_body: dict[str, Any],
        session_id: str | None = None,
        operational_knowledge: OperationalKnowledge | None = None,
    ) -> EnhancedExecutionPlan:
        """Build an enhanced execution plan.
        
        Args:
            intent: Classified intent from the request.
            request_body: Original request body.
            session_id: Optional session ID.
            operational_knowledge: User-provided operational knowledge.
            
        Returns:
            An EnhancedExecutionPlan ready for preview/execution.
        """
        op_knowledge = operational_knowledge or OperationalKnowledge()
        
        # Generate base plan
        base_plan = self._base_planner.generate(
            intent=intent,
            request_body=request_body,
            session_id=session_id,
        )
        
        # Build recovery paths
        recovery_paths = self._build_recovery_paths(base_plan, op_knowledge)
        
        # Build conditionals (if any)
        conditionals = self._build_conditionals(base_plan, op_knowledge)
        
        # Determine execution mode
        default_mode = op_knowledge.execution_mode or ExecutionMode.GOVERNANCE_DRIVEN
        
        # Build enhanced plan
        return EnhancedExecutionPlan(
            base_plan=base_plan,
            conditionals=conditionals,
            recovery_paths=recovery_paths,
            description=self._generate_description(base_plan),
            constraints=op_knowledge.constraints,
            preferences=op_knowledge.preferences,
            default_mode=default_mode,
            allow_mode_override=False,
            require_preview=op_knowledge.require_preview,
        )
    
    def generate_preview(self, plan: EnhancedExecutionPlan) -> PlanPreview:
        """Generate a preview of the execution plan for user review.
        
        Args:
            plan: The enhanced execution plan.
            
        Returns:
            A PlanPreview for user inspection.
        """
        # Simplify steps for display
        steps = []
        for action in plan.actions:
            steps.append({
                "sequence": action.sequence,
                "tool": action.tool_call.name,
                "category": action.category.value,
                "risk_score": action.risk_score,
                "resources": [
                    {"type": r.type, "path": r.path, "operation": r.operation}
                    for r in action.resources
                ],
            })
        
        # Estimate duration (rough: 5 seconds per action)
        estimated_duration = len(steps) * 5
        
        # Check if approval required
        risk = plan.base_plan.risk_assessment
        requires_approval = risk.level.value in ("high", "critical")
        approval_reason = None
        if requires_approval:
            approval_reason = f"Risk level is {risk.level.value}: {', '.join(risk.factors)}"
        
        return PlanPreview(
            plan_id=plan.plan_id,
            description=plan.description,
            steps=steps,
            total_steps=len(steps),
            estimated_duration_seconds=estimated_duration,
            risk_level=risk.level.value,
            risk_factors=risk.factors,
            constraints_applied=plan.constraints,
            editable_parameters=self._get_editable_parameters(plan),
            requires_approval=requires_approval,
            approval_reason=approval_reason,
        )
    
    def _build_recovery_paths(
        self,
        plan: ExecutionPlan,
        op_knowledge: OperationalKnowledge,
    ) -> list[RecoveryPath]:
        """Build recovery paths for each action based on category and user hints."""
        paths = []
        
        for action in plan.actions:
            # Get default strategy for category
            strategy = DEFAULT_RECOVERY_STRATEGIES.get(
                action.category,
                RecoveryStrategy.FAIL_FAST,
            )
            
            # Check user hints for override
            tool_name = action.tool_call.name
            if tool_name in op_knowledge.recovery_hints:
                hint = op_knowledge.recovery_hints[tool_name]
                try:
                    strategy = RecoveryStrategy(hint)
                except ValueError:
                    pass  # Keep default
            
            # Build recovery path
            max_retries = op_knowledge.max_retries if strategy == RecoveryStrategy.RETRY else 1
            
            paths.append(RecoveryPath(
                trigger_step=action.sequence,
                trigger_errors=[],  # Match any error
                strategy=strategy,
                max_retries=max_retries,
                backoff_ms=1000,
            ))
        
        return paths
    
    def _build_conditionals(
        self,
        plan: ExecutionPlan,
        op_knowledge: OperationalKnowledge,
    ) -> list[ConditionalBranch]:
        """Build conditional branches based on operational knowledge.
        
        Currently returns empty list - conditionals would be built from
        user-provided branching logic or inferred from multi-path tasks.
        """
        # TODO: Implement conditional inference from operational knowledge
        return []
    
    def _generate_description(self, plan: ExecutionPlan) -> str:
        """Generate a human-readable description of the plan."""
        categories = set(a.category.value for a in plan.actions)
        n_actions = len(plan.actions)
        risk = plan.risk_assessment.level.value
        
        category_str = ", ".join(sorted(categories))
        return f"Execute {n_actions} action(s) involving {category_str}. Risk level: {risk}."
    
    def _get_editable_parameters(self, plan: EnhancedExecutionPlan) -> list[str]:
        """Get list of parameters the user can edit before execution."""
        editable = []
        
        for action in plan.actions:
            for key in action.tool_call.arguments:
                param_name = f"step_{action.sequence}.{key}"
                editable.append(param_name)
        
        return editable
