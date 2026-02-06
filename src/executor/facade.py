"""Executor facade - main entry point for plan-driven execution.

This module provides the Executor class that orchestrates:
- Plan building from intent and operational knowledge
- Preview generation for user review
- Plan execution with governance enforcement
- State tracking and reporting
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable

from src.governance.classifier import IntentClassifier
from src.governance.enforcer import GovernanceEnforcer
from src.governance.middleware import GovernanceMiddleware
from src.governance.planner import PlanGenerator
from src.governance.store import PlanStore
from src.governance.validator import PolicyValidator

from src.executor.models import (
    EnhancedExecutionPlan,
    ExecutionContext,
    ExecutionMode,
    ExecutionState,
    PlanPreview,
    StepResult,
)
from src.executor.builder import PlanBuilder, OperationalKnowledge
from src.executor.engine import ExecutionEngine, ToolExecutorAdapter, AgentContextInjector


class ExecutorConfig:
    """Configuration for the executor."""
    
    def __init__(
        self,
        db_path: str,
        secret: str,
        policy_path: str,
        patterns_path: str,
        default_mode: ExecutionMode = ExecutionMode.GOVERNANCE_DRIVEN,
        require_preview: bool = True,
        max_retries: int = 3,
        token_ttl_seconds: int = 900,
    ):
        self.db_path = db_path
        self.secret = secret
        self.policy_path = policy_path
        self.patterns_path = patterns_path
        self.default_mode = default_mode
        self.require_preview = require_preview
        self.max_retries = max_retries
        self.token_ttl_seconds = token_ttl_seconds


class Executor:
    """Main facade for plan-driven execution.
    
    Usage:
        executor = Executor(config, tool_executor)
        
        # Build and preview plan
        plan = executor.build_plan(request_body, user_id, operational_knowledge)
        preview = executor.preview(plan)
        
        # User reviews preview...
        
        # Execute (after approval if needed)
        state = await executor.execute(plan, user_id)
    """
    
    def __init__(
        self,
        config: ExecutorConfig,
        tool_executor: ToolExecutorAdapter,
    ) -> None:
        """Initialize the executor.
        
        Args:
            config: Executor configuration.
            tool_executor: Adapter for executing tools.
        """
        self._config = config
        
        # Initialize governance components
        self._classifier = IntentClassifier(config.patterns_path)
        self._base_planner = PlanGenerator(config.patterns_path)
        self._validator = PolicyValidator(config.policy_path)
        self._store = PlanStore(config.db_path, config.secret)
        self._enforcer = GovernanceEnforcer(config.db_path, config.secret)
        
        # Initialize executor components
        self._plan_builder = PlanBuilder(self._base_planner)
        self._engine = ExecutionEngine(self._enforcer, tool_executor)
        self._context_injector = AgentContextInjector()
        
        # Track active plans
        self._active_plans: dict[str, EnhancedExecutionPlan] = {}
    
    def build_plan(
        self,
        request_body: dict[str, Any],
        user_id: str,
        session_id: str | None = None,
        operational_knowledge: dict[str, Any] | None = None,
    ) -> EnhancedExecutionPlan:
        """Build an enhanced execution plan from request.
        
        Args:
            request_body: The request containing tool calls.
            user_id: ID of the requesting user.
            session_id: Optional session ID.
            operational_knowledge: User-provided operational knowledge.
            
        Returns:
            EnhancedExecutionPlan ready for preview/execution.
        """
        # Classify intent
        intent = self._classifier.classify(request_body)
        
        # Build operational knowledge
        op_knowledge = OperationalKnowledge(operational_knowledge or {})
        
        # Override defaults from config
        if "require_preview" not in (operational_knowledge or {}):
            op_knowledge["require_preview"] = self._config.require_preview
        if "max_retries" not in (operational_knowledge or {}):
            op_knowledge["max_retries"] = self._config.max_retries
        
        # Build enhanced plan
        plan = self._plan_builder.build(
            intent=intent,
            request_body=request_body,
            session_id=session_id,
            operational_knowledge=op_knowledge,
        )
        
        # Store plan for later execution
        self._active_plans[plan.plan_id] = plan
        
        return plan
    
    def preview(self, plan: EnhancedExecutionPlan) -> PlanPreview:
        """Generate a preview for user review.
        
        Args:
            plan: The execution plan.
            
        Returns:
            PlanPreview for user inspection.
        """
        return self._plan_builder.generate_preview(plan)
    
    def validate(self, plan: EnhancedExecutionPlan, session_id: str | None = None) -> dict[str, Any]:
        """Validate plan against policies.
        
        Args:
            plan: The execution plan.
            session_id: Optional session ID for rate limiting.
            
        Returns:
            Validation result with decision and any violations.
        """
        result = self._validator.validate(plan.base_plan, session=None)
        
        return {
            "valid": result.valid,
            "decision": result.decision.value,
            "approval_required": result.approval_required,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "severity": v.severity.value,
                    "message": v.message,
                }
                for v in result.violations
            ],
        }
    
    def store_plan(self, plan: EnhancedExecutionPlan) -> tuple[str, str]:
        """Store plan and issue execution token.
        
        Args:
            plan: The execution plan.
            
        Returns:
            Tuple of (plan_id, token).
        """
        return self._store.store(
            plan.base_plan,
            ttl_seconds=self._config.token_ttl_seconds,
        )
    
    async def execute(
        self,
        plan: EnhancedExecutionPlan,
        user_id: str,
        session_id: str | None = None,
        mode: ExecutionMode | None = None,
        on_step_complete: Callable[[StepResult], Awaitable[None]] | None = None,
    ) -> ExecutionState:
        """Execute the plan.
        
        Args:
            plan: The execution plan.
            user_id: ID of the executing user.
            session_id: Optional session ID.
            mode: Execution mode override.
            on_step_complete: Optional callback after each step.
            
        Returns:
            Final ExecutionState with all results.
        """
        # Store plan and get token
        plan_id, token = self.store_plan(plan)
        
        # Determine execution mode
        effective_mode = mode or plan.default_mode
        
        # Build context
        context = ExecutionContext(
            plan_id=plan_id,
            session_id=session_id or plan.base_plan.session_id or "",
            user_id=user_id,
            token=token,
            mode=effective_mode,
            max_retries=self._config.max_retries,
            constraints=plan.constraints,
        )
        
        # Execute based on mode
        if effective_mode == ExecutionMode.AGENT_GUIDED:
            # For agent-guided, we just return the context injection
            # The actual execution happens externally
            return self._create_agent_guided_state(plan, context)
        
        # For governance-driven or hybrid, use the engine
        return await self._engine.execute(
            plan=plan,
            context=context,
            on_step_complete=on_step_complete,
        )
    
    def get_agent_context(
        self,
        plan: EnhancedExecutionPlan,
        state: ExecutionState | None = None,
    ) -> str:
        """Get context string to inject into agent.
        
        Args:
            plan: The execution plan.
            state: Current execution state (or None for initial).
            
        Returns:
            String to inject into agent context.
        """
        if state is None:
            state = ExecutionState(
                plan_id=plan.plan_id,
                session_id="",
                context=ExecutionContext(
                    plan_id=plan.plan_id,
                    session_id="",
                    user_id="",
                    token="",
                ),
                total_steps=len(plan.actions),
            )
        
        return self._context_injector.generate_context(plan, state)
    
    def _create_agent_guided_state(
        self,
        plan: EnhancedExecutionPlan,
        context: ExecutionContext,
    ) -> ExecutionState:
        """Create initial state for agent-guided execution."""
        return ExecutionState(
            plan_id=plan.plan_id,
            session_id=context.session_id,
            context=context,
            total_steps=len(plan.actions),
        )
    
    def close(self) -> None:
        """Clean up resources."""
        if hasattr(self._store, "_db"):
            self._store._db.close()
        if hasattr(self._enforcer, "_store"):
            self._enforcer._store._db.close()
