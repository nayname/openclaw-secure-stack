"""Execution engine for the executor layer.

EXPERIMENTAL: This module is not yet integrated into the main application.

This module provides the ExecutionEngine class for:
- Driving plan execution step by step
- Handling governance checks at each step
- Managing recovery and retry logic
- Tracking execution state
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Callable, Awaitable

from src.governance.enforcer import GovernanceEnforcer
from src.governance.models import (
    GovernanceDecision,
    OnFailBehavior,
    ToolCall,
    EnhancedExecutionPlan,
    ExecutionContext,
    Step,
    StepResult,
    StepStatus,
)


# Type for tool execution function
ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[Any]]

logger = logging.getLogger(__name__)


class ExecutionError(Exception):
    """Raised when execution fails."""

    def __init__(self, message: str, step: int, recoverable: bool = False):
        super().__init__(message)
        self.step = step
        self.recoverable = recoverable


class GovernanceBlockedError(ExecutionError):
    """Raised when governance blocks execution."""

    def __init__(self, message: str, step: int, reason: str):
        super().__init__(message, step, recoverable=False)
        self.reason = reason


class ToolExecutorAdapter(ABC):
    """Abstract adapter for executing tools.

    Implementations connect to actual tool providers:
    - LocalToolExecutor: Calls tools locally
    - AgentToolExecutor: Sends tools to LLM agent
    - MockToolExecutor: For testing
    """

    @abstractmethod
    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ExecutionContext,
    ) -> Any:
        """Execute a tool and return its result.

        Args:
            tool_name: Name of the tool to execute.
            arguments: Tool arguments.
            context: Execution context.

        Returns:
            Tool execution result.

        Raises:
            Exception: If tool execution fails.
        """
        pass


class ExecutionEngine:
    """Drives plan execution step by step with governance enforcement.

    The engine:
    1. Iterates through plan steps in order (respecting depends_on)
    2. Checks governance before each step
    3. Executes the step via ToolExecutorAdapter
    4. Handles failures according to each step's on_fail behavior
    5. Tracks execution state throughout
    """

    def __init__(
        self,
        enforcer: GovernanceEnforcer,
        tool_executor: ToolExecutorAdapter,
    ) -> None:
        """Initialize the execution engine.

        Args:
            enforcer: Governance enforcer for action validation.
            tool_executor: Adapter for executing tools.
        """
        self._enforcer = enforcer
        self._tool_executor = tool_executor

    async def execute(
        self,
        plan: EnhancedExecutionPlan,
        on_step_complete: Callable[[StepResult], Awaitable[None]] | None = None,
    ):
        """Execute the plan and return final state.

        Args:
            plan: The enhanced execution plan.
            on_step_complete: Optional callback after each step.

        Returns:
            Final ExecutionState with all results.
        """
        # Validate state is initialized
        if plan.state is None:
            raise ExecutionError(
                message="Plan state not initialized. Call initialize_state() first.",
                step=-1,
                recoverable=False,
            )

        plan.state.status = StepStatus.RUNNING
        plan.state.started_at = datetime.now(UTC).isoformat()

        try:
            # Execute each step
            # TODO: Execution is intentionally sequential for now. depends_on and parallel are reserved for future engine upgrades.
            # AbortCondition objects are currently parsed but not enforced.
            # The engine should check abort conditions before/after step execution
            # and terminate the plan when conditions are met.
            for step in plan.steps:
                # Check if we should skip (conditional / depends_on logic)
                if self._should_skip(step, plan):
                    result = self._create_skipped_result(step)
                    plan.state.step_results.append(result)
                    plan.state.skipped_steps += 1
                    continue

                # Execute with retry/recovery based on step.on_fail
                result = await self._execute_step(
                    step=step,
                    context=plan.state.context,
                )

                # Update state
                plan.state.step_results.append(result)
                plan.state.current_sequence = step.step

                if result.status == StepStatus.COMPLETED:
                    plan.state.completed_steps += 1
                elif result.status == StepStatus.FAILED:
                    plan.state.failed_steps += 1
                    if step.on_fail.behavior == OnFailBehavior.ABORT_PLAN:
                        plan.state.status = StepStatus.FAILED
                        break
                    # MARK_FAILED_AND_CONTINUE / COMPLETE_WITH_WARNING: keep going
                    # ABORT_STEP: step is done, continue to next
                elif result.status == StepStatus.BLOCKED:
                    if plan.state.context.fail_on_governance_block:
                        plan.state.status = StepStatus.BLOCKED
                        break

                # Callback
                if on_step_complete:
                    await on_step_complete(result)

            # Mark complete if we got through all steps
            if plan.state.status == StepStatus.RUNNING:
                plan.state.status = StepStatus.COMPLETED

        except Exception as e:
            plan.state.status = StepStatus.FAILED
            logger.exception(
                "Execution failed with exception: plan_id=%s, error=%s",
                plan.plan_id,
                str(e),
            )

        plan.state.completed_at = datetime.now(UTC).isoformat()

        logger.debug(
            "Execution finished: plan_id=%s, final_status=%s, duration=%s",
            plan.plan_id,
            plan.state.status.value,
            self._calc_total_duration(plan),
        )

    async def _execute_step(
        self,
        step: Step,
        context: ExecutionContext,
    ) -> StepResult:
        """Execute a single step with governance check and retry logic.

        Retries are attempted up to step.max_invocations times. The retry
        decision is based on step.on_fail.behavior:
        - abort_plan / abort_step: no retry, fail immediately
        - mark_failed_and_continue / complete_with_warning: no retry either,
          but the caller decides whether to continue

        Args:
            step: The step to execute.
            context: Execution context.

        Returns:
            StepResult with outcome.
        """
        started_at = datetime.now(UTC).isoformat()
        last_error: str | None = None
        # TODO: Retry vs on_fail.behavior coupling — retries are currently governed by max_invocations.
        # Behavioral branching (ABORT_PLAN, etc.) will be aligned in a follow-up pass once
        # failure semantics stabilize.
        max_attempts = step.max_invocations

        for attempt in range(max_attempts):
            try:
                # Check refuse_if conditions
                if step.on_fail.refuse_if:
                    for condition in step.on_fail.refuse_if:
                        # TODO: evaluate condition expressions against context
                        # For now, refuse_if conditions are checked as string
                        # markers — a real implementation would parse these.
                        pass

                # Build ToolCall for governance check
                tool_call = ToolCall(
                    name=step.do.tool,
                    arguments=step.do.parameters,
                )

                # Check governance
                enforcement = self._enforcer.enforce_action(
                    plan_id=context.plan_id,
                    token=context.token,
                    tool_call=tool_call,
                )

                if not enforcement.allowed:
                    return StepResult(
                        sequence=step.step,
                        status=StepStatus.BLOCKED,
                        started_at=started_at,
                        completed_at=datetime.now(UTC).isoformat(),
                        tool_name=step.do.tool,
                        tool_args=step.do.parameters,
                        governance_decision=GovernanceDecision.BLOCK,
                        governance_reason=enforcement.reason,
                    )

                # Execute tool
                result = await self._tool_executor.execute(
                    tool_name=step.do.tool,
                    arguments=step.do.parameters,
                    context=context,
                )

                # Mark step complete in enforcer
                self._enforcer.mark_action_complete(context.plan_id, step.step)

                completed_at = datetime.now(UTC).isoformat()
                duration_ms = self._calc_duration_ms(started_at, completed_at)

                return StepResult(
                    sequence=step.step,
                    status=StepStatus.COMPLETED,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    tool_name=step.do.tool,
                    tool_args=step.do.parameters,
                    tool_result=result,
                    governance_decision=GovernanceDecision.ALLOW,
                    retry_count=attempt,
                )

            except Exception as e:
                last_error = str(e)

                # Only retry if we have invocations left
                if attempt + 1 < max_attempts:
                    continue

                break

        # All attempts exhausted
        completed_at = datetime.now(UTC).isoformat()
        duration_ms = self._calc_duration_ms(started_at, completed_at)

        return StepResult(
            sequence=step.step,
            status=StepStatus.FAILED,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            tool_name=step.do.tool,
            tool_args=step.do.parameters,
            error=last_error,
            retry_count=max_attempts - 1,
        )

    def _should_skip(
            self,
            step: Step,
            plan: EnhancedExecutionPlan
    ) -> bool:
        """Check if this step should be skipped based on conditionals.

        TODO: Implement conditional logic when schema stabilizes.
        For now, never skip — execute all steps in sequence.
        """
        return False

    def _create_skipped_result(self, step: Step) -> StepResult:
        """Create a StepResult for a skipped step."""
        now = datetime.now(UTC).isoformat()
        return StepResult(
            sequence=step.step,
            status=StepStatus.SKIPPED,
            started_at=now,
            completed_at=now,
            tool_name=step.do.tool,
            tool_args=step.do.parameters,
        )

    def _calc_duration_ms(self, started_at: str, completed_at: str) -> int:
        """Calculate duration in milliseconds."""
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(completed_at)
        return int((end - start).total_seconds() * 1000)

    def _calc_total_duration(self, plan: EnhancedExecutionPlan) -> str:
        """Calculate total execution duration as human-readable string."""
        if plan.state is None:
            return "unknown"
        if plan.state.started_at is None or plan.state.completed_at is None:
            return "incomplete"

        start = datetime.fromisoformat(plan.state.started_at)
        end = datetime.fromisoformat(plan.state.completed_at)
        duration_sec = (end - start).total_seconds()

        if duration_sec < 1:
            return f"{int(duration_sec * 1000)}ms"
        elif duration_sec < 60:
            return f"{duration_sec:.1f}s"
        else:
            return f"{duration_sec / 60:.1f}m"