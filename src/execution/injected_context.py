"""Agent context injection for agent-guided execution.

EXPERIMENTAL: This module is not yet integrated into the main application.
"""

from __future__ import annotations

from src.governance.models import Constraints, EnhancedExecutionPlan


class AgentContextInjector:
    """Injects plan into LLM agent context."""

    def generate_context(self, plan: EnhancedExecutionPlan) -> str:
        """Generate context string to inject into agent.

        Args:
            plan: The enhanced execution plan.

        Returns:
            String to inject into agent context/system prompt.
        """
        lines = [
            "## Execution Plan",
            "",
            f"Plan ID: {plan.plan_id}",
            f"Description: {plan.description_for_user}",
            "",
            "### Constraints (MUST follow)",
        ]

        constraint_lines = self._render_constraints(plan.constraints)
        if constraint_lines:
            lines.extend(f"- {c}" for c in constraint_lines)
        else:
            lines.append("- None specified")

        if plan.invariants:
            if plan.invariants.must_hold:
                lines.extend(["", "### Invariants (MUST hold)"])
                lines.extend(f"- {inv}" for inv in plan.invariants.must_hold)
            if plan.invariants.refusal_conditions:
                lines.extend(["", "### Refuse if"])
                lines.extend(f"- {rc}" for rc in plan.invariants.refusal_conditions)

        if plan.scope:
            lines.extend([
                "",
                "### Scope",
                f"- Target system: {plan.scope.target_system}",
                f"- Environment: {plan.scope.environment}",
            ])
            if plan.scope.allowed_systems:
                lines.append(f"- Allowed systems: {', '.join(plan.scope.allowed_systems)}")
            if plan.scope.forbidden_systems:
                lines.append(f"- Forbidden systems: {', '.join(plan.scope.forbidden_systems)}")

        lines.extend(["", "### Steps to Execute"])

        for step in plan.steps:
            status_marker = self._get_status_marker(step.step, plan)
            confirmation = " [REQUIRES CONFIRMATION]" if step.requires_confirmation else ""
            lines.append(
                f"{step.step}. {step.action} "
                f"(tool={step.do.tool}, op={step.do.operation})"
                f"{confirmation}{status_marker}"
            )

        lines.extend([
            "",
            "### Rules",
            "- Execute steps in order",
            "- Do not skip steps unless instructed",
            "- Report any errors immediately",
            "- Do not deviate from the plan without approval",
        ])

        return "\n".join(lines)

    @staticmethod
    def _render_constraints(constraints: Constraints) -> list[str]:
        """Render a Constraints model as human-readable lines."""
        lines: list[str] = []
        if constraints.allow_unplanned is False:
            lines.append("No unplanned operations allowed")
        if constraints.require_sequential:
            lines.append("Operations must execute sequentially")
        lines.append(f"Maximum {constraints.max_total_operations} total operations")
        lines.append(f"Maximum duration: {constraints.max_duration_ms}ms")
        if constraints.max_parallelism > 1:
            lines.append(f"Maximum parallelism: {constraints.max_parallelism}")
        if constraints.forbidden_paths:
            lines.append(f"Forbidden paths: {', '.join(constraints.forbidden_paths)}")
        if constraints.forbidden_commands:
            lines.append(f"Forbidden commands: {', '.join(constraints.forbidden_commands)}")
        if constraints.forbidden_urls:
            lines.append(f"Forbidden URLs: {', '.join(constraints.forbidden_urls)}")
        if constraints.data_sensitivity:
            lines.append(f"Data sensitivity: {constraints.data_sensitivity.value}")
        if constraints.require_approval.model.value != "none":
            lines.append(f"Requires approval: {constraints.require_approval.model.value}")
        return lines

    def _get_status_marker(self, step_number: int, plan: EnhancedExecutionPlan) -> str:
        """Get status marker for a step.

        Args:
            step_number: The step identifier (1-based).
            plan: The plan with optional runtime state.
        """
        if plan.state is None:
            return ""

        # Map step_number to result index (steps are 1-based, results are ordered)
        for i, result in enumerate(plan.state.step_results):
            if result.sequence == step_number:
                return f" [{result.status.value}]"

        if plan.state.current_sequence == step_number:
            return " [CURRENT]"

        return ""