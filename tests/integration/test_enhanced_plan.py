"""Tests for execution governance functionality.

Tests cover:
- PlanGenerator.enhance() method
- EnhancedExecutionPlan model
- ExecutionEngine
- AgentContextInjector
- Executor
- Middleware enhancement settings
"""

from __future__ import annotations

import json
import os
import sys

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.governance.models import (
    AbortCondition,
    CheckSpec,
    EnhancedExecutionPlan,
    EnhancedIntent,
    ExecutionContext,
    ExecutionMode,
    ExecutionPlan,
    ExecutionState,
    GovernanceDecision,
    Intent,
    IntentCategory,
    IntentSignal,
    OnFailBehavior,
    PlannedAction,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    Step,
    StepAudit,
    StepDo,
    StepOnFail,
    StepResult,
    StepStatus,
    StepVerify,
    SurfaceEffects,
    ToolCall,
)
from src.governance.planner import PlanGenerator


# --- Fixtures ---


@pytest.fixture
def _mock_random_context():
    """Prevent get_random_context from hitting the filesystem in tests."""
    fake_context = {
        "user_context": {"actor_id": "test-user", "role": "tester", "trust_level": "high"},
        "scope": {"target_system": "filesystem", "environment": "test"},
        "constraints": {"allow_unplanned": False, "max_total_operations": 10},
        "invariants": {"must_hold": [], "refusal_conditions": []},
    }
    with patch("src.governance.planner.get_random_context", return_value=fake_context):
        yield


@pytest.fixture
def sample_tool_call() -> ToolCall:
    """Create a sample tool call."""
    return ToolCall(
        name="read_file",
        arguments={"path": "/home/user/document.txt"},
        id="call_123",
    )


@pytest.fixture
def sample_intent(sample_tool_call: ToolCall) -> Intent:
    """Create a sample intent."""
    return Intent(
        primary_category=IntentCategory.FILE_READ,
        signals=[
            IntentSignal(
                category=IntentCategory.FILE_READ,
                confidence=0.9,
                source="tool_pattern",
                details="tool: read_file",
            )
        ],
        tool_calls=[sample_tool_call],
        confidence=0.9,
    )


@pytest.fixture
def sample_execution_plan(sample_tool_call: ToolCall) -> ExecutionPlan:
    """Create a sample execution plan."""
    return ExecutionPlan(
        plan_id="plan-123",
        session_id="session-456",
        request_hash="a" * 64,
        actions=[
            PlannedAction(
                sequence=0,
                tool_call=sample_tool_call,
                category=IntentCategory.FILE_READ,
                resources=[
                    ResourceAccess(
                        type="file",
                        path="/home/user/document.txt",
                        operation="read",
                    )
                ],
                risk_score=10,
            )
        ],
        risk_assessment=RiskAssessment(
            overall_score=10,
            level=RiskLevel.LOW,
            factors=["file_read"],
            mitigations=[],
        ),
    )

@pytest.fixture
def real_llm():
    from src.llm.client import LLMClient
    return LLMClient()

@pytest.fixture
def sample_enhanced_plan(sample_execution_plan: ExecutionPlan) -> EnhancedExecutionPlan:
    """Create a sample enhanced execution plan."""
    return EnhancedExecutionPlan(
        base_plan=sample_execution_plan,
        execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
        description_for_user="Read a document from the user's home directory",
        intent=EnhancedIntent(
            summary="Read a document from user home",
            primary_category=IntentCategory.FILE_READ,
            signals=[], tool_calls=[], confidence=1.0,
        ),
        surface_effects=SurfaceEffects(
            touches=["/home/user/document.txt"], modifies=False, creates=False, deletes=False,
        ),
        steps=[Step(
            step=1, action="Read document",
            do=StepDo(tool="read", operation="file", target="/home/user/document.txt"),
            verify=StepVerify(checks=[CheckSpec(name="file_read", evidence="fs stat", pass_condition="file.exists == true")]),
            on_fail=StepOnFail(behavior=OnFailBehavior.ABORT_PLAN, refuse_if=[]),
            audit=StepAudit(record_outputs=[]),
        )],
        abort_conditions=[AbortCondition(condition="file.missing", reason="Target file does not exist")],
    )


def _make_llm_output(**overrides) -> str:
    """Return valid schema-conformant LLM output for tests."""
    data = {
        "version": "1.0.0",
        "plan_id": "00000000-0000-0000-0000-000000000000",
        "created_at": "2025-01-01T00:00:00Z",
        "execution_mode": "governance_driven",
        "description_for_user": "Test plan description for testing purposes",
        "surface_effects": {"touches": ["/tmp/test.txt"], "modifies": False, "creates": False, "deletes": False},
        "intent": {
            "summary": "Test plan for reading files",
            "category": "read",
            "five_w_one_h": {"who": "system", "what": "read file", "where": "/tmp", "when": "immediate", "why": "test", "how": "fs read"},
        },
        "steps": [{
            "step": 1, "action": "Read file",
            "inputs": {"required": [{"name": "path", "type": "string"}], "optional": []},
            "do": {"tool": "read", "operation": "file", "target": "/tmp/test.txt", "parameters": {}},
            "verify": {"checks": [{"name": "file_read", "evidence": "fs stat", "pass_condition": "file.exists == true"}]},
            "on_fail": {"behavior": "abort_plan", "refuse_if": []},
            "audit": {"record_outputs": [{"name": "contents", "type": "string", "write_to": "log"}]},
        }],
        "constraints": {"allow_unplanned": False, "max_total_operations": 5},
        "abort_conditions": [{"condition": "file.missing", "reason": "File not found"}],
    }
    data.update(overrides)
    return json.dumps(data)


@pytest.fixture
def mock_llm() -> MagicMock:
    """Create a mock LLM client returning schema-conformant output."""
    llm = MagicMock()
    llm.complete = MagicMock(return_value=_make_llm_output())
    return llm


@pytest.fixture
def patterns_config(tmp_path) -> str:
    """Create a temporary patterns config file."""
    config = {
        "tool_categories": {
            "file_read": ["read_file", "get_file", "list_files"],
            "file_write": ["write_file", "save_file"],
            "network_request": ["http_request", "fetch_url"],
        },
        "argument_patterns": {
            "sensitive_paths": [r"/etc/", r"/root/"],
            "external_urls": [r"^https?://"],
        },
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 1.5,
            "network_request": 1.2,
        },
    }
    config_path = tmp_path / "intent-patterns.json"
    config_path.write_text(json.dumps(config))
    return str(config_path)


@pytest.fixture
def schema_config(tmp_path) -> str:
    """Create a temporary schema config file (permissive for integration tests)."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ExecutionPlan",
        "type": "object",
        "required": [
            "version", "plan_id", "created_at", "execution_mode",
            "intent", "steps", "constraints", "abort_conditions",
            "description_for_user", "surface_effects",
        ],
        "properties": {
            "version": {"type": "string"},
            "plan_id": {"type": "string"},
            "created_at": {"type": "string"},
            "execution_mode": {"type": "string"},
            "description_for_user": {"type": "string"},
            "surface_effects": {"type": "object"},
            "intent": {"type": "object"},
            "steps": {"type": "array"},
            "constraints": {"type": "object"},
            "abort_conditions": {"type": "array"},
        },
        "additionalProperties": True,
    }
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(schema))
    return str(schema_path)

@pytest.fixture
def schema_config_strict(tmp_path) -> str:
    """Schema for real-LLM tests: enforce required surface_effects fields."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ExecutionPlan",
        "type": "object",
        "required": [
            "version", "plan_id", "created_at", "execution_mode",
            "intent", "steps", "constraints", "abort_conditions",
            "description_for_user", "surface_effects",
        ],
        "properties": {
            "version": {"type": "string"},
            "plan_id": {"type": "string"},
            "created_at": {"type": "string"},
            "execution_mode": {"type": "string"},
            "description_for_user": {"type": "string"},

            "surface_effects": {
                "type": "object",
                "required": ["touches", "modifies", "creates", "deletes"],
                "properties": {
                    "touches": {"type": "array", "items": {"type": "string"}},
                    "modifies": {"type": "boolean"},
                    "creates": {"type": "boolean"},
                    "deletes": {"type": "boolean"},
                },
                "additionalProperties": True,
            },

            "intent": {"type": "object"},
            "steps": {"type": "array"},
            "constraints": {"type": "object"},
            "abort_conditions": {"type": "array"},
        },
        "additionalProperties": True,
    }

    schema_path = tmp_path / "schema_strict.json"
    schema_path.write_text(json.dumps(schema))
    return str(schema_path)

requires_llm = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="Requires ANTHROPIC_API_KEY"
)

# --- PlanGenerator Tests ---
class TestPlanGeneratorEnhance:
    """Tests for PlanGenerator.enhance() method."""

    def test_enhance_requires_llm(
            self, patterns_config: str, schema_config: str, sample_execution_plan: ExecutionPlan
    ):
        """Test that enhance() raises error when LLM is None."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        with pytest.raises(RuntimeError, match="No LLM client"):
            generator.enhance(sample_execution_plan, llm=None, user_message="test")

    def test_enhance_requires_schema(
            self, patterns_config: str, sample_execution_plan: ExecutionPlan, mock_llm: MagicMock
    ):
        """Test that enhance() raises error when schema not found."""
        generator = PlanGenerator(patterns_config, schema_path="/nonexistent/schema.json")

        with pytest.raises(RuntimeError, match="Schema not found"):
            generator.enhance(sample_execution_plan, llm=mock_llm, user_message="test")

    def test_enhance_returns_enhanced_plan(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
            _mock_random_context
    ):
        """Test that enhance() returns EnhancedExecutionPlan."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(
            sample_execution_plan,
            llm=mock_llm,
            user_message="Read the admin file",
        )

        assert isinstance(enhanced, EnhancedExecutionPlan)
        assert enhanced.base_plan == sample_execution_plan
        assert enhanced.description_for_user == "Test plan description for testing purposes"
        assert enhanced.intent.user_message == "Read the admin file"

    def test_enhance_parses_execution_mode(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
            _mock_random_context
    ):
        """Test that execution mode is parsed correctly."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(sample_execution_plan, llm=mock_llm, user_message="test")

        assert enhanced.execution_mode == ExecutionMode.GOVERNANCE_DRIVEN

    def test_enhance_parses_agent_guided_mode(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            _mock_random_context
    ):
        """Test that agent_guided mode is parsed correctly."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value=_make_llm_output(execution_mode="agent_guided"))

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm, user_message="test")

        assert enhanced.execution_mode == ExecutionMode.AGENT_GUIDED

    def test_enhance_strips_markdown_fences(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            _mock_random_context
    ):
        """Test that markdown code fences are stripped from LLM response."""
        llm = MagicMock()
        wrapped = "```json\n" + _make_llm_output(
            description_for_user="Markdown wrapped response for testing"
        ) + "\n```"
        llm.complete = MagicMock(return_value=wrapped)

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm, user_message="test")

        assert enhanced.description_for_user == "Markdown wrapped response for testing"

    def test_enhance_raises_on_invalid_json(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            _mock_random_context
    ):
        """Test that invalid JSON from LLM raises ValueError."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value="not valid json {{{")

        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        with pytest.raises(ValueError, match="LLM returned invalid JSON"):
            generator.enhance(sample_execution_plan, llm=llm, user_message="test")


# --- EnhancedExecutionPlan Model Tests ---


class TestEnhancedExecutionPlan:
    """Tests for EnhancedExecutionPlan model."""

    def test_property_accessors(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that property accessors delegate to base plan."""
        assert sample_enhanced_plan.plan_id == "plan-123"
        assert sample_enhanced_plan.session_id == "session-456"
        assert len(sample_enhanced_plan.base_plan.actions) == 1
        assert sample_enhanced_plan.risk_assessment.level == RiskLevel.LOW

    def test_initialize_state(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that initialize_state creates proper ExecutionState."""
        sample_enhanced_plan.initialize_state(
            session_id="session-789",
            user_id="user-123",
            token="token-abc",
        )

        assert sample_enhanced_plan.state is not None
        assert sample_enhanced_plan.state.plan_id == "plan-123"
        assert sample_enhanced_plan.state.session_id == "session-789"
        assert sample_enhanced_plan.state.status == StepStatus.PENDING
        assert sample_enhanced_plan.state.current_sequence == 0
        assert sample_enhanced_plan.state.total_steps == 1

    def test_initialize_state_creates_context(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that initialize_state creates ExecutionContext."""
        sample_enhanced_plan.initialize_state(
            session_id="session-789",
            user_id="user-123",
            token="token-abc",
        )

        context = sample_enhanced_plan.state.context
        assert context.plan_id == "plan-123"
        assert context.session_id == "session-789"
        assert context.user_id == "user-123"
        assert context.token == "token-abc"

    def test_initialize_state_raises_on_none_session_id(
        self, sample_execution_plan: ExecutionPlan
    ):
        """Test that initialize_state raises ValueError when session_id is None."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            description_for_user="Test plan for unit testing purposes",
            intent=EnhancedIntent(summary="Test plan for unit testing", primary_category=IntentCategory.FILE_READ, signals=[], tool_calls=[], confidence=1.0),
            surface_effects=SurfaceEffects(touches=["/tmp/test"], modifies=False, creates=False, deletes=False),
            steps=[Step(step=1, action="Read file", do=StepDo(tool="read", operation="file", target="/tmp/test.txt", parameters={"path": "/home/user/document.txt"}), verify=StepVerify(checks=[CheckSpec(name="check", evidence="stat", pass_condition="true")]), on_fail=StepOnFail(behavior=OnFailBehavior.ABORT_PLAN, refuse_if=[]), audit=StepAudit(record_outputs=[]))],
            abort_conditions=[AbortCondition(condition="error", reason="Test abort")],
        )

        with pytest.raises(ValueError, match="session_id is required"):
            enhanced.initialize_state(
                session_id=None,
                user_id="user-123",
                token="token-abc",
            )

    def test_initialize_state_sets_started_at(
        self, sample_execution_plan: ExecutionPlan
    ):
        """Test that initialize_state sets started_at timestamp."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            description_for_user="Test plan for unit testing purposes",
            intent=EnhancedIntent(summary="Test plan for unit testing", primary_category=IntentCategory.FILE_READ, signals=[], tool_calls=[], confidence=1.0),
            surface_effects=SurfaceEffects(touches=["/tmp/test"], modifies=False, creates=False, deletes=False),
            steps=[Step(step=1, action="Read file", do=StepDo(tool="read", operation="file", target="/tmp/test.txt", parameters={"path": "/home/user/document.txt"}), verify=StepVerify(checks=[CheckSpec(name="check", evidence="stat", pass_condition="true")]), on_fail=StepOnFail(behavior=OnFailBehavior.ABORT_PLAN, refuse_if=[]), audit=StepAudit(record_outputs=[]))],
            abort_conditions=[AbortCondition(condition="error", reason="Test abort")],
        )

        enhanced.initialize_state(
            session_id="session-123",
            user_id="user-123",
            token="token-abc",
        )

        assert enhanced.state.started_at is not None
        # Should be a valid ISO format datetime
        datetime.fromisoformat(enhanced.state.started_at)


# --- Middleware Enhancement Settings Tests ---


class TestMiddlewareEnhancementSettings:
    """Tests for middleware enhancement configuration."""

    def test_enhancement_disabled_by_default(self, tmp_path):
        """Test that enhancement is disabled by default."""
        from src.governance.middleware import GovernanceMiddleware

        # Create minimal config files
        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text(json.dumps({"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}))

        policy_path = tmp_path / "policies.json"
        policy_path.write_text(json.dumps([]))

        db_path = str(tmp_path / "test.db")

        settings = {"enabled": True}

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is False

    def test_enhancement_enabled_via_settings(self, tmp_path):
        """Test that enhancement can be enabled via settings."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text(json.dumps({"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}))

        policy_path = tmp_path / "policies.json"
        policy_path.write_text(json.dumps([]))

        db_path = str(tmp_path / "test.db")

        settings = {
            "enabled": True,
            "enhancement": {
                "enabled": True,
            },
        }

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is True


# --- ExecutionState Tests ---


class TestExecutionState:
    """Tests for ExecutionState model."""

    def test_is_complete_when_pending(self):
        """Test is_complete returns False when pending."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            ),
            current_sequence=0,
            status=StepStatus.PENDING,
            total_steps=3,
        )

        assert state.is_complete() is False

    def test_is_complete_when_all_steps_done(self):
        """Test is_complete returns True when all steps completed."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            ),
            current_sequence=3,
            status=StepStatus.COMPLETED,
            total_steps=3,
        )

        assert state.is_complete() is True

    def test_is_complete_when_failed(self):
        """Test is_complete returns True when failed."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            ),
            current_sequence=1,
            status=StepStatus.FAILED,
            total_steps=3,
        )

        assert state.is_complete() is True

    def test_get_progress_percentage(self):
        """Test get_progress returns correct percentage."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            ),
            current_sequence=1,
            status=StepStatus.RUNNING,
            total_steps=4,
            completed_steps=2,
        )

        assert state.get_progress() == 50.0

    def test_get_progress_zero_steps(self):
        """Test get_progress returns 100 when no steps."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            ),
            current_sequence=0,
            status=StepStatus.COMPLETED,
            total_steps=0,
        )

        assert state.get_progress() == 100.0


# --- StepResult Tests ---


class TestStepResult:
    """Tests for StepResult model."""

    def test_step_result_completed(self):
        """Test StepResult for completed step."""
        result = StepResult(
            sequence=0,
            status=StepStatus.COMPLETED,
            started_at="2024-01-01T00:00:00+00:00",
            completed_at="2024-01-01T00:00:01+00:00",
            duration_ms=1000,
            tool_name="read_file",
            tool_args={"path": "/home/user/file.txt"},
            tool_result={"content": "file contents"},
            governance_decision=GovernanceDecision.ALLOW,
        )

        assert result.status == StepStatus.COMPLETED
        assert result.error is None
        assert result.retry_count == 0


    def test_step_result_blocked(self):
        """Test StepResult for governance-blocked step."""
        result = StepResult(
            sequence=0,
            status=StepStatus.BLOCKED,
            started_at="2024-01-01T00:00:00+00:00",
            completed_at="2024-01-01T00:00:00+00:00",
            tool_name="delete_file",
            tool_args={"path": "/etc/passwd"},
            governance_decision=GovernanceDecision.BLOCK,
            governance_reason="Access to /etc/* is denied by policy",
        )

        assert result.status == StepStatus.BLOCKED
        assert result.governance_decision == GovernanceDecision.BLOCK
        assert "denied by policy" in result.governance_reason


# --- Integration Tests ---


class TestPlanGeneratorIntegration:
    """Integration tests for plan generation and enhancement flow."""

    def test_full_generate_enhance_flow(
            self,
            patterns_config: str,
            schema_config: str,
            sample_intent: Intent,
            mock_llm: MagicMock,
            _mock_random_context
    ):
        """Test complete flow from intent to enhanced plan."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        # Step 1: Generate base plan
        base_plan = generator.generate(
            intent=sample_intent,
            request_body={"tools": []},
            session_id="session-123",
        )

        assert isinstance(base_plan, ExecutionPlan)
        assert base_plan.session_id == "session-123"

        # Step 2: Enhance with LLM
        enhanced_plan = generator.enhance(
            base_plan,
            llm=mock_llm,
            user_message="test",
        )

        assert isinstance(enhanced_plan, EnhancedExecutionPlan)
        assert enhanced_plan.base_plan == base_plan
        assert enhanced_plan.description_for_user is not None

        # Step 3: Initialize state
        enhanced_plan.initialize_state(
            session_id="session-123",
            user_id="user-456",
            token="token-xyz",
        )

        assert enhanced_plan.state is not None
        assert enhanced_plan.state.status == StepStatus.PENDING

    def test_multiple_tool_calls_generate_multiple_actions(self, patterns_config: str):
        """Test that multiple tool calls create multiple actions."""
        generator = PlanGenerator(patterns_config)

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[
                ToolCall(name="read_file", arguments={"path": "/file1.txt"}),
                ToolCall(name="read_file", arguments={"path": "/file2.txt"}),
                ToolCall(name="write_file", arguments={"path": "/output.txt"}),
            ],
            confidence=1.0,
        )

        plan = generator.generate(intent=intent, request_body={})

        assert len(plan.actions) == 3
        assert plan.actions[0].sequence == 0
        assert plan.actions[1].sequence == 1
        assert plan.actions[2].sequence == 2

        # Check risk increases with multiple actions
        assert plan.risk_assessment.overall_score > plan.actions[0].risk_score


# --- Middleware create_enhanced_plan Tests ---


# --- Middleware create_enhanced_plan Tests ---


class TestMiddlewareCreateEnhancedPlan:
    """Tests for GovernanceMiddleware.create_enhanced_plan()."""

    @pytest.fixture
    def sample_base_plan(self) -> ExecutionPlan:
        """Create a sample base plan."""
        return ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={"path": "/test"}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

    @pytest.fixture
    def mock_enhanced_plan(self, sample_base_plan):
        """Create a mock enhanced plan returned by planner."""
        return EnhancedExecutionPlan(
            base_plan=sample_base_plan,
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            description_for_user="Test enhanced plan for integration testing",
            intent=EnhancedIntent(
                summary="Test enhanced plan for testing",
                primary_category=IntentCategory.FILE_READ,
                signals=[], tool_calls=[], confidence=1.0,
            ),
            surface_effects=SurfaceEffects(
                touches=["/tmp/test"], modifies=False, creates=False, deletes=False,
            ),
            steps=[Step(
                step=1, action="Read file",
                do=StepDo(tool="read", operation="file", target="/tmp/test.txt"),
                verify=StepVerify(checks=[CheckSpec(name="check", evidence="stat", pass_condition="true")]),
                on_fail=StepOnFail(behavior=OnFailBehavior.ABORT_PLAN, refuse_if=[]),
                audit=StepAudit(record_outputs=[]),
            )],
            abort_conditions=[AbortCondition(condition="error", reason="Test abort")],
        )

    @pytest.fixture
    def middleware_with_enhancement(self, tmp_path):
        """Create middleware with enhancement enabled."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text('{"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}')

        policy_path = tmp_path / "policies.json"
        policy_path.write_text("[]")

        db_path = str(tmp_path / "test.db")

        settings = {
            "enabled": True,
            "enhancement": {
                "enabled": True,
            },
        }

        return GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

    @requires_llm
    def test_create_enhanced_plan_returns_enhanced_plan(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that create_enhanced_plan returns EnhancedExecutionPlan."""
        # Mock the planner.enhance method
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        result = middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
            request_body={"tools": []},
        )

        assert result is not None
        assert isinstance(result, EnhancedExecutionPlan)
        assert result.description_for_user == "Test enhanced plan for integration testing"

    @requires_llm
    def test_create_enhanced_plan_initializes_state(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that create_enhanced_plan initializes state correctly."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        result = middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
            request_body={"tools": []},
        )

        assert result.state is not None
        assert result.state.context.session_id == "session-456"
        assert result.state.context.user_id == "user-123"
        assert result.state.context.token == "token-abc"

    @requires_llm
    def test_create_enhanced_plan_passes_correct_user_message(
            self,
            middleware_with_enhancement,
            sample_base_plan,
            mock_enhanced_plan,
    ):
        """Middleware must extract and pass correct user_message to planner."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        body = {
            "messages": [
                {"role": "user", "content": "Read /tmp/file.txt"}
            ]
        }

        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
            request_body=body,
        )


        kwargs = middleware_with_enhancement._planner.enhance.call_args.kwargs

        assert kwargs["user_message"] == "Read /tmp/file.txt"

    @requires_llm
    def test_create_enhanced_plan_lazy_loads_llm(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that LLM client is lazy-loaded on first call."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        # Initially None
        assert middleware_with_enhancement._llm is None

        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
            request_body={"tools": []},
        )

        # After call, LLM should be created
        assert middleware_with_enhancement._llm is not None

    def test_create_enhanced_plan_extracts_user_message(
            self,
            middleware_with_enhancement,
            sample_base_plan,
            mock_enhanced_plan,
    ):
        """Middleware should extract user_message from request_body."""

        # ensure enhancement path executes
        middleware_with_enhancement._enhancement_enabled = True
        middleware_with_enhancement._llm = MagicMock()

        middleware_with_enhancement._planner.enhance = MagicMock(
            return_value=mock_enhanced_plan
        )

        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-1",
            user_id="user-1",
            token="token-1",
            request_body={"messages": [{"role": "user", "content": "read file"}]},
        )

        call_kwargs = middleware_with_enhancement._planner.enhance.call_args.kwargs

        assert "user_message" in call_kwargs

    def test_create_enhanced_plan_reuses_llm(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that LLM client is reused across calls."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        # First call
        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-1",
            user_id="user-1",
            token="token-1",
            request_body={"tools": []},
        )
        first_llm = middleware_with_enhancement._llm

        # Second call
        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-2",
            user_id="user-2",
            token="token-2",
            request_body={"tools": []},
        )
        second_llm = middleware_with_enhancement._llm

        # Should be same instance
        assert first_llm is second_llm

    def test_enhancement_disabled_by_default(self, tmp_path):
        """Test that enhancement is disabled by default."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text('{"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}')

        policy_path = tmp_path / "policies.json"
        policy_path.write_text("[]")

        db_path = str(tmp_path / "test.db")

        settings = {"enabled": True}  # No enhancement settings

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is False

    @requires_llm
    def test_create_enhanced_plan_logs_failure_with_details(
            self,
            middleware_with_enhancement,
            sample_base_plan,
            caplog,
    ):
        """Test that enhancement failures are logged with error type and traceback."""
        import logging

        middleware_with_enhancement._planner.enhance = MagicMock(
            side_effect=ValueError("bad LLM response")
        )

        with caplog.at_level(logging.WARNING):
            result = middleware_with_enhancement.create_enhanced_plan(
                basic_plan=sample_base_plan,
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
                request_body={"tools": []},
            )

        assert result is None

        # Find the relevant log record
        enhancement_logs = [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "enhancement failed" in r.message.lower()
        ]
        assert len(enhancement_logs) == 1

        record = enhancement_logs[0]
        assert record.exc_info is not None  # Stack trace included
        assert "plan-123" in record.message
        assert "ValueError" in record.message

    # ---------------------------------------------------------------------------
    # Real LLM Integration Tests (Anthropic)
    # ---------------------------------------------------------------------------
    # These tests call the real Anthropic API via src.llm.client.LLMClient.
    # They are skipped unless ANTHROPIC_API_KEY is set.
    # ---------------------------------------------------------------------------


class TestLLMClientInit:
    """Tests for LLMClient initialization."""

    def test_raises_when_anthropic_not_installed(self, monkeypatch):
        """Test that LLMClient raises helpful error when anthropic not installed."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        # Remove anthropic from modules if present
        with patch.dict(sys.modules, {"anthropic": None}):
            from src.llm.client import LLMClient

            with pytest.raises(RuntimeError, match="pip install anthropic"):
                LLMClient()

    def test_raises_without_api_key(self, monkeypatch):
        """Test that LLMClient raises error when API key not set."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, LLMClientError

            with pytest.raises(LLMClientError, match="ANTHROPIC_API_KEY"):
                LLMClient()

    def test_uses_default_model(self, monkeypatch):
        """Test that LLMClient uses default model when not specified."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, DEFAULT_MODEL

            client = LLMClient()
            assert client.model_name == DEFAULT_MODEL

    def test_uses_env_model(self, monkeypatch):
        """Test that LLMClient uses model from environment variable."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-custom-model")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            # Reload to pick up env var
            import importlib
            from src.llm import client as llm_module
            importlib.reload(llm_module)

            client = llm_module.LLMClient()
            assert client.model_name == "claude-custom-model"

    def test_uses_provided_model(self, monkeypatch):
        """Test that LLMClient uses model passed to constructor."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            client = LLMClient(model="my-custom-model")
            assert client.model_name == "my-custom-model"

    def test_uses_default_timeout(self, monkeypatch):
        """Test that LLMClient uses default timeout when not specified."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_TIMEOUT_SECONDS", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, DEFAULT_TIMEOUT

            client = LLMClient()
            assert client.timeout_seconds == DEFAULT_TIMEOUT

    def test_uses_provided_timeout(self, monkeypatch):
        """Test that LLMClient uses timeout passed to constructor."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            client = LLMClient(timeout_seconds=90)
            assert client.timeout_seconds == 90

    def test_creates_anthropic_client_with_timeout(self, monkeypatch):
        """Test that Anthropic client is created with correct timeout."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic = MagicMock()
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic = mock_anthropic
        mock_anthropic_module.AuthenticationError = Exception

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            LLMClient(timeout_seconds=45)
            mock_anthropic.assert_called_once_with(timeout=45)


class TestLLMClientComplete:
    """Tests for LLMClient.complete() method."""

    @pytest.fixture
    def mock_anthropic_module(self):
        """Create a mock anthropic module."""
        mock_module = MagicMock()
        mock_module.AuthenticationError = type("AuthenticationError", (Exception,), {})
        mock_module.APIError = type("APIError", (Exception,), {})
        return mock_module

    @pytest.fixture
    def mock_client(self, monkeypatch, mock_anthropic_module):
        """Create a LLMClient with mocked Anthropic."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_instance = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_instance

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient
            client = LLMClient()

            yield client, mock_instance, mock_anthropic_module

    def test_complete_returns_text(self, mock_client):
        """Test that complete returns the response text."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Hello, world!")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            result = client.complete("Say hello")
        assert result == "Hello, world!"

    def test_complete_uses_model(self, mock_client):
        """Test that complete uses the configured model."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["model"] == client.model_name

    def test_complete_uses_temperature(self, mock_client):
        """Test that complete passes temperature parameter."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt", temperature=0.7)

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["temperature"] == 0.7

    def test_complete_default_temperature_zero(self, mock_client):
        """Test that complete defaults to temperature=0."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["temperature"] == 0

    def test_complete_raises_on_empty_response(self, mock_client):
        """Test that complete raises error on empty response."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = []  # Empty content
        mock_anthropic.messages.create.return_value = mock_response

        from src.llm.client import LLMClientError

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            with pytest.raises(LLMClientError, match="empty response"):
                client.complete("prompt")

    def test_complete_raises_on_api_error(self, mock_client):
        """Test that complete raises LLMClientError on API error."""
        client, mock_anthropic, mock_module = mock_client

        # Raise APIError from messages.create
        mock_anthropic.messages.create.side_effect = mock_module.APIError("Rate limited")

        from src.llm.client import LLMClientError

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            with pytest.raises(LLMClientError, match="API call failed"):
                client.complete("prompt")

    def test_complete_sets_max_tokens(self, mock_client):
        """Test that complete sets max_tokens."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 4096

