"""Tests for plan generation."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.governance.models import Constraints, EnhancedIntent, IntentCategory


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


def _mock_llm_output(description: str = "Test plan for unit testing") -> str:
    """Return a valid schema-conformant LLM output for tests."""
    return json.dumps({
        "version": "1.0.0",
        "plan_id": "00000000-0000-0000-0000-000000000000",
        "created_at": "2025-01-01T00:00:00Z",
        "execution_mode": "governance_driven",
        "description_for_user": description,
        "surface_effects": {
            "touches": ["/tmp/test.txt"],
            "modifies": False,
            "creates": False,
            "deletes": False,
        },
        "intent": {
            "summary": description,
            "category": "read",
            "five_w_one_h": {"who": "system", "what": "read file", "where": "/tmp", "when": "immediate", "why": "test", "how": "filesystem read"},
        },
        "steps": [{
            "step": 1,
            "action": "Read file",
            "inputs": {"required": [{"name": "path", "type": "string"}], "optional": []},
            "do": {"tool": "read", "operation": "file", "target": "/tmp/test.txt", "parameters": {}},
            "verify": {"checks": [{"name": "file_read", "evidence": "fs stat", "pass_condition": "file.exists == true"}]},
            "on_fail": {"behavior": "abort_plan", "refuse_if": []},
            "audit": {"record_outputs": [{"name": "contents", "type": "string", "write_to": "log"}]},
        }],
        "constraints": {"allow_unplanned": False, "max_total_operations": 5},
        "abort_conditions": [{"condition": "file.missing", "reason": "File not found"}],
    })


@pytest.fixture
def patterns_path(tmp_path: Path) -> str:
    """Create a temporary patterns config file."""
    patterns = {
        "tool_categories": {
            "file_read": ["read_file"],
            "file_write": ["write_file"],
            "file_delete": ["delete_file"],
            "network_request": ["http_get"],
            "code_execution": ["execute_code"],
        },
        "argument_patterns": {
            "sensitive_paths": ["^/etc/", ".*secret.*"],
            "external_urls": ["^https?://(?!localhost)"],
        },
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 2.0,
            "file_delete": 3.0,
            "network_request": 2.0,
            "code_execution": 4.0,
            "unknown": 2.5,
        },
    }
    path = tmp_path / "intent-patterns.json"
    path.write_text(json.dumps(patterns))
    return str(path)


@pytest.fixture
def schema_path(tmp_path: Path) -> str:
    """Create a temporary schema file (permissive for unit tests)."""
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
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
            "intent": {"type": "object"},
            "steps": {"type": "array"},
            "constraints": {"type": "object"},
            "abort_conditions": {"type": "array"},
            "description_for_user": {"type": "string"},
            "surface_effects": {"type": "object"},
        },
        "additionalProperties": True,
    }
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(schema))
    return str(path)


@pytest.fixture
def planner(patterns_path: str):
    """Create a PlanGenerator instance."""
    from src.governance.planner import PlanGenerator

    return PlanGenerator(patterns_path)


@pytest.fixture
def planner_with_schema(patterns_path: str, schema_path: str):
    """Create a PlanGenerator instance with schema."""
    from src.governance.planner import PlanGenerator

    return PlanGenerator(patterns_path, schema_path=schema_path)


class TestActionBuilding:
    """Tests for building planned actions."""

    def test_builds_ordered_actions(self, planner):
        """Test actions are built with sequential order."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[
                ToolCall(name="read_file", arguments={"path": "/tmp/a.txt"}),
                ToolCall(name="read_file", arguments={"path": "/tmp/b.txt"}),
            ],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        assert len(actions) == 2
        assert actions[0].sequence == 0
        assert actions[1].sequence == 1

    def test_assigns_category_from_tool(self, planner):
        """Test category is assigned from tool classification."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        assert actions[0].category == IntentCategory.FILE_READ

    def test_calculates_risk_score(self, planner):
        """Test risk score is calculated based on category."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_DELETE,
            signals=[],
            tool_calls=[ToolCall(name="delete_file", arguments={})],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        # file_delete has risk multiplier 3.0, so base risk should be elevated
        assert actions[0].risk_score > 0

    def test_higher_risk_for_code_execution(self, planner):
        """Test code execution has higher risk than file read."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        read_intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        exec_intent = Intent(
            primary_category=IntentCategory.CODE_EXECUTION,
            signals=[],
            tool_calls=[ToolCall(name="execute_code", arguments={})],
            confidence=0.9,
        )
        read_actions = planner._build_actions(read_intent)
        exec_actions = planner._build_actions(exec_intent)
        assert exec_actions[0].risk_score > read_actions[0].risk_score


class TestResourceExtraction:
    """Tests for extracting resources from tool calls."""

    def test_extracts_file_path(self, planner):
        """Test file path is extracted from arguments."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        assert len(resources) >= 1
        assert any(r.type == "file" and r.path == "/tmp/file.txt" for r in resources)

    def test_extracts_url(self, planner):
        """Test URL is extracted from arguments."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="http_get", arguments={"url": "https://api.example.com"})
        resources = planner._extract_resources(tc)
        assert any(r.type == "url" for r in resources)

    def test_determines_operation_read(self, planner):
        """Test read operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "read" for r in file_resources)

    def test_determines_operation_write(self, planner):
        """Test write operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "write" for r in file_resources)

    def test_determines_operation_delete(self, planner):
        """Test delete operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="delete_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "delete" for r in file_resources)

    def test_no_resources_for_unknown_args(self, planner):
        """Test no resources extracted for unknown argument patterns."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="custom_tool", arguments={"foo": "bar"})
        resources = planner._extract_resources(tc)
        # Should return empty or minimal resources
        assert isinstance(resources, list)


class TestRiskAssessment:
    """Tests for risk assessment calculation."""

    def test_calculates_overall_score(self, planner):
        """Test overall score is calculated from actions."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[ResourceAccess(type="file", path="/tmp/a", operation="read")],
                risk_score=30,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert 0 <= assessment.overall_score <= 100

    def test_determines_risk_level_low(self, planner):
        """Test LOW risk level for low scores."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            RiskLevel,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.level in (RiskLevel.LOW, RiskLevel.INFO)

    def test_determines_risk_level_high(self, planner):
        """Test HIGH risk level for high scores."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            RiskLevel,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=80,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_identifies_risk_factors(self, planner):
        """Test risk factors are identified."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=80,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert "code_execution" in assessment.factors

    def test_caps_at_100(self, planner):
        """Test overall score is capped at 100."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ToolCall,
        )

        # Create many high-risk actions
        actions = [
            PlannedAction(
                sequence=i,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=100,
            )
            for i in range(10)
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.overall_score == 100


class TestFullGeneration:
    """Tests for full plan generation."""

    def test_generates_plan_with_uuid(self, planner):
        """Test generated plan has valid UUID plan_id."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={"path": "/tmp"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={"tools": []})
        # Should be a valid UUID
        uuid.UUID(plan.plan_id)

    def test_includes_request_hash(self, planner):
        """Test plan includes request hash."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        request_body = {"tools": [{"name": "read_file"}]}
        plan = planner.generate(intent, request_body=request_body)
        assert len(plan.request_hash) == 64  # SHA-256 hex

    def test_request_hash_matches(self, planner):
        """Test request hash matches computed hash."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        request_body = {"tools": [{"name": "read_file"}]}
        plan = planner.generate(intent, request_body=request_body)

        expected_hash = hashlib.sha256(
            json.dumps(request_body, sort_keys=True).encode()
        ).hexdigest()
        assert plan.request_hash == expected_hash

    def test_includes_session_id(self, planner):
        """Test plan includes session ID when provided."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={}, session_id="sess-123")
        assert plan.session_id == "sess-123"

    def test_session_id_none_when_not_provided(self, planner):
        """Test session_id is None when not provided."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert plan.session_id is None

    def test_empty_intent_empty_actions(self, planner):
        """Test empty intent produces empty actions."""
        from src.governance.models import Intent, IntentCategory

        empty_intent = Intent(
            primary_category=IntentCategory.UNKNOWN,
            signals=[],
            tool_calls=[],
            confidence=1.0,
        )
        plan = planner.generate(empty_intent, request_body={})
        assert plan.actions == []

    def test_actions_have_resources(self, planner):
        """Test generated actions include resources."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert len(plan.actions) == 1
        assert len(plan.actions[0].resources) > 0

    def test_risk_assessment_included(self, planner):
        """Test plan includes risk assessment."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.CODE_EXECUTION,
            signals=[],
            tool_calls=[ToolCall(name="execute_code", arguments={"code": "print(1)"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert plan.risk_assessment is not None
        assert plan.risk_assessment.overall_score > 0


class TestSanitization:
    """Tests for sanitizing data before LLM calls using allowlist approach."""

    def test_sanitize_allows_plan_structure_keys(self, planner):
        """Test that plan structure keys are allowed."""
        data = {
            "plan_id": "test-123",
            "session_id": "sess-456",
            "actions": [],
            "risk_assessment": {"overall_score": 50},
        }
        result = planner._sanitize_for_llm(data)
        assert result["plan_id"] == "test-123"
        assert result["session_id"] == "sess-456"
        assert result["actions"] == []
        assert result["risk_assessment"]["overall_score"] == 50

    def test_sanitize_redacts_unknown_keys(self, planner):
        """Test that unknown keys are redacted (allowlist approach)."""
        data = {
            "plan_id": "test-123",
            "unknown_field": "should be redacted",
            "another_unknown": {"nested": "value"},
        }
        result = planner._sanitize_for_llm(data)
        assert result["plan_id"] == "test-123"
        assert result["unknown_field"] == "[REDACTED]"
        assert result["another_unknown"] == "[REDACTED]"

    def test_sanitize_allows_safe_argument_keys(self, planner):
        """Test that safe argument keys are allowed inside arguments."""
        data = {
            "tool_call": {
                "name": "read_file",
                "arguments": {
                    "path": "/tmp/file.txt",
                    "mode": "read",
                    "encoding": "utf-8",
                }
            }
        }
        result = planner._sanitize_for_llm(data)
        assert result["tool_call"]["arguments"]["path"] == "/tmp/file.txt"
        assert result["tool_call"]["arguments"]["mode"] == "read"
        assert result["tool_call"]["arguments"]["encoding"] == "utf-8"

    def test_sanitize_redacts_sensitive_argument_keys(self, planner):
        """Test that sensitive keys in arguments are redacted."""
        data = {
            "tool_call": {
                "name": "api_call",
                "arguments": {
                    "path": "/tmp/file.txt",  # safe - in SAFE_ARGUMENT_KEYS
                    "api_key": "sk-secret",   # not safe - redacted
                    "password": "secret123",  # not safe - redacted
                    "token": "bearer-xyz",    # not safe - redacted
                }
            }
        }
        result = planner._sanitize_for_llm(data)
        assert result["tool_call"]["arguments"]["path"] == "/tmp/file.txt"
        assert result["tool_call"]["arguments"]["api_key"] == "[REDACTED]"
        assert result["tool_call"]["arguments"]["password"] == "[REDACTED]"
        assert result["tool_call"]["arguments"]["token"] == "[REDACTED]"

    def test_sanitize_nested_actions(self, planner):
        """Test sanitization of nested action structures."""
        data = {
            "actions": [
                {
                    "sequence": 0,
                    "tool_call": {
                        "name": "read_file",
                        "arguments": {
                            "path": "/tmp/test.txt",
                            "secret_key": "should-redact",
                        }
                    },
                    "category": "file_read",
                    "risk_score": 10,
                }
            ]
        }
        result = planner._sanitize_for_llm(data)
        action = result["actions"][0]
        assert action["sequence"] == 0
        assert action["tool_call"]["name"] == "read_file"
        assert action["tool_call"]["arguments"]["path"] == "/tmp/test.txt"
        assert action["tool_call"]["arguments"]["secret_key"] == "[REDACTED]"
        assert action["category"] == "file_read"
        assert action["risk_score"] == 10

    def test_sanitize_preserves_resources(self, planner):
        """Test that resource fields are preserved."""
        data = {
            "resources": [
                {"type": "file", "path": "/tmp/test.txt", "operation": "read"}
            ]
        }
        result = planner._sanitize_for_llm(data)
        assert result["resources"][0]["type"] == "file"
        assert result["resources"][0]["path"] == "/tmp/test.txt"
        assert result["resources"][0]["operation"] == "read"

    def test_count_redacted_fields(self, planner):
        """Test counting redacted fields."""
        data = {
            "plan_id": "test",
            "unknown1": "[REDACTED]",
            "unknown2": "[REDACTED]",
            "actions": [{"secret": "[REDACTED]"}],
        }
        count = planner._count_redacted_fields(data)
        assert count == 3

    def test_count_redacted_empty(self, planner):
        """Test counting with no redacted fields."""
        data = {"plan_id": "test", "session_id": "sess"}
        count = planner._count_redacted_fields(data)
        assert count == 0


class TestEnhanceSecurityAudit:
    """Tests for security audit logging during enhance()."""

    def test_enhance_logs_security_audit(
        self, planner_with_schema, caplog, _mock_random_context
    ):
        """Test that enhance() logs a security audit event."""
        from src.governance.models import (
            ExecutionPlan,
            PlannedAction,
            IntentCategory,
            ToolCall,
            RiskAssessment,
            RiskLevel,
        )

        # Create a minimal plan
        plan = ExecutionPlan(
            plan_id="test-plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(
                        name="read_file",
                        arguments={"path": "/tmp/test.txt", "password": "secret"},
                    ),
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

        mock_llm = MagicMock()
        mock_llm.complete.return_value = _mock_llm_output("Test plan for audit logging")

        with caplog.at_level(logging.INFO):
            planner_with_schema.enhance(plan, llm=mock_llm, user_message="test")

        # Check audit log was created
        assert any("SECURITY_AUDIT" in record.message for record in caplog.records)
        assert any("test-plan-123" in record.message for record in caplog.records)

    def test_enhance_does_not_leak_plan_data_to_llm(self, planner_with_schema, _mock_random_context):
        """Test that base plan data (including sensitive args) is not sent to LLM."""
        from src.governance.models import (
            ExecutionPlan,
            PlannedAction,
            IntentCategory,
            ToolCall,
            RiskAssessment,
            RiskLevel,
        )

        plan = ExecutionPlan(
            plan_id="test-plan",
            session_id="session",
            request_hash="b" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(
                        name="api_call",
                        arguments={
                            "url": "https://api.example.com",
                            "api_key": "sk-secret-key-12345",
                            "password": "super-secret",
                        },
                    ),
                    category=IntentCategory.NETWORK_REQUEST,
                    resources=[],
                    risk_score=20,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=20,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

        mock_llm = MagicMock()
        mock_llm.complete.return_value = _mock_llm_output("Test sanitization plan")

        planner_with_schema.enhance(plan, llm=mock_llm, user_message="test")

        # Check what was sent to LLM
        call_args = mock_llm.complete.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]

        # Base plan data (including sensitive values) should NOT appear in prompt
        # The prompt only contains user_message, local_context, and schema
        assert "sk-secret-key-12345" not in prompt
        assert "super-secret" not in prompt
        assert "https://api.example.com" not in prompt
        assert "test-plan" not in prompt

    def test_enhance_logs_redacted_count(self, planner_with_schema, caplog, _mock_random_context):
        """Test that audit log includes count of redacted fields."""
        from src.governance.models import (
            ExecutionPlan,
            PlannedAction,
            IntentCategory,
            ToolCall,
            RiskAssessment,
            RiskLevel,
        )

        plan = ExecutionPlan(
            plan_id="plan-with-secrets",
            session_id="session",
            request_hash="c" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(
                        name="db_connect",
                        arguments={
                            "path": "/tmp/db.sock",  # safe - in SAFE_ARGUMENT_KEYS
                            "password": "dbpass",    # not safe - redacted
                            "token": "auth-token",   # not safe - redacted
                        },
                    ),
                    category=IntentCategory.NETWORK_REQUEST,
                    resources=[],
                    risk_score=30,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=30,
                level=RiskLevel.MEDIUM,
                factors=[],
                mitigations=[],
            ),
        )

        mock_llm = MagicMock()
        mock_llm.complete.return_value = _mock_llm_output("DB connection test plan")

        with caplog.at_level(logging.INFO):
            planner_with_schema.enhance(plan, llm=mock_llm, user_message="test")

        # Find the audit log message
        audit_logs = [r for r in caplog.records if "SECURITY_AUDIT" in r.message]
        assert len(audit_logs) == 1
        # Should mention fields_redacted=2 (password and token - path is safe)
        assert "fields_redacted=2" in audit_logs[0].message

class TestIntentParsing:

    def test_parse_intent_category_mapping(self, planner_with_schema):
        """Category string should map correctly to IntentCategory enum."""
        data = {
            "summary": "Read a file from the system",
            "category": "read",
            "five_w_one_h": {
                "who": "system",
                "what": "read file",
                "where": "/tmp",
                "when": "now",
                "why": "testing",
                "how": "filesystem",
            },
        }

        intent = planner_with_schema._parse_intent(data, "Read a file from the system")

        from src.governance.models import IntentCategory
        assert intent.primary_category == IntentCategory.FILE_READ


    def test_parse_intent_defaults(self, planner_with_schema):
        """Intent should apply defaults for optional fields."""
        data = {
            "summary": "Read a configuration file for testing",
            "category": "read",
            "five_w_one_h": {},
        }

        intent = planner_with_schema._parse_intent(data, "Read a configuration file for testing")

        assert intent.signals == []
        assert intent.tool_calls == []
        assert intent.confidence == 1.0

    def test_parse_intent_unknown_category(self, planner_with_schema):
        """Unknown category should map to UNKNOWN."""
        data = {
            "summary": "Something strange",
            "category": "unknown_category",
            "five_w_one_h": {},
        }

        intent = planner_with_schema._parse_intent(data, "Some user query")

        from src.governance.models import IntentCategory
        assert intent.primary_category == IntentCategory.UNKNOWN


class TestConstraintsModel:

    def test_allow_unplanned_must_be_false(self):
        """Constraints must reject allow_unplanned=True."""
        with pytest.raises(Exception):
            Constraints(allow_unplanned=True)


    def test_constraints_defaults(self):
        """Default constraint values should be valid."""
        c = Constraints()

        assert c.allow_unplanned is False
        assert c.max_total_operations == 50


class TestEnhancedIntentValidation:

    def test_summary_min_length(self):
        """Summary shorter than required should fail."""
        import pytest

        with pytest.raises(Exception):
            EnhancedIntent(
                summary="short",
                primary_category=IntentCategory.FILE_READ,
                signals=[],
                tool_calls=[],
                confidence=1.0,
            )


    def test_confidence_bounds(self):
        """Confidence must be between 0 and 1."""
        import pytest

        with pytest.raises(Exception):
            EnhancedIntent(
                summary="Valid summary of plan",
                primary_category=IntentCategory.FILE_READ,
                signals=[],
                tool_calls=[],
                confidence=2.0,
            )


