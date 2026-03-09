"""Tests for governance middleware."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def secret() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def policy_path(tmp_path: Path) -> str:
    policy_file = tmp_path / "policies.json"
    policies = [
        {
            "id": "GOV-001",
            "name": "Block file delete",
            "type": "action",
            "effect": "deny",
            "priority": 100,
            "conditions": {"category": "file_delete"},
        },
        {
            "id": "GOV-002",
            "name": "Approve code execution",
            "type": "action",
            "effect": "require_approval",
            "priority": 90,
            "conditions": {"category": "code_execution"},
        },
    ]
    policy_file.write_text(json.dumps(policies))
    return str(policy_file)


@pytest.fixture
def patterns_path(tmp_path: Path) -> str:
    patterns_file = tmp_path / "patterns.json"
    patterns = {
        "tool_categories": {
            "file_read": ["read_file", "get_file"],
            "file_write": ["write_file", "save_file"],
            "file_delete": ["delete_file", "remove_file"],
            "code_execution": ["execute_code", "run_script"],
        },
        "argument_patterns": {"sensitive_paths": ["^/etc/", ".*password.*"]},
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 1.5,
            "file_delete": 2.0,
            "code_execution": 2.5,
        },
    }
    patterns_file.write_text(json.dumps(patterns))
    return str(patterns_file)


@pytest.fixture
def settings() -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": "enforce",
        "approval": {"enabled": True, "timeout_seconds": 3600},
        "session": {"enabled": True, "ttl_seconds": 3600},
        "enforcement": {"enabled": True, "token_ttl_seconds": 900},
        "bypass_paths": ["/health", "/healthz"],
    }


@pytest.fixture
def middleware(governance_db_path: str, secret: str, policy_path: str, patterns_path: str, settings: dict):
    from src.governance.middleware import GovernanceMiddleware

    mw = GovernanceMiddleware(
        db_path=governance_db_path,
        secret=secret,
        policy_path=policy_path,
        patterns_path=patterns_path,
        settings=settings,
    )
    yield mw
    mw.close()


class TestMiddlewareInit:
    def test_creates_with_settings(
        self, governance_db_path, secret, policy_path, patterns_path, settings
    ):
        from src.governance.middleware import GovernanceMiddleware

        mw = GovernanceMiddleware(
            db_path=governance_db_path,
            secret=secret,
            policy_path=policy_path,
            patterns_path=patterns_path,
            settings=settings,
        )
        assert mw is not None

    async def test_disabled_middleware_allows_all(
        self, governance_db_path, secret, policy_path, patterns_path
    ):
        from src.governance.middleware import GovernanceMiddleware
        from src.governance.models import GovernanceDecision

        settings = {"enabled": False}
        mw = GovernanceMiddleware(
            db_path=governance_db_path,
            secret=secret,
            policy_path=policy_path,
            patterns_path=patterns_path,
            settings=settings,
        )

        result = await mw.evaluate(
            request_body={"tools": [{"type": "function", "function": {"name": "delete_file"}}]},
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.ALLOW


class TestEvaluate:
    async def test_blocked_action_returns_block(self, middleware):
        from src.governance.models import GovernanceDecision

        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "delete_file", "arguments": {"path": "/tmp/file"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.BLOCK
        assert len(result.violations) > 0

    async def test_allowed_action_returns_allow(self, middleware):
        from src.governance.models import GovernanceDecision

        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/safe.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.ALLOW

    async def test_requires_approval_for_code_execution(self, middleware):
        from src.governance.models import GovernanceDecision

        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "print('hi')"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
        assert result.approval_id is not None


class TestPlanGeneration:
    async def test_generates_plan_for_allowed_request(self, middleware):
        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.plan_id is not None
        assert result.token is not None

    async def test_plan_includes_session_binding(self, middleware):
        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id="sess-123",
            user_id="user-1",
        )
        # Plan should be bound to session
        assert result.plan_id is not None


class TestApprovalFlow:
    async def test_creates_approval_for_risky_action(self, middleware):
        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "rm -rf /"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.approval_id is not None

    async def test_stores_original_request_for_retry(self, middleware):
        from src.governance.models import GovernanceDecision

        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "test"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL

        # Original request should be stored with approval
        approval = middleware.get_approval(result.approval_id)
        assert approval is not None
        assert approval.original_request is not None


class TestEnforcement:
    async def test_enforce_with_valid_token(self, middleware):
        from src.governance.models import GovernanceDecision, ToolCall

        # First, get a plan
        eval_result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert eval_result.decision == GovernanceDecision.ALLOW

        # Now enforce action
        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        enforce_result = middleware.enforce(
            plan_id=eval_result.plan_id,
            token=eval_result.token,
            tool_call=tool_call,
        )
        assert enforce_result.allowed is True

    def test_enforce_rejects_without_plan(self, middleware):
        from src.governance.models import ToolCall

        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = middleware.enforce(
            plan_id="nonexistent",
            token="invalid.token",
            tool_call=tool_call,
        )
        assert result.allowed is False


class TestSessionManagement:
    async def test_creates_session_on_first_request(self, middleware):
        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        # Should have a session ID in the result
        assert result.session_id is not None

    async def test_reuses_existing_session(self, middleware):
        # First request
        result1 = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/a.txt"}}}]
            },
            session_id="sess-abc",
            user_id="user-1",
        )

        # Second request with same session
        result2 = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/b.txt"}}}]
            },
            session_id="sess-abc",
            user_id="user-1",
        )

        assert result1.session_id == result2.session_id == "sess-abc"


class TestEvaluationResult:
    async def test_result_structure(self, middleware):
        from src.governance.models import GovernanceDecision

        result = await middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )

        assert hasattr(result, "decision")
        assert hasattr(result, "plan_id")
        assert hasattr(result, "token")
        assert hasattr(result, "violations")
        assert hasattr(result, "session_id")
        assert result.decision == GovernanceDecision.ALLOW


class TestSchemaPathResolution:
    """Tests for schema path resolution in middleware initialization."""

    def test_schema_path_default_canonical_location(self, tmp_path, secret):
        """Test that default schema path is at schemas/execution-plan/1.0.0/schema.json."""
        from src.governance.middleware import GovernanceMiddleware

        # Create project structure: tmp_path is the project root
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        patterns_file = config_dir / "intent-patterns.json"
        patterns_file.write_text(json.dumps({
            "tool_categories": {},
            "argument_patterns": {},
            "risk_multipliers": {},
        }))

        policy_file = config_dir / "policies.json"
        policy_file.write_text(json.dumps([]))

        # Create schema at the canonical location (relative to project root)
        schema_dir = tmp_path / "schemas" / "execution-plan" / "1.0.0"
        schema_dir.mkdir(parents=True)
        schema_file = schema_dir / "schema.json"
        schema_file.write_text(json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"description_for_user": {"type": "string"}},
        }))

        db_path = str(tmp_path / "test.db")

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=str(policy_file),
            patterns_path=str(patterns_file),
            settings={"enabled": True},
        )

        # Planner should have loaded the schema from canonical location
        assert middleware._planner._schema is not None

    def test_schema_path_explicit_absolute(self, tmp_path, secret):
        """Test that explicit absolute schema path is used as-is."""
        from src.governance.middleware import GovernanceMiddleware

        # Create config files
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        patterns_file = config_dir / "intent-patterns.json"
        patterns_file.write_text(json.dumps({
            "tool_categories": {},
            "argument_patterns": {},
            "risk_multipliers": {},
        }))

        policy_file = config_dir / "policies.json"
        policy_file.write_text(json.dumps([]))

        # Schema in a completely different directory
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        schema_file = other_dir / "my-schema.json"
        schema_file.write_text(json.dumps({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"description": {"type": "string"}},
        }))

        db_path = str(tmp_path / "test.db")

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=str(policy_file),
            patterns_path=str(patterns_file),
            settings={
                "enabled": True,
                "enhancement": {
                    "schema_path": str(schema_file),  # Absolute path
                },
            },
        )

        # Planner should have loaded the schema from explicit path
        assert middleware._planner._schema is not None

    def test_schema_path_relative_resolved_from_project_root(self, tmp_path, secret):
        """Test that relative schema path is resolved from project root."""
        from src.governance.middleware import GovernanceMiddleware

        # Create config files
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        patterns_file = config_dir / "intent-patterns.json"
        patterns_file.write_text(json.dumps({
            "tool_categories": {},
            "argument_patterns": {},
            "risk_multipliers": {},
        }))

        policy_file = config_dir / "policies.json"
        policy_file.write_text(json.dumps([]))

        # Schema at a custom relative path from project root
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        schema_file = custom_dir / "my-schema.json"
        schema_file.write_text(json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"description_for_user": {"type": "string"}},
        }))

        db_path = str(tmp_path / "test.db")

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=str(policy_file),
            patterns_path=str(patterns_file),
            settings={
                "enabled": True,
                "enhancement": {
                    "schema_path": "custom/my-schema.json",  # Relative to project root
                },
            },
        )

        # Planner should have loaded the schema
        assert middleware._planner._schema is not None

    def test_schema_path_missing_file_handled(self, tmp_path, secret):
        """Test that missing schema file results in None schema."""
        from src.governance.middleware import GovernanceMiddleware

        config_dir = tmp_path / "config"
        config_dir.mkdir()

        patterns_file = config_dir / "intent-patterns.json"
        patterns_file.write_text(json.dumps({
            "tool_categories": {},
            "argument_patterns": {},
            "risk_multipliers": {},
        }))

        policy_file = config_dir / "policies.json"
        policy_file.write_text(json.dumps([]))

        # No schema file created

        db_path = str(tmp_path / "test.db")

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=str(policy_file),
            patterns_path=str(patterns_file),
            settings={"enabled": True},
        )

        # Planner should have None schema (file doesn't exist)
        assert middleware._planner._schema is None

class TestExtractUserMessage:

    def test_extract_user_message_string_content(self, middleware):
        """Extract user message when content is a simple string."""
        body = {
            "messages": [
                {"role": "user", "content": "Read /etc/hosts"}
            ]
        }
        msg = middleware._extract_user_message(body)
        assert msg == "Read /etc/hosts"

    def test_extract_user_message_content_blocks(self, middleware):
        """Extract user message when content is structured blocks."""
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Read /tmp/file.txt"}
                    ],
                }
            ]
        }
        msg = middleware._extract_user_message(body)
        assert msg == "Read /tmp/file.txt"

    def test_extract_user_message_last_user_wins(self, middleware):
        """If multiple user messages exist, the last one should be used."""
        body = {
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "assistant", "content": "ignored"},
                {"role": "user", "content": "second"},
            ]
        }
        msg = middleware._extract_user_message(body)
        assert msg == "second"

    def test_extract_user_message_returns_none_if_missing(self, middleware):
        """Return None if no user message exists."""
        body = {
            "messages": [
                {"role": "assistant", "content": "hello"}
            ]
        }
        msg = middleware._extract_user_message(body)
        assert msg is None