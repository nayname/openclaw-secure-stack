"""Tests for operational profile loading and validation."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from src.governance.models import (
    DatabaseConfig,
    NetworkConfig,
    OperationalProfile,
    PathConfig,
    Procedure,
    ServiceConfig,
)
from src.governance.profile import ProfileLoader, load_profile


class TestOperationalProfile:
    """Tests for OperationalProfile model."""

    def test_create_minimal_profile(self):
        """Test creating a profile with minimal fields."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test Profile",
        )

        assert profile.profile_id == "test"
        assert profile.name == "Test Profile"
        assert profile.environment == "development"
        assert profile.paths.working_dirs == []
        assert profile.paths.protected_paths == []

    def test_create_full_profile(self):
        """Test creating a profile with all fields."""
        profile = OperationalProfile(
            profile_id="full-test",
            name="Full Test Profile",
            description="A complete test profile",
            version="2.0.0",
            environment="production",
            project_root="~/code/myproject",
            paths=PathConfig(
                working_dirs=["~/code/myproject"],
                protected_paths=["~/.ssh", "/etc"],
                sensitive_patterns=["*.env", "*secret*"],
                scratch_dirs=["/tmp"],
            ),
            database=DatabaseConfig(
                protected_tables=["users", "payments"],
                safe_tables=["sessions", "cache_*"],
                require_where_clause=True,
                max_affected_rows=500,
            ),
            services=ServiceConfig(
                protected_services=["postgres", "nginx"],
                safe_services=["redis"],
                forbidden_commands=["rm -rf /"],
                confirm_commands=["reboot"],
            ),
            network=NetworkConfig(
                allowed_domains=["api.github.com"],
                blocked_domains=["*.pastebin.com"],
            ),
            procedures=[
                Procedure(
                    name="credential_rotation",
                    description="Rotate credentials safely",
                    required_steps=["Generate new creds", "Update services"],
                    preconditions=["All services healthy"],
                    postconditions=["All services connected"],
                    rollback_steps=["Revert to old creds"],
                )
            ],
            global_constraints=["Never modify production"],
            maintenance_windows=["0 2 * * 0"],
            blocked_hours=["09:00-18:00"],
            notify_on_high_risk=True,
            notify_channels=["slack:#ops"],
        )

        assert profile.profile_id == "full-test"
        assert profile.environment == "production"
        assert len(profile.paths.working_dirs) == 1
        assert len(profile.procedures) == 1
        assert profile.procedures[0].name == "credential_rotation"

    def test_is_path_allowed(self):
        """Test path validation against profile."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            paths=PathConfig(
                working_dirs=["~/code/project"],
                protected_paths=["~/.ssh", "/etc", "~/.aws"],
            ),
        )

        # Protected paths should be blocked
        assert profile.is_path_allowed("~/.ssh/id_rsa") is False
        assert profile.is_path_allowed("/etc/passwd") is False
        assert profile.is_path_allowed("~/.aws/credentials") is False

        # Working dirs should be allowed
        assert profile.is_path_allowed("~/code/project/src/main.py") is True

        # Outside working dirs should be blocked (when working_dirs is set)
        assert profile.is_path_allowed("~/other/file.txt") is False

    def test_is_path_allowed_no_working_dirs(self):
        """Test path validation when no working dirs are set."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            paths=PathConfig(
                protected_paths=["~/.ssh"],
            ),
        )

        # Protected still blocked
        assert profile.is_path_allowed("~/.ssh/id_rsa") is False

        # Everything else allowed when no working_dirs
        assert profile.is_path_allowed("~/any/path") is True
        assert profile.is_path_allowed("/tmp/file") is True

    def test_is_table_protected(self):
        """Test database table protection."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            database=DatabaseConfig(
                protected_tables=["users", "payments", "orders_*"],
            ),
        )

        assert profile.is_table_protected("users") is True
        assert profile.is_table_protected("payments") is True
        assert profile.is_table_protected("orders_2024") is True
        assert profile.is_table_protected("sessions") is False
        assert profile.is_table_protected("cache") is False

    def test_is_command_forbidden(self):
        """Test command blocking."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            services=ServiceConfig(
                forbidden_commands=[
                    "rm -rf /",
                    "rm -rf ~",
                    "DROP DATABASE",
                ],
            ),
        )

        assert profile.is_command_forbidden("rm -rf /") is True
        assert profile.is_command_forbidden("rm -rf ~") is True
        assert profile.is_command_forbidden("DROP DATABASE production") is True
        assert profile.is_command_forbidden("rm file.txt") is False
        assert profile.is_command_forbidden("ls -la") is False

    def test_is_domain_allowed(self):
        """Test domain allowlist/blocklist."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            network=NetworkConfig(
                allowed_domains=["api.github.com", "*.internal.company.com"],
                blocked_domains=["*.pastebin.com", "*.webhook.site"],
            ),
        )

        # Blocked domains
        assert profile.is_domain_allowed("evil.pastebin.com") is False
        assert profile.is_domain_allowed("test.webhook.site") is False

        # Allowed domains
        assert profile.is_domain_allowed("api.github.com") is True
        assert profile.is_domain_allowed("svc.internal.company.com") is True

        # Not in allowlist = blocked
        assert profile.is_domain_allowed("google.com") is False

    def test_is_domain_allowed_no_allowlist(self):
        """Test domain checking when no allowlist is set."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            network=NetworkConfig(
                blocked_domains=["*.pastebin.com"],
            ),
        )

        # Blocked still blocked
        assert profile.is_domain_allowed("evil.pastebin.com") is False

        # Everything else allowed when no allowlist
        assert profile.is_domain_allowed("google.com") is True
        assert profile.is_domain_allowed("api.github.com") is True

    def test_get_procedure(self):
        """Test procedure lookup."""
        profile = OperationalProfile(
            profile_id="test",
            name="Test",
            procedures=[
                Procedure(
                    name="credential_rotation",
                    description="Rotate creds",
                    required_steps=["Step 1", "Step 2"],
                ),
                Procedure(
                    name="database_cleanup",
                    description="Clean DB",
                    required_steps=["Step A", "Step B"],
                ),
            ],
        )

        proc = profile.get_procedure("credential_rotation")
        assert proc is not None
        assert proc.name == "credential_rotation"
        assert len(proc.required_steps) == 2

        proc = profile.get_procedure("database_cleanup")
        assert proc is not None
        assert proc.name == "database_cleanup"

        proc = profile.get_procedure("nonexistent")
        assert proc is None


class TestProfileLoader:
    """Tests for ProfileLoader."""

    def test_load_from_dict(self):
        """Test loading profile from dictionary."""
        loader = ProfileLoader()

        data = {
            "profile_id": "dict-test",
            "name": "Dict Test Profile",
            "environment": "staging",
            "paths": {
                "working_dirs": ["~/code"],
                "protected_paths": ["~/.ssh"],
            },
            "database": {
                "protected_tables": ["users"],
            },
        }

        profile = loader.load_from_dict(data)

        assert profile.profile_id == "dict-test"
        assert profile.name == "Dict Test Profile"
        assert profile.environment == "staging"
        assert profile.paths.working_dirs == ["~/code"]
        assert profile.database.protected_tables == ["users"]

    def test_load_from_file(self):
        """Test loading profile from JSON file."""
        loader = ProfileLoader()

        data = {
            "profile_id": "file-test",
            "name": "File Test Profile",
            "environment": "production",
            "paths": {
                "working_dirs": ["~/project"],
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            profile = loader.load_from_file(temp_path)

            assert profile.profile_id == "file-test"
            assert profile.name == "File Test Profile"
            assert profile.environment == "production"
        finally:
            os.unlink(temp_path)

    def test_load_from_file_not_found(self):
        """Test loading from nonexistent file."""
        loader = ProfileLoader()

        with pytest.raises(FileNotFoundError):
            loader.load_from_file("/nonexistent/path/profile.json")

    def test_load_from_file_invalid_json(self):
        """Test loading from invalid JSON file."""
        loader = ProfileLoader()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ invalid json }")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Invalid JSON"):
                loader.load_from_file(temp_path)
        finally:
            os.unlink(temp_path)

    def test_get_default_profile(self):
        """Test getting default safe profile."""
        loader = ProfileLoader()

        profile = loader.get_default_profile()

        assert profile.profile_id == "default-safe"
        assert profile.name == "Default Safe Profile"
        assert "~/.ssh" in profile.paths.protected_paths
        assert "users" in profile.database.protected_tables
        assert profile.database.require_where_clause is True

    def test_register_and_get_profile(self):
        """Test registering and retrieving profiles."""
        loader = ProfileLoader()

        profile1 = OperationalProfile(profile_id="p1", name="Profile 1")
        profile2 = OperationalProfile(profile_id="p2", name="Profile 2")

        loader.register_profile(profile1)
        loader.register_profile(profile2)

        assert loader.get_profile("p1") == profile1
        assert loader.get_profile("p2") == profile2
        assert loader.get_profile("nonexistent") is None


class TestLoadProfileHelper:
    """Tests for the load_profile helper function."""

    def test_load_profile_with_path(self):
        """Test load_profile with explicit path."""
        data = {
            "profile_id": "helper-test",
            "name": "Helper Test",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            profile = load_profile(temp_path)
            assert profile.profile_id == "helper-test"
        finally:
            os.unlink(temp_path)

    def test_load_profile_fallback_to_default(self):
        """Test load_profile falls back to default when no profile found."""
        # With no path and no discoverable profile, should get default
        profile = load_profile()

        assert profile.profile_id == "default-safe"
        assert profile.name == "Default Safe Profile"
