"""Tests for configuration loading and validation."""

import pytest

from spine.config import parse_config


class TestConfigValidation:
    def test_minimal_valid_config(self):
        raw = {
            "spine": {"log_level": "info"},
            "servers": [],
        }
        cfg = parse_config(raw)
        assert cfg.log_level == "info"
        assert len(cfg.servers) == 0

    def test_server_with_allowed_command(self):
        raw = {
            "servers": [
                {
                    "name": "test",
                    "command": "python",
                    "args": ["-m", "my_server"],
                }
            ],
        }
        cfg = parse_config(raw)
        assert len(cfg.servers) == 1
        assert cfg.servers[0].name == "test"

    def test_server_pii_scrambling_flags(self):
        raw = {
            "servers": [
                {
                    "name": "postgres",
                    "command": "python",
                    "scramble_pii_in_responses": True,
                    "scramble_pii_use_nlp": False,
                },
                {
                    "name": "other",
                    "command": "python",
                },
            ],
        }

        cfg = parse_config(raw)

        assert cfg.servers[0].scramble_pii_in_responses is True
        assert cfg.servers[0].scramble_pii_use_nlp is False
        assert cfg.servers[1].scramble_pii_in_responses is False
        assert cfg.servers[1].scramble_pii_use_nlp is True

    def test_server_with_blocked_command(self):
        raw = {
            "servers": [
                {
                    "name": "evil",
                    "command": "bash",
                    "args": ["-c", "echo pwned"],
                }
            ],
        }
        with pytest.raises(ValueError, match="not in allowed"):
            parse_config(raw)

    def test_duplicate_server_names_rejected(self):
        raw = {
            "servers": [
                {"name": "dup", "command": "python", "args": []},
                {"name": "dup", "command": "node", "args": []},
            ],
        }
        with pytest.raises(ValueError, match="Duplicate"):
            parse_config(raw)

    def test_invalid_minifier_level(self):
        raw = {
            "servers": [],
            "minifier": {"level": 5},
        }
        with pytest.raises(ValueError, match="minifier.level"):
            parse_config(raw)

    def test_env_var_resolution(self, monkeypatch):
        monkeypatch.setenv("TEST_TOKEN", "secret123")
        raw = {
            "servers": [
                {
                    "name": "gh",
                    "command": "npx",
                    "args": ["-y", "@mcp/server-github"],
                    "env": {"GITHUB_TOKEN": "${TEST_TOKEN}"},
                }
            ],
        }
        cfg = parse_config(raw)
        assert cfg.servers[0].env["GITHUB_TOKEN"] == "secret123"

    def test_undefined_env_var_fails(self):
        raw = {
            "servers": [
                {
                    "name": "gh",
                    "command": "npx",
                    "args": [],
                    "env": {"TOKEN": "${NONEXISTENT_VAR_XYZ}"},
                }
            ],
        }
        with pytest.raises(ValueError, match="not set"):
            parse_config(raw)

    def test_security_policy_loaded(self):
        raw = {
            "servers": [],
            "security": {
                "global_rate_limit": 100,
                "tools": [
                    {"pattern": "shell_*", "action": "deny"},
                ],
            },
        }
        cfg = parse_config(raw)
        assert cfg.security.global_rate_limit == 100
        assert not cfg.security.is_tool_allowed("shell_exec")

    def test_routing_defaults(self):
        cfg = parse_config({"servers": []})
        assert cfg.routing.max_tools == 5
        assert "spine_set_context" in cfg.routing.always_include

    def test_state_guard_defaults(self):
        cfg = parse_config({"servers": []})
        assert cfg.state_guard.enabled is True
        assert cfg.state_guard.max_tracked_files == 200
