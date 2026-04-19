"""
Tests for the MCP Spine security module.

Covers:
  - Secret detection and scrubbing
  - Path traversal prevention
  - JSON-RPC message validation
  - Command injection guards
  - Rate limiting
  - Environment variable resolution
  - Audit fingerprinting
"""


import importlib.util

import pytest

import spine.security.pii as pii_module
from spine.security import (
    PathViolation,
    RateLimitBucket,
    RateLimiter,
    ValidationError,
    audit_fingerprint,
    contains_secret,
    hash_content,
    hash_tool_schema,
    is_path_safe,
    resolve_env_vars,
    scramble_pii,
    scramble_pii_value,
    scrub_secrets,
    validate_message,
    validate_path,
    validate_server_command,
)
from spine.security.pii import PiiScramblerUnavailable
from spine.security.policy import (
    PathPolicy,
    PolicyAction,
    SecurityPolicy,
    ToolPolicy,
    load_security_policy,
)

# ───────────────────────────────────────────────
# Secret Detection & Scrubbing
# ───────────────────────────────────────────────

class TestSecretScrubbing:
    def test_aws_key_detected(self):
        text = "key = AKIAIOSFODNN7EXAMPLE"
        assert contains_secret(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in scrub_secrets(text)

    def test_github_token_detected(self):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert contains_secret(text)
        assert "[REDACTED]" in scrub_secrets(text)

    def test_bearer_token_detected(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIs.something.here"
        assert contains_secret(text)

    def test_private_key_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        assert contains_secret(text)

    def test_connection_string_detected(self):
        text = "postgres://admin:s3cret@db.host.com:5432/mydb"
        assert contains_secret(text)

    def test_clean_text_not_flagged(self):
        text = "This is a normal log message about tool execution"
        assert not contains_secret(text)
        assert scrub_secrets(text) == text

    def test_api_key_pattern(self):
        text = "api_key=sk_live_abc123def456"
        assert contains_secret(text)

    def test_multiple_secrets_scrubbed(self):
        text = "key=AKIAIOSFODNN7EXAMPLE token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        cleaned = scrub_secrets(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
        assert "ghp_" not in cleaned


# ───────────────────────────────────────────────
# PII Detection & Scrambling
# ───────────────────────────────────────────────

class TestPIIScrambling:
    has_pii_deps = all(
        importlib.util.find_spec(module)
        for module in ("presidio_analyzer", "presidio_anonymizer", "faker")
    )

    def test_missing_optional_dependencies_raise_clear_error(self):
        if self.has_pii_deps:
            pytest.skip("PII optional dependencies are installed")

        with pytest.raises(PiiScramblerUnavailable, match="Presidio|Faker"):
            scramble_pii("Contact jane.doe@example.org", use_nlp=False)

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_email_scrambled(self):
        text = "Contact jane.doe@sample.org for access"
        scrambled = scramble_pii(text, use_nlp=False)
        assert "jane.doe@sample.org" not in scrambled
        assert "@" in scrambled

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_email_scrambling_is_deterministic(self):
        text = "Email jane.doe@sample.org"
        assert scramble_pii(text, use_nlp=False) == scramble_pii(text, use_nlp=False)

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_ssn_scrambled_but_keeps_shape(self):
        scrambled = scramble_pii("ssn: 856-45-6789", use_nlp=False)
        assert "856-45-6789" not in scrambled

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_phone_scrambled(self):
        scrambled = scramble_pii("Call 415-867-5309", use_nlp=False)
        assert "415-867-5309" not in scrambled

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_labeled_postal_code_scrambled_without_touching_plain_ids(self):
        scrambled = scramble_pii("zip: 90210; order id 12345", use_nlp=False)
        assert "90210" not in scrambled
        assert "12345" in scrambled

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_deep_scramble_uses_structured_keys_as_context(self):
        value = {"postal_code": "90210", "id": "12345"}
        scrambled = scramble_pii_value(value, use_nlp=False)
        assert scrambled["postal_code"] != "90210"
        assert scrambled["id"] == "12345"

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_serialized_database_rows_use_column_name_context(self):
        text = "[{'column_name': 'email', 'value': 'jane@example.com'}]"
        scrambled = scramble_pii(text, use_nlp=False)
        assert "jane@example.com" not in scrambled
        assert "column_name" in scrambled
        assert "email" in scrambled

    @pytest.mark.skipif(not has_pii_deps, reason="PII optional dependencies not installed")
    def test_serialized_database_rows_scramble_direct_keyed_values(self):
        text = "[{'email': 'jane@example.com', 'zipcode': '90210'}]"
        scrambled = scramble_pii(text, use_nlp=False)
        assert "jane@example.com" not in scrambled
        assert "90210" not in scrambled
        assert "zipcode" in scrambled

    def test_structured_database_rows_leave_names_and_ids_alone(self, monkeypatch):
        monkeypatch.setattr(pii_module, "_fake_value", lambda entity, value: f"[{entity}]")
        text = (
            "[{'id': 1, 'user_id': 2, 'first_name': 'Jane', "
            "'last_name': 'Smith', 'name': 'users', "
            "'encrypted_pin': 'pin-secret-abc', "
            "'encrypted_otp_secret': 'otp-secret-encrypted'}]"
        )

        scrambled = pii_module._scramble_structured_text(text)

        assert "'id': 1" in scrambled
        assert "'user_id': 2" in scrambled
        assert "'first_name': 'Jane'" in scrambled
        assert "'last_name': 'Smith'" in scrambled
        assert "'name': 'users'" in scrambled
        assert "'encrypted_pin': 'pin-secret-abc'" in scrambled
        assert "'encrypted_otp_secret': 'otp-secret-encrypted'" in scrambled

    def test_structured_database_rows_scramble_user_profile_contact_fields(self, monkeypatch):
        monkeypatch.setattr(pii_module, "_fake_value", lambda entity, value: f"[{entity}]")
        text = (
            "[{'email': 'jane@example.com', 'parent_email_address': 'parent@example.com', "
            "'phone_number': '415-867-5309', 'zipcode': '90210', "
            "'library_card_number': 'LC-12345', 'cultural_pass_number': 'CP-98765', "
            "'birthdate': '2012-03-04', 'current_sign_in_ip': '198.51.100.10', "
            "'login': 'jane-reader', 'username': 'jreader', "
            "'school_student_id': 12345, 'safe_code': 'BOOK-ALPHA'}]"
        )

        scrambled = pii_module._scramble_structured_text(text)

        for value in (
            "jane@example.com",
            "parent@example.com",
            "415-867-5309",
            "90210",
            "LC-12345",
            "CP-98765",
            "2012-03-04",
            "198.51.100.10",
            "jane-reader",
            "jreader",
        ):
            assert value not in scrambled

        assert "'school_student_id': 12345" in scrambled
        assert "BOOK-ALPHA" in scrambled

    def test_sql_input_scrambling_preserves_join_ids(self, monkeypatch):
        monkeypatch.setattr(pii_module, "_fake_value", lambda entity, value: f"[{entity}]")
        sql = (
            "SELECT users.*, profiles.* FROM users "
            "JOIN profiles ON profiles.user_id = users.id "
            "WHERE users.id = '12' "
            "AND profiles.user_id = '12' "
            "AND users.email = 'jane@example.com' "
            "AND profiles.zipcode = '90210' "
            "AND profiles.address = '123 Main St' "
            "AND users.login = 'jane-reader' "
            "AND users.username = 'jreader'"
        )

        scrambled = pii_module._scramble_structured_text(sql)

        assert "users.id = '12'" in scrambled
        assert "profiles.user_id = '12'" in scrambled
        for value in (
            "jane@example.com",
            "90210",
            "123 Main St",
            "jane-reader",
            "jreader",
        ):
            assert value not in scrambled

# ───────────────────────────────────────────────
# Path Traversal Prevention
# ───────────────────────────────────────────────

class TestPathValidation:
    def test_valid_path_within_root(self, tmp_path):
        test_file = tmp_path / "src" / "main.py"
        test_file.parent.mkdir(parents=True)
        test_file.touch()
        result = validate_path(str(test_file), [str(tmp_path)])
        assert result == test_file.resolve()

    def test_traversal_blocked(self, tmp_path):
        with pytest.raises(PathViolation):
            validate_path(
                str(tmp_path / ".." / ".." / "etc" / "passwd"),
                [str(tmp_path)],
            )

    def test_null_byte_blocked(self, tmp_path):
        with pytest.raises(PathViolation, match="Null byte"):
            validate_path(
                str(tmp_path / "file\x00.txt"),
                [str(tmp_path)],
            )

    def test_absolute_path_outside_root(self, tmp_path):
        with pytest.raises(PathViolation):
            validate_path("/etc/shadow", [str(tmp_path)])

    def test_is_path_safe_convenience(self, tmp_path):
        test_file = tmp_path / "ok.txt"
        test_file.touch()
        assert is_path_safe(str(test_file), [str(tmp_path)])
        assert not is_path_safe("/etc/shadow", [str(tmp_path)])


# ───────────────────────────────────────────────
# JSON-RPC Validation
# ───────────────────────────────────────────────

class TestMessageValidation:
    def test_valid_request(self):
        validate_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })  # should not raise

    def test_missing_jsonrpc(self):
        with pytest.raises(ValidationError, match="jsonrpc"):
            validate_message({"id": 1, "method": "test"})

    def test_invalid_method_name(self):
        with pytest.raises(ValidationError, match="Invalid method"):
            validate_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "rm -rf /",
            })

    def test_tool_name_injection(self):
        with pytest.raises(ValidationError, match="Invalid tool name"):
            validate_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool; rm -rf /"},
            })

    def test_tool_name_too_long(self):
        with pytest.raises(ValidationError, match="too long"):
            validate_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "a" * 200},
            })

    def test_too_many_arguments(self):
        with pytest.raises(ValidationError, match="Too many"):
            validate_message({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "test_tool",
                    "arguments": {f"arg{i}": i for i in range(150)},
                },
            })

    def test_non_dict_rejected(self):
        with pytest.raises(ValidationError, match="JSON object"):
            validate_message("not a dict")


# ───────────────────────────────────────────────
# Command Injection Guard
# ───────────────────────────────────────────────

class TestCommandValidation:
    def test_allowed_command(self):
        validate_server_command("python", ["-m", "my_server"])

    def test_npx_allowed(self):
        validate_server_command("npx", ["-y", "@mcp/server-fs", "/home"])

    def test_arbitrary_command_blocked(self):
        with pytest.raises(ValidationError, match="not in allowed"):
            validate_server_command("bash", ["-c", "echo hacked"])

    def test_path_traversal_in_command(self):
        with pytest.raises(ValidationError, match="not in allowed"):
            validate_server_command("../../bin/bash", ["-c", "whoami"])

    def test_shell_metachar_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("python", ["-m", "server; rm -rf /"])

    def test_pipe_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("node", ["server.js", "| cat /etc/passwd"])

    def test_backtick_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("python", ["`whoami`"])

    # ── Windows path edge cases ──
    # These must all PASS (not raise) because create_subprocess_exec
    # handles them safely without shell interpretation.

    def test_spaces_in_path(self):
        validate_server_command("npx", ["-y", "@mcp/server-fs", "C:\\Users\\John Doe\\project"])

    def test_parentheses_in_path(self):
        validate_server_command("npx", ["-y", "@mcp/server-fs", "C:\\Program Files (x86)\\app"])

    def test_spaces_and_parentheses_combined(self):
        validate_server_command("npx", ["-y", "@mcp/server-fs", "C:\\Users\\John Doe\\My Project (v2)"])

    def test_windows_exe_with_spaces(self):
        validate_server_command("C:\\Program Files\\Python314\\python.exe", ["-m", "server"])

    def test_npx_cmd_with_spaces(self):
        validate_server_command("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "@mcp/server"])

    def test_unicode_in_path(self):
        validate_server_command("python", ["-m", "server", "C:\\Users\\Ren\u00e9\\docs"])

    def test_long_windows_path(self):
        validate_server_command("python", ["-m", "server", "C:\\Users\\User\\Desktop\\My Projects\\MCP (The Spine)\\data\\subfolder"])

    # These must still be BLOCKED

    def test_dollar_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("python", ["--flag=$(whoami)"])

    def test_semicolon_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("python", ["server; rm -rf /"])

    def test_ampersand_in_args(self):
        with pytest.raises(ValidationError, match="Dangerous"):
            validate_server_command("python", ["server & echo pwned"])


# ───────────────────────────────────────────────
# Rate Limiting
# ───────────────────────────────────────────────

class TestRateLimiting:
    def test_bucket_allows_within_limit(self):
        bucket = RateLimitBucket(max_calls=3, window_seconds=60.0)
        assert bucket.allow()
        assert bucket.allow()
        assert bucket.allow()
        assert not bucket.allow()  # 4th call blocked

    def test_bucket_remaining(self):
        bucket = RateLimitBucket(max_calls=5, window_seconds=60.0)
        assert bucket.remaining == 5
        bucket.allow()
        bucket.allow()
        assert bucket.remaining == 3

    def test_limiter_per_tool(self):
        limiter = RateLimiter(default_max_calls=2, default_window=60.0)
        assert limiter.check("tool_a")
        assert limiter.check("tool_a")
        assert not limiter.check("tool_a")
        # Different tool should have its own bucket
        assert limiter.check("tool_b")

    def test_limiter_overrides(self):
        limiter = RateLimiter(
            default_max_calls=10,
            default_window=60.0,
            overrides={"dangerous_tool": (1, 60.0)},
        )
        assert limiter.check("dangerous_tool")
        assert not limiter.check("dangerous_tool")


# ───────────────────────────────────────────────
# Environment Variable Resolution
# ───────────────────────────────────────────────

class TestEnvResolution:
    def test_resolves_set_var(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "abc123")
        assert resolve_env_vars("${MY_TOKEN}") == "abc123"

    def test_fails_on_unset_var(self):
        with pytest.raises(ValueError, match="not set"):
            resolve_env_vars("${DEFINITELY_NOT_SET_12345}")

    def test_mixed_text_and_vars(self, monkeypatch):
        monkeypatch.setenv("HOST", "localhost")
        result = resolve_env_vars("http://${HOST}:8080")
        assert result == "http://localhost:8080"


# ───────────────────────────────────────────────
# Security Policy
# ───────────────────────────────────────────────

class TestSecurityPolicy:
    def test_tool_policy_glob_matching(self):
        policy = ToolPolicy(name_pattern="file_*", action=PolicyAction.DENY)
        assert policy.matches("file_read")
        assert policy.matches("file_write")
        assert not policy.matches("github_create_pr")

    def test_policy_denies_tool(self):
        sp = SecurityPolicy(
            tool_policies=[
                ToolPolicy(name_pattern="execute_*", action=PolicyAction.DENY),
            ]
        )
        assert not sp.is_tool_allowed("execute_command")
        assert sp.is_tool_allowed("read_file")

    def test_path_policy_denies_env_files(self):
        pp = PathPolicy()
        assert not pp.is_path_allowed("**/.env")
        assert not pp.is_path_allowed("**/*.key")

    def test_load_from_config(self):
        config = {
            "security": {
                "scrub_secrets_in_logs": True,
                "global_rate_limit": 100,
                "tools": [
                    {"pattern": "shell_*", "action": "deny"},
                    {"pattern": "file_write", "action": "audit", "rate_limit": 5},
                ],
            }
        }
        policy = load_security_policy(config)
        assert not policy.is_tool_allowed("shell_exec")
        assert policy.is_tool_allowed("file_write")
        assert policy.should_audit_tool("file_write")
        assert policy.global_rate_limit == 100


# ───────────────────────────────────────────────
# Hashing & Integrity
# ───────────────────────────────────────────────

class TestIntegrity:
    def test_content_hash_deterministic(self):
        h1 = hash_content(b"hello world")
        h2 = hash_content(b"hello world")
        assert h1 == h2

    def test_content_hash_differs(self):
        h1 = hash_content(b"version 1")
        h2 = hash_content(b"version 2")
        assert h1 != h2

    def test_schema_hash_key_order_independent(self):
        s1 = {"name": "tool", "type": "object"}
        s2 = {"type": "object", "name": "tool"}
        assert hash_tool_schema(s1) == hash_tool_schema(s2)

    def test_audit_fingerprint_deterministic(self):
        fp1 = audit_fingerprint("tool_call", "read_file", 1000.0, "abc123")
        fp2 = audit_fingerprint("tool_call", "read_file", 1000.0, "abc123")
        assert fp1 == fp2

    def test_audit_fingerprint_changes_with_input(self):
        fp1 = audit_fingerprint("tool_call", "read_file", 1000.0, "abc123")
        fp2 = audit_fingerprint("tool_call", "write_file", 1000.0, "abc123")
        assert fp1 != fp2
