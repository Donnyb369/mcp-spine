"""
MCP Spine — Security Package

Defense-in-depth for a local MCP proxy. Each concern lives
in its own submodule; this file re-exports the public API
so existing imports continue to work unchanged.

Submodules:
  secrets     — credential detection & scrubbing
  paths       — path traversal jail
  validation  — JSON-RPC message checks
  commands    — server spawn guards
  rate_limit  — per-tool sliding window
  integrity   — SHA-256 hashing & HMAC fingerprints
  env         — environment variable resolution
  policy      — declarative security policies
"""

from spine.security.commands import (
    validate_server_command,
)
from spine.security.env import (
    resolve_env_vars,
    safe_env_dict,
)
from spine.security.integrity import (
    audit_fingerprint,
    hash_content,
    hash_tool_schema,
)
from spine.security.paths import (
    PathViolation,
    is_path_safe,
    validate_path,
)
from spine.security.pii import (
    contains_pii,
    scramble_pii,
    scramble_pii_value,
)
from spine.security.rate_limit import (
    RateLimitBucket,
    RateLimiter,
)
from spine.security.secrets import (
    REDACTED,
    contains_secret,
    scrub_secrets,
)
from spine.security.validation import (
    MAX_ARGUMENT_KEYS,
    MAX_MESSAGE_SIZE,
    MAX_SCHEMA_DEPTH,
    MAX_TOOL_NAME_LENGTH,
    ValidationError,
    validate_message,
    validate_message_size,
)

__all__ = [
    # secrets
    "REDACTED", "contains_secret", "scrub_secrets",
    # pii
    "contains_pii", "scramble_pii", "scramble_pii_value",
    # paths
    "PathViolation", "is_path_safe", "validate_path",
    # validation
    "ValidationError", "validate_message", "validate_message_size",
    "MAX_MESSAGE_SIZE", "MAX_SCHEMA_DEPTH", "MAX_TOOL_NAME_LENGTH",
    "MAX_ARGUMENT_KEYS",
    # commands
    "validate_server_command",
    # rate_limit
    "RateLimitBucket", "RateLimiter",
    # integrity
    "audit_fingerprint", "hash_content", "hash_tool_schema",
    # env
    "resolve_env_vars", "safe_env_dict",
]
