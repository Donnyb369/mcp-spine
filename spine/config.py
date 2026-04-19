"""
MCP Spine — Configuration

Loads and validates spine.toml configuration.
All config values are validated before use; no raw user input reaches
downstream servers or the filesystem without checks.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from spine.security import safe_env_dict, validate_server_command
from spine.security.policy import SecurityPolicy, load_security_policy

if sys.version_info >= (3, 12):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class ServerConfig:
    """Configuration for a single downstream MCP server."""
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    max_retries: int = 2
    circuit_breaker_threshold: int = 3
    enabled: bool = True
    transport: str = "stdio"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    scramble_pii_in_responses: bool = False
    scramble_pii_use_nlp: bool = True

    def validate(self, allowed_commands: frozenset[str]) -> list[str]:
        warnings = []
        if self.transport == "sse":
            if not self.url:
                raise ValueError(f"Server '{self.name}': SSE transport requires 'url'")
            if not self.url.startswith(("http://", "https://")):
                raise ValueError(f"Server '{self.name}': SSE url must start with http:// or https://")
        else:
            if not self.command:
                raise ValueError(f"Server '{self.name}': stdio transport requires 'command'")
            try:
                validate_server_command(self.command, self.args, allowed_commands)
            except Exception as e:
                raise ValueError(f"Server '{self.name}': {e}") from e
        if self.timeout_seconds <= 0:
            raise ValueError(f"Server '{self.name}': timeout must be positive")
        if self.timeout_seconds > 300:
            warnings.append(f"Server '{self.name}': timeout {self.timeout_seconds}s is very long")
        return warnings


@dataclass
class RoutingConfig:
    max_tools: int = 5
    always_include: list[str] = field(default_factory=lambda: ["spine_set_context"])
    embedding_model: str = "all-MiniLM-L6-v2"
    rerank: bool = True
    similarity_threshold: float = 0.3


@dataclass
class StateGuardConfig:
    enabled: bool = True
    watch_paths: list[str] = field(default_factory=lambda: ["."])
    ignore_patterns: list[str] = field(default_factory=lambda: [
        "**/.git/**",
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/.venv/**",
        "**/venv/**",
        "**/*.pyc",
        "**/.DS_Store",
    ])
    max_tracked_files: int = 200
    max_pin_files: int = 20
    snippet_length: int = 200


@dataclass
class MinifierConfig:
    level: int = 2
    max_description_length: int = 120
    preserve_required: bool = True


@dataclass
class TokenBudgetConfig:
    """Daily token budget settings."""
    daily_limit: int = 0
    warn_at: float = 0.8
    action: str = "warn"


@dataclass
class SpineConfig:
    log_level: str = "info"
    log_file: str | None = None
    audit_db: str = "spine_audit.db"

    servers: list[ServerConfig] = field(default_factory=list)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    state_guard: StateGuardConfig = field(default_factory=StateGuardConfig)
    minifier: MinifierConfig = field(default_factory=MinifierConfig)
    token_budget: TokenBudgetConfig = field(default_factory=TokenBudgetConfig)
    security: SecurityPolicy = field(default_factory=SecurityPolicy)

    def validate(self) -> list[str]:
        warnings = []
        if not self.servers:
            warnings.append("No downstream servers configured")
        seen_names = set()
        for server in self.servers:
            if server.name in seen_names:
                raise ValueError(f"Duplicate server name: {server.name!r}")
            seen_names.add(server.name)
            warnings.extend(server.validate(self.security.allowed_commands))
        if self.routing.max_tools < 1:
            raise ValueError("routing.max_tools must be >= 1")
        if self.routing.max_tools > 50:
            warnings.append(f"routing.max_tools={self.routing.max_tools} is very high")
        if self.minifier.level not in range(4):
            raise ValueError("minifier.level must be 0-3")
        if self.token_budget.daily_limit < 0:
            raise ValueError("token_budget.daily_limit must be >= 0")
        if not 0.0 <= self.token_budget.warn_at <= 1.0:
            raise ValueError("token_budget.warn_at must be between 0.0 and 1.0")
        if self.token_budget.action not in ("warn", "block"):
            raise ValueError("token_budget.action must be 'warn' or 'block'")
        return warnings


def load_config(path: str | Path) -> SpineConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "rb") as f:
        raw = tomllib.load(f)
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> SpineConfig:
    spine_section = raw.get("spine", {})
    security = load_security_policy(raw)

    servers = []
    for srv in raw.get("servers", []):
        env = {}
        if "env" in srv:
            env = safe_env_dict(srv["env"])
        servers.append(ServerConfig(
            name=srv["name"],
            command=srv.get("command", ""),
            args=srv.get("args", []),
            env=env,
            timeout_seconds=srv.get("timeout_seconds", 30.0),
            max_retries=srv.get("max_retries", 2),
            circuit_breaker_threshold=srv.get("circuit_breaker_threshold", 3),
            enabled=srv.get("enabled", True),
            transport=srv.get("transport", "stdio"),
            url=srv.get("url", ""),
            headers=srv.get("headers", {}),
            scramble_pii_in_responses=srv.get("scramble_pii_in_responses", False),
            scramble_pii_use_nlp=srv.get("scramble_pii_use_nlp", True),
        ))

    routing_raw = raw.get("routing", {})
    routing = RoutingConfig(
        max_tools=routing_raw.get("max_tools", 5),
        always_include=routing_raw.get("always_include", ["spine_set_context"]),
        embedding_model=routing_raw.get("embedding_model", "all-MiniLM-L6-v2"),
        rerank=routing_raw.get("rerank", True),
        similarity_threshold=routing_raw.get("similarity_threshold", 0.3),
    )

    sg_raw = raw.get("state_guard", {})
    state_guard = StateGuardConfig(
        enabled=sg_raw.get("enabled", True),
        watch_paths=sg_raw.get("watch_paths", ["."]),
        ignore_patterns=sg_raw.get("ignore_patterns", StateGuardConfig().ignore_patterns),
        max_tracked_files=sg_raw.get("max_tracked_files", 200),
        max_pin_files=sg_raw.get("max_pin_files", 20),
        snippet_length=sg_raw.get("snippet_length", 200),
    )

    min_raw = raw.get("minifier", {})
    minifier = MinifierConfig(
        level=min_raw.get("level", 2),
        max_description_length=min_raw.get("max_description_length", 120),
        preserve_required=min_raw.get("preserve_required", True),
    )

    tb_raw = raw.get("token_budget", {})
    token_budget = TokenBudgetConfig(
        daily_limit=tb_raw.get("daily_limit", 0),
        warn_at=tb_raw.get("warn_at", 0.8),
        action=tb_raw.get("action", "warn"),
    )

    config = SpineConfig(
        log_level=spine_section.get("log_level", "info"),
        log_file=spine_section.get("log_file"),
        audit_db=spine_section.get("audit_db", "spine_audit.db"),
        servers=servers,
        routing=routing,
        state_guard=state_guard,
        minifier=minifier,
        token_budget=token_budget,
        security=security,
    )
    config.validate()
    return config
