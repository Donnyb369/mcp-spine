# MCP Spine

[![mcp-spine MCP server](https://glama.ai/mcp/servers/Donnyb369/mcp-spine/badges/score.svg)](https://glama.ai/mcp/servers/Donnyb369/mcp-spine)

**The middleware layer MCP is missing.** Security, routing, token control, and compliance — between your LLM and your tools.

MCP Spine is a local-first proxy that sits between Claude Desktop (or any MCP client) and your MCP servers. One config, one entry point, full control over what goes in, what comes out, and what gets logged.

57 tools across 5 servers. One proxy. Zero tokens wasted.

## The Problem

You've connected Claude to GitHub, Slack, your database, your filesystem. Now you have 40+ tools loaded, thousands of tokens burned on schemas every turn, no audit trail, no rate limits, and no way to stop the LLM from reading your boss's DMs. MCP gives agents power. Spine gives you control.

## What It Does

| Layer | What it solves |
|---|---|
| **Security Proxy** | Rate limiting, secret scrubbing, path jails, HMAC audit trail |
| **Semantic Router** | Only relevant tools reach the LLM — local embeddings, no API calls |
| **Schema Minifier** | 61% token savings by stripping unnecessary schema fields |
| **State Guard** | SHA-256 file pins prevent the LLM from editing stale versions |
| **Token Budget** | Daily limits with warn/block enforcement and persistent tracking |
| **Plugin System** | Custom middleware hooks — filter, transform, block per tool |
| **HITL Confirmation** | Destructive tools pause for human approval before executing |
| **Multi-User Audit** | Session-tagged audit trail for shared deployments |

## Demo

![MCP Spine Doctor](docs/demo.gif)

*Runs on Windows, macOS, and Linux. CI tested across all three.*

## Install

```bash
pip install mcp-spine

# With semantic routing (optional)
pip install mcp-spine[ml]
```

## Quick Start

```bash
# Interactive setup wizard — detects your servers, asks about features
mcp-spine init

# Or quick default config
mcp-spine init --quick

# Check everything works
mcp-spine doctor --config spine.toml

# Start the proxy
mcp-spine serve --config spine.toml
```

## Claude Desktop Integration

Replace all your individual MCP server entries with a single Spine entry:

```json
{
  "mcpServers": {
    "spine": {
      "command": "python",
      "args": ["-m", "spine.cli", "serve", "--config", "/path/to/spine.toml"],
      "cwd": "/path/to/mcp-spine"
    }
  }
}
```

## Features

### Security Proxy (Stage 1)
- JSON-RPC message validation and sanitization
- Secret scrubbing (AWS keys, GitHub tokens, bearer tokens, private keys, connection strings)
- Per-tool and global rate limiting with sliding windows
- Path traversal prevention with symlink-aware jail
- Command injection guards for server spawning
- HMAC-fingerprinted SQLite audit trail
- Circuit breakers on failing servers
- Declarative security policies from config

### Semantic Router (Stage 2)
- Local vector embeddings using `all-MiniLM-L6-v2` (no API calls, no data leaves your machine)
- ChromaDB-backed tool indexing
- Query-time routing: only the most relevant tools are sent to the LLM
- `spine_set_context` meta-tool for explicit context switching
- Keyword overlap + recency boost reranking
- Background model loading — tools work immediately, routing activates when ready

### Schema Minification (Stage 3)
- 4 aggression levels (0=off, 1=light, 2=standard, 3=aggressive)
- Level 2 achieves **61% token savings** on tool schemas
- Strips `$schema`, titles, `additionalProperties`, parameter descriptions, defaults
- Preserves all required fields and type information

### State Guard (Stage 4)
- Watches project files via `watchfiles`
- Maintains SHA-256 manifest with monotonic versioning
- Injects compact state pins into tool responses
- Prevents LLMs from editing stale file versions

### Human-in-the-Loop
- `require_confirmation` policy flag for destructive tools
- Spine intercepts the call, shows the arguments, and waits for user approval
- `spine_confirm` / `spine_deny` meta-tools for the LLM to relay the decision
- Per-tool granularity via glob patterns

### Tool Output Memory
- Ring buffer caching last 50 tool results
- Deduplication by tool name + argument hash
- TTL expiration (1 hour default)
- `spine_recall` meta-tool to query cached results
- Prevents context loss when semantic router swaps tools between turns

### Token Budget
- Daily token consumption tracking across all tool calls
- Configurable daily limit with warn/block actions
- Persistent SQLite storage (survives restarts within the same day)
- Automatic midnight rollover
- `spine_budget` meta-tool to check usage mid-conversation
- Token estimation via character-count heuristic (~4 chars/token)

### Plugin System
- Drop-in Python plugins that hook into the tool call pipeline
- Four hook points: `on_tool_call`, `on_tool_response`, `on_tool_list`, `on_startup`/`on_shutdown`
- Plugins can transform arguments, filter responses, block calls, or hide tools
- Plugin chaining — multiple plugins run in sequence
- Allow/deny lists for plugin access control
- Auto-discovery from a configurable plugins directory
- Example included: Slack channel compliance filter

### Config Hot-Reload
- Edit `spine.toml` while Spine is running — changes apply in seconds
- Hot-reloadable: minifier level, rate limits, security policies, token budget, state guard patterns
- Non-reloadable (requires restart): server list, commands, audit DB path
- All reloads logged to the audit trail

### Multi-User Audit
- Unique session ID generated per client connection
- Client name and version extracted from MCP handshake
- All audit entries tagged with session ID
- `mcp-spine audit --sessions` lists all client sessions
- `mcp-spine audit --session <id>` filters entries by session
- Enables compliance and usage tracking for shared deployments

### Transport Support
- **stdio** — local subprocess servers (filesystem, GitHub, SQLite, etc.)
- **SSE** — legacy remote servers over HTTP/Server-Sent Events
- **Streamable HTTP** — MCP 2025-03-26 spec, single-endpoint bidirectional transport with session management
- All transports share the same security, routing, and audit pipeline

### Diagnostics

```bash
# Check your setup
mcp-spine doctor --config spine.toml

# Live monitoring dashboard
mcp-spine dashboard

# Usage analytics (includes token budget)
mcp-spine analytics --hours 24

# Query audit log
mcp-spine audit --last 50
mcp-spine audit --security-only
mcp-spine audit --tool write_file
mcp-spine audit --sessions
mcp-spine audit --session <session-id>
```

## Example Config

```toml
[spine]
log_level = "info"
audit_db = "spine_audit.db"

# Add as many servers as you need — they start concurrently
[[servers]]
name = "filesystem"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
timeout_seconds = 120

[[servers]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "ghp_..." }
timeout_seconds = 180

[[servers]]
name = "sqlite"
command = "uvx"
args = ["mcp-server-sqlite", "--db-path", "/path/to/database.db"]
timeout_seconds = 60

[[servers]]
name = "memory"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-memory"]
timeout_seconds = 60

[[servers]]
name = "brave-search"
command = "node"
args = ["/path/to/node_modules/@modelcontextprotocol/server-brave-search/dist/index.js"]
env = { BRAVE_API_KEY = "your_key" }
timeout_seconds = 60

# Remote server via legacy SSE
# [[servers]]
# name = "remote-sse"
# transport = "sse"
# url = "https://your-server.com/sse"
# headers = { Authorization = "Bearer token" }
# timeout_seconds = 30

# Remote server via Streamable HTTP (MCP 2025-03-26)
# [[servers]]
# name = "remote-api"
# transport = "streamable-http"
# url = "https://your-server.com/mcp"
# headers = { Authorization = "Bearer token" }
# timeout_seconds = 30

# Semantic routing
[routing]
max_tools = 15
rerank = true

# Schema minification — 61% token savings at level 2
[minifier]
level = 2

# Token budget — track and limit daily token spend
[token_budget]
daily_limit = 500000    # tokens per day (0 = unlimited)
warn_at = 0.8           # warn at 80% usage
action = "warn"         # "warn" = log warning, "block" = reject tool calls

# State guard — prevent context rot
[state_guard]
enabled = true
watch_paths = ["/path/to/project"]

# Plugins — custom middleware hooks
[plugins]
enabled = true
directory = "plugins"
# allow_list = ["slack-filter"]  # optional whitelist
# deny_list = ["debug-plugin"]  # optional blacklist

# Human-in-the-loop for destructive tools
[[security.tools]]
pattern = "write_file"
action = "allow"
require_confirmation = true

[[security.tools]]
pattern = "write_query"
action = "allow"
require_confirmation = true

# Security
[security]
scrub_secrets_in_logs = true
audit_all_tool_calls = true
global_rate_limit = 120
per_tool_rate_limit = 60

[security.path]
allowed_roots = ["/path/to/project"]
denied_patterns = ["**/.env", "**/*.key", "**/*.pem"]
```

## Security Model

Defense-in-depth — every layer assumes the others might fail.

| Threat | Mitigation |
|---|---|
| Prompt injection via tool args | Input validation, tool name allowlists |
| Path traversal | Symlink-aware jail to `allowed_roots` |
| Secret leakage | Automatic scrubbing of AWS keys, tokens, private keys |
| Runaway agent loops | Per-tool + global rate limiting |
| Command injection | Command allowlist, shell metacharacter blocking |
| Denial of service | Message size limits, circuit breakers |
| Sensitive file access | Deny-list patterns for `.env`, `.key`, `.pem`, `.ssh/` |
| Tool abuse | Policy-based blocking, audit logging, HITL confirmation |
| Log tampering | HMAC fingerprints on every audit entry |
| Destructive operations | `require_confirmation` pauses for user approval |
| Runaway token spend | Daily budget limits with warn/block enforcement |
| Unvetted plugins | Allow/deny lists, directory isolation, audit logging |
| Sensitive data exposure | Plugin-based response filtering (e.g., Slack channel compliance) |

## Architecture

```
Client ◄──stdio──► MCP Spine ◄──stdio────────► Filesystem Server
                       │      ◄──stdio────────► GitHub Server
                       │      ◄──stdio────────► SQLite Server
                       │      ◄──stdio────────► Memory Server
                       │      ◄──stdio────────► Brave Search
                       │      ◄──SSE──────────► Legacy Remote
                       │      ◄──Streamable HTTP──► Modern Remote
                   ┌───┴───┐
                   │SecPol │  ← Rate limits, path jail, secret scrub
                   │Router │  ← Semantic routing (local embeddings)
                   │Minify │  ← Schema compression (61% savings)
                   │Guard  │  ← File state pinning (SHA-256)
                   │HITL   │  ← Human-in-the-loop confirmation
                   │Memory │  ← Tool output cache
                   │Budget │  ← Daily token tracking + limits
                   │Plugin │  ← Custom middleware hooks
                   │Audit  │  ← Session-tagged multi-user trail
                   └───────┘
```

### Startup Sequence

1. **Instant handshake** (~2ms) — Responds to `initialize` immediately
2. **Concurrent server startup** — All servers connect in parallel via `asyncio.gather`
3. **Progressive readiness** — Tools available as soon as any server connects
4. **Late server notification** — `tools/listChanged` sent when slow servers finish
5. **Background ML loading** — Semantic router activates silently when model loads

## Windows Support

Battle-tested on Windows with specific hardening for:

- MSIX sandbox paths for Claude Desktop config and logs
- `npx.cmd` resolution via `shutil.which()`
- Paths with spaces (`C:\Users\John Doe\`) and parentheses (`C:\Program Files (x86)\`)
- `PureWindowsPath` for cross-platform basename extraction
- Environment variable merging (config env extends, not replaces, system env)
- UTF-8 encoding without BOM
- Unbuffered stdout (`-u` flag) to prevent pipe hangs

## Project Structure

```
mcp-spine/
├── pyproject.toml
├── spine/
│   ├── cli.py              # Click CLI (init, serve, verify, audit, dashboard, analytics, doctor)
│   ├── config.py           # TOML config loader with validation
│   ├── proxy.py            # Core proxy event loop
│   ├── protocol.py         # JSON-RPC message handling
│   ├── transport.py        # Server pool, circuit breakers, concurrent startup
│   ├── audit.py            # Structured logging + SQLite audit trail + sessions
│   ├── router.py           # Semantic routing (ChromaDB + sentence-transformers)
│   ├── minifier.py         # Schema pruning (4 aggression levels)
│   ├── state_guard.py      # File watcher + SHA-256 manifest + pin injection
│   ├── memory.py           # Tool output cache (ring buffer + dedup + TTL)
│   ├── budget.py           # Token budget tracker (daily limits + persistence)
│   ├── plugins.py          # Plugin system (hooks, discovery, chaining)
│   ├── dashboard.py        # Live TUI dashboard (Rich)
│   ├── sse_client.py       # SSE transport client (legacy)
│   ├── streamable_http.py  # Streamable HTTP transport (MCP 2025-03-26)
│   └── security/
│       ├── secrets.py      # Credential detection & scrubbing
│       ├── paths.py        # Path traversal jail
│       ├── validation.py   # JSON-RPC message validation
│       ├── commands.py     # Server spawn guards
│       ├── rate_limit.py   # Sliding window throttling
│       ├── integrity.py    # SHA-256 + HMAC fingerprints
│       ├── env.py          # Fail-closed env var resolution
│       └── policy.py       # Declarative security policies
├── tests/
│   ├── test_security.py    # Security tests
│   ├── test_config.py      # Config validation tests
│   ├── test_minifier.py    # Schema minification tests
│   ├── test_state_guard.py # State guard tests
│   ├── test_proxy_features.py  # HITL, dashboard, analytics tests
│   ├── test_memory.py      # Tool output memory tests
│   ├── test_budget.py      # Token budget tracker tests
│   └── test_plugins.py     # Plugin system tests
├── examples/
│   └── slack_filter.py     # Example: Slack compliance filter plugin
├── configs/
│   └── example.spine.toml  # Complete reference config
└── .github/
    └── workflows/
        └── ci.yml          # GitHub Actions: test + lint + publish
```

## Tests

```bash
pytest tests/ -v
```

190+ tests covering security, config validation, schema minification, state guard, HITL policies, dashboard queries, analytics, tool memory, token budget tracking, plugin system, and Windows path edge cases.

CI runs on every push: Windows + Linux, Python 3.11/3.12/3.13.

## License

MIT
