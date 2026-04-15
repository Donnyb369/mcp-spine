# MCP Spine

[![mcp-spine MCP server](https://glama.ai/mcp/servers/Donnyb369/mcp-spine/badges/card.svg)](https://glama.ai/mcp/servers/Donnyb369/mcp-spine)

**Context Minifier & State Guard** — A local-first MCP middleware proxy that reduces token waste, prevents tool attrition, and eliminates context rot.

MCP Spine sits between your LLM client (Claude Desktop, etc.) and your MCP servers, providing security hardening, intelligent tool routing, schema compression, and file state tracking — all through a single proxy.

## Why

LLM agents using MCP tools face three problems:

1. **Token waste** — Tool schemas consume thousands of tokens per request. With 40+ tools loaded, you're burning context on JSON schemas before the conversation even starts.
2. **Context rot** — In long sessions, LLMs revert to editing old file versions they memorized earlier, silently overwriting your latest changes.
3. **No security boundary** — MCP servers run with full access. There's no audit trail, no rate limiting, no secret scrubbing between the LLM and your tools.

MCP Spine solves all three.

## Install

```bash
pip install mcp-spine

# With semantic routing (optional)
pip install mcp-spine[ml]
```

## Quick Start

```bash
# Generate config
mcp-spine init

# Diagnose your setup
mcp-spine doctor --config spine.toml

# Validate config
mcp-spine verify --config spine.toml

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
      "args": ["-u", "-m", "spine.cli", "serve", "--config", "/path/to/spine.toml"],
      "cwd": "/path/to/mcp-spine"
    }
  }
}
```

The `-u` flag ensures unbuffered stdout, preventing pipe hangs on Windows.

## Features

### Stage 1: Security Proxy
- JSON-RPC message validation and sanitization
- Secret scrubbing (AWS keys, GitHub tokens, bearer tokens, private keys, connection strings)
- Per-tool and global rate limiting with sliding windows
- Path traversal prevention with symlink-aware jail
- Command injection guards for server spawning
- HMAC-fingerprinted SQLite audit trail
- Circuit breakers on failing servers
- Declarative security policies from config

### Stage 2: Semantic Router
- Local vector embeddings using `all-MiniLM-L6-v2` (no API calls, no data leaves your machine)
- ChromaDB-backed tool indexing
- Query-time routing: only the most relevant tools are sent to the LLM
- `spine_set_context` meta-tool for explicit context switching
- Keyword overlap + recency boost reranking
- Background model loading — tools work immediately, routing activates when ready

### Stage 3: Schema Minification
- 4 aggression levels (0=off, 1=light, 2=standard, 3=aggressive)
- Level 2 achieves **61% token savings** on tool schemas
- Strips `$schema`, titles, `additionalProperties`, parameter descriptions, defaults
- Preserves all required fields and type information

### Stage 4: State Guard
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

### SSE Transport
- Connect to remote MCP servers over HTTP/SSE alongside local stdio servers
- No external dependencies (uses stdlib urllib)
- Supports custom headers for authentication

### Diagnostics

```bash
# Check your setup
mcp-spine doctor --config spine.toml

# Live monitoring dashboard
mcp-spine dashboard

# Usage analytics
mcp-spine analytics --hours 24

# Query audit log
mcp-spine audit --last 50
mcp-spine audit --security-only
mcp-spine audit --tool write_file
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

# Remote server via SSE
# [[servers]]
# name = "remote-tools"
# transport = "sse"
# url = "https://your-server.com/sse"
# headers = { Authorization = "Bearer token" }
# timeout_seconds = 30

# Semantic routing
[routing]
max_tools = 15
rerank = true

# Schema minification — 61% token savings at level 2
[minifier]
level = 2

# State guard — prevent context rot
[state_guard]
enabled = true
watch_paths = ["/path/to/project"]

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

## Architecture

```
Client ◄──stdio──► MCP Spine ◄──stdio──► Filesystem Server
                       │      ◄──stdio──► GitHub Server
                       │      ◄──stdio──► SQLite Server
                       │      ◄──stdio──► Memory Server
                       │      ◄──stdio──► Brave Search
                       │      ◄──SSE────► Remote Server
                   ┌───┴───┐
                   │SecPol │  ← Rate limits, path jail, secret scrub
                   │Router │  ← Semantic routing (local embeddings)
                   │Minify │  ← Schema compression (61% savings)
                   │Guard  │  ← File state pinning (SHA-256)
                   │HITL   │  ← Human-in-the-loop confirmation
                   │Memory │  ← Tool output cache
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
│   ├── audit.py            # Structured logging + SQLite audit trail
│   ├── router.py           # Semantic routing (ChromaDB + sentence-transformers)
│   ├── minifier.py         # Schema pruning (4 aggression levels)
│   ├── state_guard.py      # File watcher + SHA-256 manifest + pin injection
│   ├── memory.py           # Tool output cache (ring buffer + dedup + TTL)
│   ├── dashboard.py        # Live TUI dashboard (Rich)
│   ├── sse_client.py       # SSE transport client for remote servers
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
│   └── test_memory.py      # Tool output memory tests
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

135+ tests covering security, config validation, schema minification, state guard, HITL policies, dashboard queries, analytics, tool memory, and Windows path edge cases.

CI runs on every push: Windows + Linux, Python 3.11/3.12/3.13.

## License

MIT
