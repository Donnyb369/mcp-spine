"""
MCP Spine — CLI Entry Point

Commands:
  init     — Generate a starter spine.toml config
  serve    — Start the proxy (used in claude_desktop_config.json)
  status   — Show current server and tool status
  audit    — Query the audit log
  verify   — Validate a spine.toml config without starting
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

DEFAULT_CONFIG = """\
# MCP Spine Configuration
# See: https://github.com/your-org/mcp-spine

[spine]
log_level = "info"                  # debug | info | warn | error
audit_db = "spine_audit.db"         # SQLite audit trail location

# ── Downstream MCP Servers ──
# Add your MCP servers here. The Spine will proxy all of them
# through a single connection point.

# [[servers]]
# name = "filesystem"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
# timeout_seconds = 30

# [[servers]]
# name = "github"
# command = "npx"
# args = ["-y", "@modelcontextprotocol/server-github"]
# env = { GITHUB_TOKEN = "${GITHUB_TOKEN}" }

# ── Semantic Routing (Stage 2) ──
[routing]
max_tools = 5                        # Max tools shown to LLM per request
always_include = ["spine_set_context"] # Tools always visible to LLM
embedding_model = "all-MiniLM-L6-v2"  # Local embedding model
rerank = true
similarity_threshold = 0.3

# ── Schema Minification (Stage 3) ──
[minifier]
level = 2                            # 0=off, 1=light, 2=standard, 3=aggressive
max_description_length = 120

# ── State Guard (Stage 4) ──
[state_guard]
enabled = true
watch_paths = ["."]
max_tracked_files = 200
max_pin_files = 20
ignore_patterns = [
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/*.pyc",
]

# ── Security ──
[security]
scrub_secrets_in_logs = true         # Auto-redact secrets in audit logs
scrub_secrets_in_responses = false   # Opt-in: may break some tool outputs
audit_all_tool_calls = true          # Log every tool call
global_rate_limit = 60               # Max tool calls per minute (all tools)
per_tool_rate_limit = 30             # Max calls per minute per tool

[security.path]
allowed_roots = ["."]
denied_patterns = [
    "**/.env",
    "**/.env.*",
    "**/secrets.*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/.ssh/*",
    "**/.aws/*",
]

# Uncomment to block specific tools:
# [[security.tools]]
# pattern = "execute_command"
# action = "deny"

# Uncomment to audit-log specific tools:
# [[security.tools]]
# pattern = "file_write"
# action = "audit"
# rate_limit = 10
"""


@click.group()
@click.version_option(version="0.1.0", prog_name="mcp-spine")
def main():
    """MCP Spine — Context Minifier & State Guard"""
    pass


@main.command()
@click.option(
    "--path", "-p",
    default="spine.toml",
    help="Output path for the config file",
)
@click.option("--force", "-f", is_flag=True, help="Overwrite existing config")
def init(path: str, force: bool):
    """Generate a starter spine.toml configuration."""
    config_path = Path(path)
    if config_path.exists() and not force:
        console.print(
            f"[yellow]Config already exists at {config_path}. "
            f"Use --force to overwrite.[/yellow]"
        )
        sys.exit(1)

    config_path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    console.print(
        Panel(
            f"[green]Created {config_path}[/green]\n\n"
            f"Next steps:\n"
            f"  1. Edit {config_path} to add your MCP servers\n"
            f"  2. Run [bold]mcp-spine verify[/bold] to validate\n"
            f"  3. Update claude_desktop_config.json to use:\n"
            f'     [dim]{{"command": "mcp-spine", "args": ["serve"]}}[/dim]',
            title="MCP Spine Initialized",
            border_style="green",
        )
    )


@main.command()
@click.option(
    "--config", "-c",
    default="spine.toml",
    help="Path to spine.toml config",
)
def serve(config: str):
    """Start the Spine proxy (used in claude_desktop_config.json)."""
    from spine.config import load_config
    from spine.proxy import SpineProxy

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print(
            f"[red]Config not found: {config}[/red]\n"
            f"Run [bold]mcp-spine init[/bold] to create one.",
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Config error: {e}[/red]")
        sys.exit(1)

    proxy = SpineProxy(cfg)
    asyncio.run(proxy.start())


@main.command()
@click.option(
    "--config", "-c",
    default="spine.toml",
    help="Path to spine.toml config",
)
def verify(config: str):
    """Validate a spine.toml config without starting the proxy."""
    from spine.config import load_config

    try:
        cfg = load_config(config)
        warnings = cfg.validate()
    except FileNotFoundError:
        console.print(f"[red]Config not found: {config}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Validation FAILED: {e}[/red]")
        sys.exit(1)

    # Success
    table = Table(title="Configuration Summary")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Servers", str(len(cfg.servers)))
    for s in cfg.servers:
        table.add_row(f"  └─ {s.name}", f"{s.command} {' '.join(s.args[:2])}")
    table.add_row("Max tools exposed", str(cfg.routing.max_tools))
    table.add_row("Minification level", str(cfg.minifier.level))
    table.add_row("State Guard", "enabled" if cfg.state_guard.enabled else "disabled")
    table.add_row("Secret scrubbing", "on" if cfg.security.scrub_secrets_in_logs else "off")
    table.add_row("Rate limit (global)", f"{cfg.security.global_rate_limit}/min")
    table.add_row("Rate limit (per-tool)", f"{cfg.security.per_tool_rate_limit}/min")
    table.add_row("Audit logging", "on" if cfg.security.audit_all_tool_calls else "off")

    console.print(table)

    if warnings:
        for w in warnings:
            console.print(f"[yellow]⚠ {w}[/yellow]")

    console.print("[green]✓ Config is valid[/green]")


@main.command()
@click.option("--db", default="spine_audit.db", help="Audit database path")
@click.option("--event", "-e", default=None, help="Filter by event type")
@click.option("--tool", "-t", default=None, help="Filter by tool name")
@click.option("--last", "-n", default=20, help="Number of recent entries")
@click.option("--security-only", is_flag=True, help="Show only security events")
def audit(db: str, event: str | None, tool: str | None, last: int, security_only: bool):
    """Query the audit log."""
    import sqlite3

    db_path = Path(db)
    if not db_path.exists():
        console.print(f"[red]Audit database not found: {db}[/red]")
        sys.exit(1)

    conn = sqlite3.connect(db)
    query = "SELECT timestamp, event_type, tool_name, server_name, details, fingerprint FROM audit_log"
    conditions = []
    params = []

    if event:
        conditions.append("event_type = ?")
        params.append(event)
    if tool:
        conditions.append("tool_name = ?")
        params.append(tool)
    if security_only:
        conditions.append(
            "event_type IN ('rate_limited', 'path_violation', "
            "'secret_detected', 'validation_error', 'policy_deny')"
        )

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY timestamp DESC LIMIT {last}"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    if not rows:
        console.print("[dim]No audit entries found.[/dim]")
        return

    table = Table(title=f"Audit Log (last {last})")
    table.add_column("Time", style="dim", width=10)
    table.add_column("Event", style="cyan")
    table.add_column("Tool", style="green")
    table.add_column("Server", style="blue")
    table.add_column("Fingerprint", style="dim", width=12)

    import datetime

    for ts, evt, tname, sname, details, fp in reversed(rows):
        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        style = "red bold" if evt in (
            "rate_limited", "path_violation", "secret_detected",
            "policy_deny", "validation_error"
        ) else ""
        table.add_row(
            time_str,
            f"[{style}]{evt}[/{style}]" if style else evt,
            tname or "",
            sname or "",
            fp or "",
        )

    console.print(table)


@main.command()
@click.option(
    "--db", default="spine_audit.db",
    help="Path to the audit database",
)
@click.option(
    "--refresh", default=1.0, type=float,
    help="Refresh rate in seconds",
)
def dashboard(db: str, refresh: float) -> None:
    """Launch the live TUI dashboard."""
    from spine.dashboard import SpineDashboard

    dash = SpineDashboard(db_path=db, refresh_rate=refresh)
    dash.run()


@main.command()
@click.option("--db", default="spine_audit.db", help="Audit database path")
@click.option("--hours", "-h", default=24, type=int, help="Analyze last N hours")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def analytics(db: str, hours: int, json_output: bool) -> None:
    """Show tool usage analytics and performance metrics."""
    import sqlite3
    import datetime as dt

    db_path = Path(db)
    if not db_path.exists():
        console.print(f"[red]Audit database not found: {db}[/red]")
        sys.exit(1)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    cutoff = time.time() - (hours * 3600)

    def query(sql, params=()):
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        except sqlite3.Error:
            return []

    # ── Tool usage ranking ──
    tool_usage = query("""
        SELECT tool_name, COUNT(*) as calls,
               ROUND(AVG(CAST(json_extract(details, '$.duration_ms') AS REAL)), 1) as avg_ms,
               ROUND(MIN(CAST(json_extract(details, '$.duration_ms') AS REAL)), 1) as min_ms,
               ROUND(MAX(CAST(json_extract(details, '$.duration_ms') AS REAL)), 1) as max_ms
        FROM audit_log
        WHERE event_type = 'tool_call'
          AND tool_name IS NOT NULL
          AND timestamp > ?
        GROUP BY tool_name
        ORDER BY calls DESC
    """, (cutoff,))

    # ── Total stats ──
    totals = query("""
        SELECT COUNT(*) as total_calls,
               ROUND(AVG(CAST(json_extract(details, '$.duration_ms') AS REAL)), 1) as avg_ms
        FROM audit_log
        WHERE event_type = 'tool_call' AND timestamp > ?
    """, (cutoff,))
    total = totals[0] if totals else {"total_calls": 0, "avg_ms": 0}

    # ── Security event breakdown ──
    sec_events = query("""
        SELECT event_type, COUNT(*) as cnt
        FROM audit_log
        WHERE event_type IN (
            'rate_limited', 'path_violation', 'secret_detected',
            'validation_error', 'policy_deny'
        ) AND timestamp > ?
        GROUP BY event_type
        ORDER BY cnt DESC
    """, (cutoff,))

    # ── Hourly activity ──
    hourly = query("""
        SELECT CAST((timestamp - ?) / 3600 AS INTEGER) as hour_offset,
               COUNT(*) as calls
        FROM audit_log
        WHERE event_type = 'tool_call' AND timestamp > ?
        GROUP BY hour_offset
        ORDER BY hour_offset
    """, (cutoff, cutoff))

    # ── HITL stats ──
    hitl = query("""
        SELECT
            SUM(CASE WHEN json_extract(details, '$.action') = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
            SUM(CASE WHEN json_extract(details, '$.action') = 'denied' THEN 1 ELSE 0 END) as denied
        FROM audit_log
        WHERE event_type = 'tool_call'
          AND json_extract(details, '$.confirmation_id') IS NOT NULL
          AND timestamp > ?
    """, (cutoff,))
    hitl_stats = hitl[0] if hitl else {"confirmed": 0, "denied": 0}

    # ── Busiest period ──
    busiest = query("""
        SELECT datetime(timestamp, 'unixepoch', 'localtime') as ts, COUNT(*) as cnt
        FROM audit_log
        WHERE event_type = 'tool_call' AND timestamp > ?
        GROUP BY CAST(timestamp / 300 AS INTEGER)
        ORDER BY cnt DESC
        LIMIT 1
    """, (cutoff,))

    conn.close()

    import time as _time

    if json_output:
        result = {
            "period_hours": hours,
            "total_calls": total["total_calls"],
            "avg_latency_ms": total["avg_ms"],
            "tools": tool_usage,
            "security_events": sec_events,
            "hitl": hitl_stats,
            "hourly_activity": hourly,
        }
        console.print(json.dumps(result, indent=2))
        return

    # ── Render tables ──
    console.print()
    console.print(
        Panel(
            f"[bold cyan]MCP Spine Analytics[/bold cyan]  ·  Last {hours} hours",
            style="cyan",
        )
    )

    # Summary
    summary = Table(show_header=False, expand=True, box=None)
    summary.add_column(ratio=1)
    summary.add_column(ratio=1)
    summary.add_column(ratio=1)
    summary.add_column(ratio=1)
    summary.add_row(
        f"[dim]Total Calls:[/dim] [bold]{total['total_calls']}[/bold]",
        f"[dim]Avg Latency:[/dim] [bold]{total['avg_ms'] or 0:.0f}ms[/bold]",
        f"[dim]Security Events:[/dim] [bold]{sum(e['cnt'] for e in sec_events)}[/bold]",
        f"[dim]HITL:[/dim] [bold]{hitl_stats.get('confirmed') or 0} confirmed, {hitl_stats.get('denied') or 0} denied[/bold]",
    )
    console.print(summary)
    console.print()

    # Tool usage table
    if tool_usage:
        t = Table(title="Tool Usage Ranking", expand=True)
        t.add_column("#", style="dim", width=3)
        t.add_column("Tool", style="cyan", ratio=3)
        t.add_column("Calls", justify="right", ratio=1)
        t.add_column("Avg", justify="right", ratio=1)
        t.add_column("Min", justify="right", ratio=1)
        t.add_column("Max", justify="right", ratio=1)
        t.add_column("Bar", ratio=3)

        max_calls = max(tu["calls"] for tu in tool_usage) if tool_usage else 1
        for i, tu in enumerate(tool_usage, 1):
            bar_width = int((tu["calls"] / max_calls) * 20)
            bar = "█" * bar_width + "░" * (20 - bar_width)

            avg_style = "green" if (tu["avg_ms"] or 0) < 200 else "yellow" if (tu["avg_ms"] or 0) < 1000 else "red"

            t.add_row(
                str(i),
                tu["tool_name"],
                str(tu["calls"]),
                f"[{avg_style}]{tu['avg_ms'] or 0:.0f}ms[/{avg_style}]",
                f"{tu['min_ms'] or 0:.0f}ms",
                f"{tu['max_ms'] or 0:.0f}ms",
                f"[cyan]{bar}[/cyan]",
            )
        console.print(t)
    else:
        console.print("[dim]No tool calls in this period.[/dim]")

    # Security events
    if sec_events:
        console.print()
        s = Table(title="Security Events", expand=True)
        s.add_column("Event Type", style="red", ratio=2)
        s.add_column("Count", justify="right", ratio=1)
        s.add_column("Bar", ratio=3)

        max_sec = max(e["cnt"] for e in sec_events) if sec_events else 1
        for e in sec_events:
            bar_width = int((e["cnt"] / max_sec) * 20)
            bar = "█" * bar_width + "░" * (20 - bar_width)
            s.add_row(
                e["event_type"].replace("_", " ").title(),
                str(e["cnt"]),
                f"[red]{bar}[/red]",
            )
        console.print(s)

    # Hourly activity sparkline
    if hourly:
        console.print()
        h = Table(title=f"Hourly Activity (last {hours}h)", expand=True)
        h.add_column("Hour", style="dim", ratio=1)
        h.add_column("Calls", justify="right", ratio=1)
        h.add_column("Activity", ratio=4)

        max_hourly = max(hr["calls"] for hr in hourly) if hourly else 1
        for hr in hourly:
            bar_width = int((hr["calls"] / max_hourly) * 30)
            bar = "▓" * bar_width
            hours_ago = hours - hr["hour_offset"]
            h.add_row(
                f"{hours_ago}h ago",
                str(hr["calls"]),
                f"[green]{bar}[/green]",
            )
        console.print(h)

    # Busiest period
    if busiest:
        console.print()
        console.print(
            f"[dim]Busiest 5-min window:[/dim] {busiest[0]['ts']} "
            f"({busiest[0]['cnt']} calls)"
        )

    console.print()


if __name__ == "__main__":
    main()
