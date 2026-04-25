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

    # ── Token budget (today) ──
    budget_row: dict | None = None
    try:
        from datetime import date as _date
        today_iso = _date.today().isoformat()
        rows = query(
            "SELECT date, tokens_used, tokens_limit "
            "FROM token_usage WHERE date = ?",
            (today_iso,),
        )
        budget_row = rows[0] if rows else None
    except Exception:
        budget_row = None

    conn.close()


    if json_output:
        result = {
            "period_hours": hours,
            "total_calls": total["total_calls"],
            "avg_latency_ms": total["avg_ms"],
            "tools": tool_usage,
            "security_events": sec_events,
            "hitl": hitl_stats,
            "hourly_activity": hourly,
            "token_budget": _budget_snapshot(budget_row),
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

    # Token budget (today)
    snap = _budget_snapshot(budget_row)
    if snap["daily_limit"] > 0 or snap["tokens_used"] > 0:
        console.print()
        b = Table(title="Token Budget (today)", show_header=False, expand=True)
        b.add_column(ratio=1)
        b.add_column(ratio=2)

        used = snap["tokens_used"]
        limit = snap["daily_limit"]
        remaining = snap["tokens_remaining"]
        pct = snap["usage_pct"]

        pct_style = "green" if pct < 0.5 else "yellow" if pct < 0.8 else "red"
        limit_display = f"{limit:,}" if limit > 0 else "[dim]unset[/dim]"

        b.add_row("Date", snap["date"])
        b.add_row("Used", f"{used:,}")
        b.add_row("Limit", limit_display)
        b.add_row(
            "Remaining",
            f"{remaining:,}" if limit > 0 else "[dim]n/a[/dim]",
        )
        b.add_row(
            "Usage",
            f"[{pct_style}]{pct * 100:.1f}%[/{pct_style}]"
            if limit > 0 else "[dim]n/a[/dim]",
        )

        # Simple bar
        if limit > 0:
            bar_width = int(pct * 30)
            bar = "█" * bar_width + "░" * (30 - bar_width)
            b.add_row("", f"[{pct_style}]{bar}[/{pct_style}]")

        console.print(b)

    # Busiest period
    if busiest:
        console.print()
        console.print(
            f"[dim]Busiest 5-min window:[/dim] {busiest[0]['ts']} "
            f"({busiest[0]['cnt']} calls)"
        )

    console.print()


def _budget_snapshot(row: dict | None) -> dict:
    """
    Build a consistent budget-stats dict from a token_usage row.

    Returns a dict usable in both JSON output and rendered tables.
    """
    from datetime import date as _date
    if row is None:
        return {
            "date": _date.today().isoformat(),
            "tokens_used": 0,
            "daily_limit": 0,
            "tokens_remaining": 0,
            "usage_pct": 0.0,
        }
    used = int(row.get("tokens_used") or 0)
    limit = int(row.get("tokens_limit") or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    pct = (used / limit) if limit > 0 else 0.0
    return {
        "date": row.get("date") or _date.today().isoformat(),
        "tokens_used": used,
        "daily_limit": limit,
        "tokens_remaining": remaining,
        "usage_pct": round(min(1.0, pct), 4),
    }


@main.command()
@click.option("--db", default="spine_audit.db", help="Audit database path")
@click.option("--format", "-f", "fmt", type=click.Choice(["csv", "json"]), default="csv", help="Export format")
@click.option("--hours", "-h", default=24, help="Hours of history to export")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
@click.option("--event", "-e", default=None, help="Filter by event type")
def export(db: str, fmt: str, hours: int, output: str | None, event: str | None):
    """Export audit data to CSV or JSON."""
    import csv
    import io
    import sqlite3

    db_path = Path(db)
    if not db_path.exists():
        console.print(f"[red]Audit database not found: {db}[/red]")
        sys.exit(1)

    import time as _time
    cutoff = _time.time() - (hours * 3600)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT timestamp, event_type, tool_name, server_name, details, session_id, created_at
        FROM audit_log
        WHERE timestamp > ?
    """
    params: list = [cutoff]

    if event:
        query += " AND event_type = ?"
        params.append(event)

    query += " ORDER BY timestamp ASC"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    if not rows:
        console.print("[dim]No data to export.[/dim]")
        return

    data = [dict(row) for row in rows]

    if fmt == "json":
        import json as _json
        content = _json.dumps(data, indent=2, default=str)
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        content = buf.getvalue()

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]Exported {len(data)} entries to {output}[/green]")
    else:
        click.echo(content)


@main.command()
@click.option("--db", default="spine_audit.db", help="Audit database path")
@click.option("--port", "-p", default=8777, help="Port to serve on")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
def web(db: str, port: int, host: str) -> None:
    """Open the web dashboard in your browser."""
    from spine.web_dashboard import run_web_dashboard

    run_web_dashboard(db_path=db, host=host, port=port)


@main.command()
@click.option("--config", "-c", default="spine.toml", help="Config file path")
def doctor(config: str) -> None:
    """Diagnose common setup issues."""
    import os
    import platform
    import shutil

    console.print(Panel("[bold cyan]MCP Spine Doctor[/bold cyan]", style="cyan"))

    # System info
    t = Table(title="System", show_header=False, expand=True)
    t.add_column(ratio=1)
    t.add_column(ratio=2)
    t.add_row("OS", f"{platform.system()} {platform.release()}")
    t.add_row("Python", f"{platform.python_version()} ({sys.executable})")
    t.add_row("Architecture", platform.machine())
    t.add_row("CWD", os.getcwd())
    console.print(t)

    # Config
    config_path = Path(config)
    t2 = Table(title="Config", show_header=False, expand=True)
    t2.add_column(ratio=1)
    t2.add_column(ratio=2)
    t2.add_row("Config file", str(config_path.absolute()))
    t2.add_row("Exists", "[green]Yes[/green]" if config_path.exists() else "[red]No[/red]")

    if config_path.exists():
        try:
            from spine.config import load_config
            cfg = load_config(str(config_path))
            t2.add_row("Servers", str(len(cfg.servers)))
            for s in cfg.servers:
                transport = f"[cyan]{s.transport}[/cyan]"
                if s.transport == "sse":
                    t2.add_row(f"  {s.name}", f"{transport} → {s.url}")
                else:
                    t2.add_row(f"  {s.name}", f"{transport} → {s.command} {' '.join(s.args[:2])}")
            t2.add_row("Minification", f"Level {cfg.minifier.level}")
            t2.add_row("State Guard", "[green]on[/green]" if cfg.state_guard.enabled else "[dim]off[/dim]")
            t2.add_row("Audit DB", cfg.audit_db)
            # Token budget
            tb = cfg.token_budget
            if tb.daily_limit > 0:
                t2.add_row(
                    "Token budget",
                    f"[green]{tb.daily_limit:,}/day[/green] "
                    f"(warn at {int(tb.warn_at * 100)}%, action={tb.action})",
                )
            else:
                t2.add_row("Token budget", "[dim]disabled[/dim]")
        except Exception as e:
            t2.add_row("[red]Error[/red]", str(e))
    console.print(t2)

    # Token budget usage today (if audit DB exists)
    if config_path.exists():
        try:
            from spine.config import load_config as _lc
            cfg_tmp = _lc(str(config_path))
            db_path = Path(cfg_tmp.audit_db)
            if db_path.exists():
                import sqlite3 as _sq
                from datetime import date as _date
                conn = _sq.connect(str(db_path))
                try:
                    row = conn.execute(
                        "SELECT tokens_used, tokens_limit FROM token_usage "
                        "WHERE date = ?",
                        (_date.today().isoformat(),),
                    ).fetchone()
                except _sq.Error:
                    row = None
                conn.close()

                tb = Table(title="Token Budget (today)", show_header=False, expand=True)
                tb.add_column(ratio=1)
                tb.add_column(ratio=2)
                if row is None:
                    tb.add_row("Usage", "[dim]no records yet today[/dim]")
                else:
                    used = int(row[0] or 0)
                    limit = int(row[1] or 0)
                    if limit > 0:
                        pct = used / limit
                        style = "green" if pct < 0.5 else "yellow" if pct < 0.8 else "red"
                        tb.add_row("Used", f"{used:,}")
                        tb.add_row("Limit", f"{limit:,}")
                        tb.add_row("Remaining", f"{max(0, limit - used):,}")
                        tb.add_row(
                            "Usage",
                            f"[{style}]{pct * 100:.1f}%[/{style}]",
                        )
                    else:
                        tb.add_row("Used", f"{used:,}")
                        tb.add_row("Limit", "[dim]unset[/dim]")
                console.print(tb)
        except Exception:
            pass

    # Commands
    t3 = Table(title="Dependencies", show_header=False, expand=True)
    t3.add_column(ratio=1)
    t3.add_column(ratio=2)

    for cmd in ["npx", "node", "npm", "uvx", "git"]:
        path = shutil.which(cmd)
        if path:
            t3.add_row(cmd, f"[green]{path}[/green]")
        else:
            t3.add_row(cmd, "[red]Not found[/red]")

    # ML deps
    try:
        import sentence_transformers
        t3.add_row("sentence-transformers", f"[green]{sentence_transformers.__version__}[/green]")
    except ImportError:
        t3.add_row("sentence-transformers", "[dim]Not installed (optional)[/dim]")

    try:
        import chromadb
        t3.add_row("chromadb", f"[green]{chromadb.__version__}[/green]")
    except ImportError:
        t3.add_row("chromadb", "[dim]Not installed (optional)[/dim]")

    console.print(t3)

    # Claude Desktop config
    t4 = Table(title="Claude Desktop", show_header=False, expand=True)
    t4.add_column(ratio=1)
    t4.add_column(ratio=2)

    claude_paths = [
        Path(os.environ.get("APPDATA", "")) / "Claude" / "claude_desktop_config.json",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ]

    found = False
    for cp in claude_paths:
        if cp.exists():
            t4.add_row("Config", f"[green]{cp}[/green]")
            found = True
            try:
                import json as _json
                data = _json.loads(cp.read_text())
                servers = data.get("mcpServers", {})
                spine_entry = servers.get("spine")
                if spine_entry:
                    t4.add_row("Spine entry", "[green]Found[/green]")
                    t4.add_row("  Command", spine_entry.get("command", "?"))
                else:
                    t4.add_row("Spine entry", "[red]Not found — add it to mcpServers[/red]")
            except Exception:
                t4.add_row("Parse", "[red]Failed to read config[/red]")
            break

    if not found:
        t4.add_row("Config", "[red]Not found[/red]")

    # Log file
    log_paths = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Packages" / "Claude_pzs8sxrjxfjjc" / "LocalCache" / "Roaming" / "Claude" / "logs" / "mcp-server-spine.log",
        Path(os.environ.get("APPDATA", "")) / "Claude" / "logs" / "mcp-server-spine.log",
    ]
    for lp in log_paths:
        if lp.exists():
            t4.add_row("Log file", f"[green]{lp}[/green]")
            break
    else:
        t4.add_row("Log file", "[dim]Not found (starts after first run)[/dim]")

    console.print(t4)
    console.print()


if __name__ == "__main__":
    main()
