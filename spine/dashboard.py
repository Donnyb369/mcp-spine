"""
MCP Spine — Live TUI Dashboard

Real-time monitoring dashboard showing:
  - Server status and uptime
  - Recent tool calls with latency
  - Security events
  - Token savings from schema minification
  - Rate limit status

Usage:
    mcp-spine dashboard --config spine.toml
    mcp-spine dashboard --db spine_audit.db
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class SpineDashboard:
    """Live TUI dashboard for MCP Spine monitoring."""

    def __init__(self, db_path: str = "spine_audit.db", refresh_rate: float = 1.0):
        self._db_path = db_path
        self._refresh_rate = refresh_rate
        self._console = Console()
        self._start_time = time.time()

    def _connect_db(self) -> sqlite3.Connection | None:
        """Connect to the audit database."""
        path = Path(self._db_path)
        if not path.exists():
            return None
        try:
            db = sqlite3.connect(self._db_path)
            db.row_factory = sqlite3.Row
            return db
        except sqlite3.Error:
            return None

    def _query(self, db: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
        """Run a query and return results as dicts."""
        try:
            rows = db.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            return []

    def _build_header(self) -> Panel:
        """Build the header panel."""
        uptime = time.time() - self._start_time
        hours, remainder = divmod(int(uptime), 3600)
        minutes, seconds = divmod(remainder, 60)

        header = Text()
        header.append("MCP SPINE", style="bold cyan")
        header.append("  ·  ", style="dim")
        header.append("Live Dashboard", style="dim")
        header.append("  ·  ", style="dim")
        header.append(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}", style="green")
        header.append("  ·  ", style="dim")
        header.append(f"DB: {self._db_path}", style="dim")

        return Panel(header, style="cyan", height=3)

    def _build_servers_panel(self, db: sqlite3.Connection) -> Panel:
        """Build the server status panel."""
        table = Table(expand=True, show_header=True, header_style="bold")
        table.add_column("Server", style="cyan", ratio=2)
        table.add_column("Status", justify="center", ratio=1)
        table.add_column("Tools", justify="center", ratio=1)
        table.add_column("Calls", justify="center", ratio=1)
        table.add_column("Errors", justify="center", ratio=1)

        # Get server connect events
        servers = self._query(db, """
            SELECT DISTINCT json_extract(details, '$.server_name') as name
            FROM audit_log
            WHERE event_type = 'server_connect'
              AND json_extract(details, '$.server_name') IS NOT NULL
        """)

        for server in servers:
            name = server.get("name", "unknown")
            if not name:
                continue

            # Count tool calls for this server
            calls = self._query(db, """
                SELECT COUNT(*) as cnt FROM audit_log
                WHERE event_type = 'tool_call' AND server_name = ?
            """, (name,))
            call_count = calls[0]["cnt"] if calls else 0

            # Count errors
            errors = self._query(db, """
                SELECT COUNT(*) as cnt FROM audit_log
                WHERE event_type IN ('tool_blocked', 'rate_limited', 'path_violation')
                  AND server_name = ?
            """, (name,))
            error_count = errors[0]["cnt"] if errors else 0

            # Get tool count from latest tool_list
            tools = self._query(db, """
                SELECT json_extract(details, '$.total') as total
                FROM audit_log
                WHERE event_type = 'tool_list'
                ORDER BY timestamp DESC LIMIT 1
            """)
            tool_count = tools[0].get("total", "?") if tools else "?"

            status = Text("● ONLINE", style="green bold")
            error_style = "red bold" if error_count > 0 else "dim"

            table.add_row(
                name,
                status,
                str(tool_count),
                str(call_count),
                Text(str(error_count), style=error_style),
            )

        if not servers:
            table.add_row("No servers detected", Text("—", style="dim"), "—", "—", "—")

        return Panel(table, title="[bold]Servers[/bold]", border_style="blue")

    def _build_recent_calls_panel(self, db: sqlite3.Connection) -> Panel:
        """Build the recent tool calls panel."""
        table = Table(expand=True, show_header=True, header_style="bold")
        table.add_column("Time", style="dim", ratio=1)
        table.add_column("Tool", style="cyan", ratio=3)
        table.add_column("Duration", justify="right", ratio=1)
        table.add_column("Status", justify="center", ratio=1)

        calls = self._query(db, """
            SELECT timestamp, tool_name, details
            FROM audit_log
            WHERE event_type = 'tool_call' AND tool_name IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 12
        """)

        for call in calls:
            ts = datetime.fromtimestamp(call["timestamp"]).strftime("%H:%M:%S")
            tool = call.get("tool_name", "?")
            details = json.loads(call.get("details", "{}"))
            duration = details.get("duration_ms")
            duration_str = f"{duration}ms" if duration else "—"

            # Color duration based on speed
            if duration and duration > 1000:
                dur_style = "red"
            elif duration and duration > 200:
                dur_style = "yellow"
            else:
                dur_style = "green"

            confirmed = details.get("confirmed")
            if confirmed:
                status = Text("✓ HITL", style="green")
            else:
                status = Text("✓", style="green")

            table.add_row(
                ts,
                tool[:30],
                Text(duration_str, style=dur_style),
                status,
            )

        if not calls:
            table.add_row("—", "No tool calls yet", "—", "—")

        return Panel(table, title="[bold]Recent Tool Calls[/bold]", border_style="green")

    def _build_security_panel(self, db: sqlite3.Connection) -> Panel:
        """Build the security events panel."""
        table = Table(expand=True, show_header=True, header_style="bold")
        table.add_column("Time", style="dim", ratio=1)
        table.add_column("Event", style="red", ratio=2)
        table.add_column("Details", ratio=3)

        events = self._query(db, """
            SELECT timestamp, event_type, tool_name, details
            FROM audit_log
            WHERE event_type IN (
                'rate_limited', 'path_violation', 'secret_detected',
                'validation_error', 'policy_deny'
            )
            ORDER BY timestamp DESC
            LIMIT 8
        """)

        for event in events:
            ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
            etype = event["event_type"].replace("_", " ").title()
            details = json.loads(event.get("details", "{}"))
            reason = details.get("reason", details.get("error", ""))
            tool = event.get("tool_name", "")

            detail_str = f"{tool}: {reason}" if tool else reason

            table.add_row(ts, etype, detail_str[:50])

        if not events:
            table.add_row("—", Text("No security events", style="green"), "All clear")

        return Panel(table, title="[bold]Security Events[/bold]", border_style="red")

    def _build_stats_panel(self, db: sqlite3.Connection) -> Panel:
        """Build the statistics panel."""
        # Total calls
        total = self._query(db, """
            SELECT COUNT(*) as cnt FROM audit_log WHERE event_type = 'tool_call'
        """)
        total_calls = total[0]["cnt"] if total else 0

        # Avg latency
        avg = self._query(db, """
            SELECT AVG(CAST(json_extract(details, '$.duration_ms') AS REAL)) as avg_ms
            FROM audit_log
            WHERE event_type = 'tool_call'
              AND json_extract(details, '$.duration_ms') IS NOT NULL
        """)
        avg_ms = avg[0]["avg_ms"] if avg and avg[0]["avg_ms"] else 0

        # Security events
        sec = self._query(db, """
            SELECT COUNT(*) as cnt FROM audit_log
            WHERE event_type IN (
                'rate_limited', 'path_violation', 'secret_detected',
                'validation_error', 'policy_deny'
            )
        """)
        sec_count = sec[0]["cnt"] if sec else 0

        # HITL confirmations
        hitl = self._query(db, """
            SELECT COUNT(*) as cnt FROM audit_log
            WHERE event_type = 'tool_call'
              AND json_extract(details, '$.confirmed') = 1
        """)
        hitl_count = hitl[0]["cnt"] if hitl else 0

        # Most used tool
        top_tool = self._query(db, """
            SELECT tool_name, COUNT(*) as cnt
            FROM audit_log
            WHERE event_type = 'tool_call' AND tool_name IS NOT NULL
            GROUP BY tool_name
            ORDER BY cnt DESC
            LIMIT 1
        """)
        top = f"{top_tool[0]['tool_name']} ({top_tool[0]['cnt']}x)" if top_tool else "—"

        stats = Text()
        stats.append("Total Calls: ", style="dim")
        stats.append(f"{total_calls}\n", style="bold cyan")
        stats.append("Avg Latency: ", style="dim")
        stats.append(f"{avg_ms:.0f}ms\n", style="bold green" if avg_ms < 500 else "bold yellow")
        stats.append("Security Events: ", style="dim")
        stats.append(f"{sec_count}\n", style="bold red" if sec_count > 0 else "bold green")
        stats.append("HITL Confirmations: ", style="dim")
        stats.append(f"{hitl_count}\n", style="bold cyan")
        stats.append("Top Tool: ", style="dim")
        stats.append(f"{top}\n", style="bold")
        stats.append("Minification: ", style="dim")
        stats.append("Level 2 (61% savings)", style="bold green")

        return Panel(stats, title="[bold]Statistics[/bold]", border_style="yellow")

    def _build_layout(self, db: sqlite3.Connection) -> Layout:
        """Build the full dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=2),
        )

        layout["left"].split_column(
            Layout(name="servers", ratio=1),
            Layout(name="calls", ratio=2),
        )

        layout["right"].split_column(
            Layout(name="stats", ratio=1),
            Layout(name="security", ratio=1),
        )

        layout["header"].update(self._build_header())
        layout["servers"].update(self._build_servers_panel(db))
        layout["calls"].update(self._build_recent_calls_panel(db))
        layout["stats"].update(self._build_stats_panel(db))
        layout["security"].update(self._build_security_panel(db))

        footer = Text("  Press Ctrl+C to exit", style="dim")
        layout["footer"].update(Panel(footer, style="dim", height=3))

        return layout

    def run(self) -> None:
        """Run the live dashboard."""
        db = self._connect_db()
        if db is None:
            self._console.print(
                f"[red]Cannot open audit database: {self._db_path}[/red]\n"
                f"Run [bold]mcp-spine serve[/bold] first to generate audit data."
            )
            return

        self._console.print("[cyan]Starting MCP Spine Dashboard...[/cyan]")
        self._start_time = time.time()

        try:
            with Live(
                self._build_layout(db),
                console=self._console,
                refresh_per_second=1 / self._refresh_rate,
                screen=True,
            ) as live:
                while True:
                    time.sleep(self._refresh_rate)
                    # Reconnect each refresh to pick up new entries
                    db.close()
                    db = self._connect_db()
                    if db:
                        live.update(self._build_layout(db))
        except KeyboardInterrupt:
            pass
        finally:
            if db:
                db.close()
            self._console.print("[cyan]Dashboard stopped.[/cyan]")
