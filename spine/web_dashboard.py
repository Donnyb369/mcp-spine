"""
MCP Spine — Web Dashboard

Browser-based monitoring dashboard showing live tool calls,
token usage, session history, and security events.

Serves a single-page app on localhost using Python's built-in
http.server — no external dependencies.

Usage:
    mcp-spine web --config spine.toml
    mcp-spine web --db spine_audit.db --port 8777
"""

from __future__ import annotations

import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class DashboardAPI:
    """Queries the audit DB and returns JSON for the web dashboard."""

    def __init__(self, db_path: str):
        self._db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._db_path)
        db.row_factory = sqlite3.Row
        return db

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        try:
            db = self._connect()
            rows = db.execute(sql, params).fetchall()
            db.close()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            return []

    def overview(self) -> dict[str, Any]:
        """Main overview stats."""
        total = self._query(
            "SELECT COUNT(*) as cnt FROM audit_log WHERE event_type IN ('tool_call', 'tool_response')"
        )
        sec = self._query(
            "SELECT COUNT(*) as cnt FROM audit_log WHERE event_type IN "
            "('rate_limited','path_violation','secret_detected','validation_error','policy_deny')"
        )
        sessions = self._query(
            "SELECT COUNT(DISTINCT session_id) as cnt FROM audit_log WHERE session_id IS NOT NULL"
        )

        # Token budget
        budget = self._query("SELECT * FROM token_usage ORDER BY date DESC LIMIT 1")
        budget_data = budget[0] if budget else {"date": "—", "tokens_used": 0, "tokens_limit": 0}

        # Tool call count (actual routed calls)
        calls = self._query(
            "SELECT COUNT(*) as cnt FROM audit_log WHERE event_type = 'tool_response' AND tool_name IS NOT NULL"
        )

        return {
            "total_events": total[0]["cnt"] if total else 0,
            "tool_calls": calls[0]["cnt"] if calls else 0,
            "security_events": sec[0]["cnt"] if sec else 0,
            "sessions": sessions[0]["cnt"] if sessions else 0,
            "budget": dict(budget_data) if budget else None,
        }

    def recent_calls(self, limit: int = 20) -> list[dict]:
        """Recent tool calls with timing."""
        return self._query("""
            SELECT timestamp, event_type, tool_name, server_name, details, session_id
            FROM audit_log
            WHERE event_type = 'tool_response' AND tool_name IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    def tool_stats(self) -> list[dict]:
        """Per-tool usage statistics."""
        return self._query("""
            SELECT tool_name,
                   COUNT(*) as calls,
                   ROUND(AVG(CAST(json_extract(details, '$.tokens_this_call') AS REAL)), 0) as avg_tokens
            FROM audit_log
            WHERE event_type = 'tool_response' AND tool_name IS NOT NULL
            GROUP BY tool_name
            ORDER BY calls DESC
            LIMIT 20
        """)

    def security_events(self, limit: int = 20) -> list[dict]:
        """Recent security events."""
        return self._query("""
            SELECT timestamp, event_type, tool_name, details, session_id
            FROM audit_log
            WHERE event_type IN (
                'rate_limited','path_violation','secret_detected',
                'validation_error','policy_deny','tool_blocked'
            )
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

    def sessions(self) -> list[dict]:
        """All client sessions."""
        return self._query("""
            SELECT session_id,
                   MIN(created_at) as first_seen,
                   MAX(created_at) as last_seen,
                   COUNT(*) as entries
            FROM audit_log
            WHERE session_id IS NOT NULL
            GROUP BY session_id
            ORDER BY first_seen DESC
            LIMIT 30
        """)

    def hourly_activity(self, hours: int = 24) -> list[dict]:
        """Hourly tool call counts."""
        cutoff = time.time() - (hours * 3600)
        return self._query("""
            SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch', 'localtime')) as hour,
                   COUNT(*) as calls
            FROM audit_log
            WHERE event_type = 'tool_response'
              AND tool_name IS NOT NULL
              AND timestamp > ?
            GROUP BY hour
            ORDER BY hour
        """, (cutoff,))

    def servers(self) -> list[dict]:
        """Connected servers from startup logs."""
        return self._query("""
            SELECT json_extract(details, '$.command') as command,
                   json_extract(details, '$.server_name') as name
            FROM audit_log
            WHERE event_type = 'server_connect'
              AND details LIKE '%command%'
            ORDER BY timestamp DESC
            LIMIT 20
        """)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Spine Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;600;700&display=swap');

  :root {
    --bg: #0a0e17;
    --surface: #111827;
    --surface-hover: #1a2235;
    --border: #1e293b;
    --text: #e2e8f0;
    --text-dim: #64748b;
    --accent: #06b6d4;
    --accent-glow: rgba(6, 182, 212, 0.15);
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --purple: #8b5cf6;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Outfit', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  .header {
    padding: 20px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, #0f1520, var(--bg));
  }

  .header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 2px;
  }

  .header h1 span { color: var(--text-dim); font-weight: 400; }

  .header-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
    color: var(--text-dim);
  }

  .pulse {
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
    50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    padding: 24px 32px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: border-color 0.2s;
  }

  .stat-card:hover { border-color: var(--accent); }
  .stat-card .label { font-size: 0.8rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .stat-card .value { font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 700; }
  .stat-card .sub { font-size: 0.75rem; color: var(--text-dim); margin-top: 4px; }

  .panels {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 16px;
    padding: 0 32px 24px;
  }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }

  .panel-header {
    padding: 14px 20px;
    font-weight: 600;
    font-size: 0.9rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .panel-header .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
  }

  .panel-body { padding: 0; }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  th {
    text-align: left;
    padding: 10px 16px;
    color: var(--text-dim);
    font-weight: 400;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
  }

  td {
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
  }

  tr:last-child td { border-bottom: none; }
  tr:hover { background: var(--surface-hover); }

  .tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }

  .tag-green { background: rgba(16, 185, 129, 0.15); color: var(--green); }
  .tag-red { background: rgba(239, 68, 68, 0.15); color: var(--red); }
  .tag-yellow { background: rgba(245, 158, 11, 0.15); color: var(--yellow); }
  .tag-purple { background: rgba(139, 92, 246, 0.15); color: var(--purple); }
  .tag-cyan { background: var(--accent-glow); color: var(--accent); }

  .budget-bar {
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    margin-top: 8px;
    overflow: hidden;
  }

  .budget-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
  }

  .chart-bar-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 16px;
    border-bottom: 1px solid var(--border);
  }

  .chart-bar-row:last-child { border-bottom: none; }

  .chart-bar-label {
    width: 140px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .chart-bar {
    flex: 1;
    height: 20px;
    background: var(--accent-glow);
    border-radius: 4px;
    position: relative;
  }

  .chart-bar-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 4px;
    min-width: 2px;
    transition: width 0.5s ease;
  }

  .chart-bar-count {
    width: 50px;
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    color: var(--text-dim);
  }

  .empty-state {
    padding: 32px;
    text-align: center;
    color: var(--text-dim);
    font-size: 0.85rem;
  }

  .bottom-panels {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    padding: 0 32px 32px;
  }

  @media (max-width: 900px) {
    .grid { grid-template-columns: repeat(2, 1fr); }
    .panels, .bottom-panels { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<div class="header">
  <h1>MCP SPINE <span>Dashboard</span></h1>
  <div class="header-status">
    <div class="pulse"></div>
    <span id="refresh-status">Refreshing...</span>
  </div>
</div>

<div class="grid" id="stats-grid">
  <div class="stat-card">
    <div class="label">Tool Calls</div>
    <div class="value" id="stat-calls">—</div>
  </div>
  <div class="stat-card">
    <div class="label">Security Events</div>
    <div class="value" id="stat-security">—</div>
  </div>
  <div class="stat-card">
    <div class="label">Sessions</div>
    <div class="value" id="stat-sessions">—</div>
  </div>
  <div class="stat-card">
    <div class="label">Token Budget</div>
    <div class="value" id="stat-budget">—</div>
    <div class="sub" id="stat-budget-sub"></div>
    <div class="budget-bar"><div class="budget-fill" id="budget-fill"></div></div>
  </div>
</div>

<div class="panels">
  <div class="panel">
    <div class="panel-header">
      <div class="dot" style="background:var(--green)"></div>
      Recent Tool Calls
    </div>
    <div class="panel-body">
      <table>
        <thead><tr><th>Time</th><th>Tool</th><th>Server</th><th>Session</th><th>Status</th></tr></thead>
        <tbody id="calls-body"></tbody>
      </table>
      <div class="empty-state" id="calls-empty" style="display:none">No tool calls yet</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <div class="dot" style="background:var(--accent)"></div>
      Tool Usage
    </div>
    <div class="panel-body" id="tool-stats-body"></div>
  </div>
</div>

<div class="bottom-panels">
  <div class="panel">
    <div class="panel-header">
      <div class="dot" style="background:var(--red)"></div>
      Security Events
    </div>
    <div class="panel-body">
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>Tool</th><th>Details</th></tr></thead>
        <tbody id="security-body"></tbody>
      </table>
      <div class="empty-state" id="security-empty" style="display:none">No security events — all clear</div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <div class="dot" style="background:var(--purple)"></div>
      Client Sessions
    </div>
    <div class="panel-body">
      <table>
        <thead><tr><th>Session</th><th>First Seen</th><th>Last Seen</th><th>Events</th></tr></thead>
        <tbody id="sessions-body"></tbody>
      </table>
      <div class="empty-state" id="sessions-empty" style="display:none">No sessions recorded</div>
    </div>
  </div>
</div>

<script>
const API = '/api';

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

function fmtEvent(e) {
  const map = {
    rate_limited: ['Rate Limited', 'red'],
    path_violation: ['Path Violation', 'red'],
    secret_detected: ['Secret Found', 'yellow'],
    validation_error: ['Validation', 'yellow'],
    policy_deny: ['Denied', 'red'],
    tool_blocked: ['Blocked', 'red'],
  };
  const [label, color] = map[e] || [e, 'cyan'];
  return `<span class="tag tag-${color}">${label}</span>`;
}

async function refresh() {
  try {
    const [overview, calls, tools, security, sessions] = await Promise.all([
      fetch(API + '/overview').then(r => r.json()),
      fetch(API + '/calls').then(r => r.json()),
      fetch(API + '/tools').then(r => r.json()),
      fetch(API + '/security').then(r => r.json()),
      fetch(API + '/sessions').then(r => r.json()),
    ]);

    // Stats
    document.getElementById('stat-calls').textContent = overview.tool_calls || 0;
    document.getElementById('stat-security').textContent = overview.security_events || 0;
    const secEl = document.getElementById('stat-security');
    secEl.style.color = overview.security_events > 0 ? 'var(--red)' : 'var(--green)';
    document.getElementById('stat-sessions').textContent = overview.sessions || 0;

    if (overview.budget && overview.budget.tokens_limit > 0) {
      const pct = Math.min(100, (overview.budget.tokens_used / overview.budget.tokens_limit * 100));
      document.getElementById('stat-budget').textContent = pct.toFixed(1) + '%';
      document.getElementById('stat-budget-sub').textContent =
        `${(overview.budget.tokens_used || 0).toLocaleString()} / ${(overview.budget.tokens_limit || 0).toLocaleString()}`;
      const fill = document.getElementById('budget-fill');
      fill.style.width = pct + '%';
      fill.style.background = pct > 80 ? 'var(--red)' : pct > 50 ? 'var(--yellow)' : 'var(--green)';
    } else {
      document.getElementById('stat-budget').textContent = '—';
      document.getElementById('stat-budget-sub').textContent = 'Not configured';
    }

    // Recent calls
    const callsBody = document.getElementById('calls-body');
    const callsEmpty = document.getElementById('calls-empty');
    if (calls.length === 0) {
      callsBody.innerHTML = '';
      callsEmpty.style.display = 'block';
    } else {
      callsEmpty.style.display = 'none';
      callsBody.innerHTML = calls.map(c => {
        const details = typeof c.details === 'string' ? JSON.parse(c.details) : (c.details || {});
        const success = details.success !== false;
        return `<tr>
          <td>${fmtTime(c.timestamp)}</td>
          <td>${(c.tool_name || '—').substring(0, 25)}</td>
          <td>${(c.server_name || '—').substring(0, 15)}</td>
          <td style="color:var(--text-dim)">${(c.session_id || '—').substring(0, 8)}</td>
          <td><span class="tag tag-${success ? 'green' : 'red'}">${success ? 'OK' : 'ERR'}</span></td>
        </tr>`;
      }).join('');
    }

    // Tool stats
    const toolBody = document.getElementById('tool-stats-body');
    if (tools.length === 0) {
      toolBody.innerHTML = '<div class="empty-state">No tool data</div>';
    } else {
      const maxCalls = Math.max(...tools.map(t => t.calls));
      toolBody.innerHTML = tools.map(t => {
        const pct = (t.calls / maxCalls * 100);
        return `<div class="chart-bar-row">
          <div class="chart-bar-label">${t.tool_name || '?'}</div>
          <div class="chart-bar"><div class="chart-bar-fill" style="width:${pct}%"></div></div>
          <div class="chart-bar-count">${t.calls}</div>
        </div>`;
      }).join('');
    }

    // Security
    const secBody = document.getElementById('security-body');
    const secEmpty = document.getElementById('security-empty');
    if (security.length === 0) {
      secBody.innerHTML = '';
      secEmpty.style.display = 'block';
    } else {
      secEmpty.style.display = 'none';
      secBody.innerHTML = security.map(s => {
        const details = typeof s.details === 'string' ? JSON.parse(s.details) : (s.details || {});
        const reason = details.reason || details.error || '';
        return `<tr>
          <td>${fmtTime(s.timestamp)}</td>
          <td>${fmtEvent(s.event_type)}</td>
          <td>${(s.tool_name || '—').substring(0, 20)}</td>
          <td style="color:var(--text-dim)">${reason.substring(0, 30)}</td>
        </tr>`;
      }).join('');
    }

    // Sessions
    const sessBody = document.getElementById('sessions-body');
    const sessEmpty = document.getElementById('sessions-empty');
    if (sessions.length === 0) {
      sessBody.innerHTML = '';
      sessEmpty.style.display = 'block';
    } else {
      sessEmpty.style.display = 'none';
      sessBody.innerHTML = sessions.map(s => `<tr>
        <td><span class="tag tag-cyan">${(s.session_id || '—').substring(0, 12)}</span></td>
        <td style="color:var(--text-dim)">${s.first_seen || '—'}</td>
        <td style="color:var(--text-dim)">${s.last_seen || '—'}</td>
        <td>${s.entries || 0}</td>
      </tr>`).join('');
    }

    document.getElementById('refresh-status').textContent =
      'Updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('refresh-status').textContent = 'Error: ' + e.message;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the web dashboard."""

    api: DashboardAPI  # Set by the server factory

    def log_message(self, format, *args):
        pass  # Suppress default access logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/' or path == '/index.html':
            self._serve_html()
        elif path.startswith('/api/'):
            self._serve_api(path[5:])
        else:
            self.send_error(404)

    def _serve_html(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode('utf-8'))

    def _serve_api(self, endpoint: str):
        data: Any = None

        if endpoint == 'overview':
            data = self.api.overview()
        elif endpoint == 'calls':
            data = self.api.recent_calls()
        elif endpoint == 'tools':
            data = self.api.tool_stats()
        elif endpoint == 'security':
            data = self.api.security_events()
        elif endpoint == 'sessions':
            data = self.api.sessions()
        elif endpoint == 'hourly':
            data = self.api.hourly_activity()
        elif endpoint == 'servers':
            data = self.api.servers()
        else:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode('utf-8'))


def run_web_dashboard(
    db_path: str = "spine_audit.db",
    host: str = "127.0.0.1",
    port: int = 8777,
) -> None:
    """Start the web dashboard server."""
    from rich.console import Console

    console = Console()

    if not Path(db_path).exists():
        console.print(f"[red]Audit database not found: {db_path}[/red]")
        console.print("Run [bold]mcp-spine serve[/bold] first to generate audit data.")
        return

    api = DashboardAPI(db_path)

    # Inject API into handler class
    handler_class = type(
        'Handler',
        (DashboardHandler,),
        {'api': api},
    )

    server = HTTPServer((host, port), handler_class)

    console.print("[cyan]MCP Spine Web Dashboard[/cyan]")
    console.print(f"  [green]http://{host}:{port}[/green]")
    console.print(f"  [dim]DB: {db_path}[/dim]")
    console.print("  [dim]Press Ctrl+C to stop[/dim]")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[cyan]Dashboard stopped.[/cyan]")
    finally:
        server.server_close()
