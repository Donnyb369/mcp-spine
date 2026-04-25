"""
MCP Spine — Webhook Notifications

Sends HTTP POST notifications to external services (Slack, Discord, etc.)
when security events fire or token budget thresholds are reached.

Config example:
    [webhooks]
    enabled = true

    [[webhooks.hooks]]
    url = "https://hooks.slack.com/services/T.../B.../xxx"
    events = ["security", "budget_warn", "budget_exceeded"]
    format = "slack"

    [[webhooks.hooks]]
    url = "https://discord.com/api/webhooks/xxx/yyy"
    events = ["security"]
    format = "discord"

    [[webhooks.hooks]]
    url = "https://your-server.com/spine-webhook"
    events = ["security", "budget_warn", "tool_blocked"]
    format = "json"
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WebhookTarget:
    """A single webhook destination."""
    url: str
    events: list[str] = field(default_factory=lambda: ["security"])
    format: str = "json"  # json, slack, discord
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0


@dataclass
class WebhookConfig:
    """Webhook system configuration."""
    enabled: bool = False
    hooks: list[WebhookTarget] = field(default_factory=list)


class WebhookManager:
    """
    Sends webhook notifications for security and budget events.

    Notifications are sent in background threads to avoid
    blocking the proxy event loop.
    """

    def __init__(self, config: WebhookConfig, logger: Any = None):
        self.config = config
        self._logger = logger

    def notify(self, event_type: str, payload: dict[str, Any]) -> None:
        """
        Send a notification to all matching webhook targets.

        event_type: one of 'security', 'budget_warn', 'budget_exceeded',
                    'tool_blocked', 'rate_limited', 'policy_deny'
        """
        if not self.config.enabled:
            return

        for hook in self.config.hooks:
            if event_type in hook.events or "all" in hook.events:
                thread = threading.Thread(
                    target=self._send,
                    args=(hook, event_type, payload),
                    daemon=True,
                )
                thread.start()

    def _send(
        self, hook: WebhookTarget, event_type: str, payload: dict[str, Any]
    ) -> None:
        """Send a single webhook notification (runs in a thread)."""
        try:
            body = self._format_payload(hook.format, event_type, payload)
            req = urllib.request.Request(
                hook.url,
                data=json.dumps(body).encode("utf-8"),
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            for key, value in hook.headers.items():
                req.add_header(key, value)

            urllib.request.urlopen(req, timeout=hook.timeout)

        except Exception as e:
            if self._logger:
                try:
                    self._logger.warn(
                        "startup",
                        component="webhooks",
                        message=f"Webhook failed: {e}",
                    )
                except Exception:
                    pass

    def _format_payload(
        self, fmt: str, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Format the payload for the target service."""
        title = self._title(event_type)
        detail = self._detail(event_type, payload)

        if fmt == "slack":
            return {
                "text": f"*{title}*\n{detail}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*:warning: {title}*\n{detail}",
                        },
                    },
                ],
            }

        if fmt == "discord":
            color = 0xFF4444 if "security" in event_type else 0xFFAA00
            return {
                "embeds": [
                    {
                        "title": title,
                        "description": detail,
                        "color": color,
                    },
                ],
            }

        # Default: raw JSON
        return {
            "event": event_type,
            "title": title,
            "detail": detail,
            "source": "mcp-spine",
            **payload,
        }

    def _title(self, event_type: str) -> str:
        return {
            "security": "MCP Spine Security Alert",
            "budget_warn": "MCP Spine Token Budget Warning",
            "budget_exceeded": "MCP Spine Token Budget Exceeded",
            "tool_blocked": "MCP Spine Tool Blocked",
            "rate_limited": "MCP Spine Rate Limit Hit",
            "policy_deny": "MCP Spine Policy Denial",
        }.get(event_type, f"MCP Spine Alert: {event_type}")

    def _detail(self, event_type: str, payload: dict[str, Any]) -> str:
        parts = []
        if payload.get("tool_name"):
            parts.append(f"Tool: {payload['tool_name']}")
        if payload.get("reason"):
            parts.append(f"Reason: {payload['reason']}")
        if payload.get("tokens_used"):
            parts.append(f"Tokens used: {payload['tokens_used']:,}")
        if payload.get("tokens_limit"):
            parts.append(f"Limit: {payload['tokens_limit']:,}")
        if payload.get("usage_pct"):
            parts.append(f"Usage: {payload['usage_pct']:.0%}")
        if payload.get("session_id"):
            parts.append(f"Session: {payload['session_id'][:12]}")
        return "\n".join(parts) if parts else "No additional details"
