"""
Example Spine Plugin — Slack Channel Filter

Filters Slack tool responses to exclude messages from
sensitive channels before they reach the LLM.

Usage:
    1. Copy this file to your plugins/ directory
    2. Edit deny_channels and deny_keywords below
    3. Enable plugins in spine.toml:

        [plugins]
        enabled = true
        directory = "plugins"
"""

from spine.plugins import SpinePlugin


class SlackFilter(SpinePlugin):
    """Filter sensitive Slack channels and keywords from tool responses."""

    name = "slack-filter"

    # Channels the LLM should never see
    deny_channels = [
        "hr-private",
        "exec-salary",
        "legal-confidential",
        "performance-reviews",
    ]

    # Keywords that trigger message redaction
    deny_keywords = [
        "termination",
        "salary",
        "disciplinary",
        "confidential",
    ]

    def on_tool_response(self, tool_name, arguments, response):
        # Only filter Slack-related tools
        if "slack" not in tool_name.lower():
            return response

        if not isinstance(response, dict):
            return response

        content = response.get("content", [])
        if not isinstance(content, list):
            return response

        filtered = []
        redacted = 0
        for block in content:
            text = block.get("text", "") if isinstance(block, dict) else str(block)
            text_lower = text.lower()

            # Check channel deny list
            if any(ch in text_lower for ch in self.deny_channels):
                redacted += 1
                continue

            # Check keyword deny list
            if any(kw in text_lower for kw in self.deny_keywords):
                redacted += 1
                continue

            filtered.append(block)

        if redacted:
            filtered.append({
                "type": "text",
                "text": f"[{redacted} message(s) redacted by compliance filter]",
            })

        return {**response, "content": filtered}
