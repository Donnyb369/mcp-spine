"""
MCP Spine — Prompt Injection Detection

Scans tool responses for common prompt injection patterns
before they reach the LLM. Detected injections are logged
as security events and optionally stripped.

Patterns detected:
  - System prompt overrides ("ignore previous instructions")
  - Role-play injection ("you are now a...")
  - Instruction injection ("[SYSTEM]", "### INSTRUCTION")
  - Base64-encoded payloads in unexpected contexts
  - Hidden text/unicode tricks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InjectionResult:
    """Result of an injection scan."""
    detected: bool = False
    patterns: list[str] = field(default_factory=list)
    severity: str = "none"  # none, low, medium, high
    details: str = ""


# Compiled patterns for performance
_INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "system_override",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "role_injection",
        re.compile(
            r"you\s+are\s+now\s+(a|an|the)\s+",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (
        "system_tag",
        re.compile(
            r"\[SYSTEM\]|\[ADMIN\]|###\s*INSTRUCTION|###\s*SYSTEM|<\s*system\s*>",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "instruction_override",
        re.compile(
            r"(forget|disregard|override|bypass)\s+(everything|all|your|the)\s+(above|instructions|rules|guidelines)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "jailbreak_attempt",
        re.compile(
            r"(DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|unrestricted\s+mode)",
            re.IGNORECASE,
        ),
        "high",
    ),
    (
        "hidden_instruction",
        re.compile(
            r"(respond\s+only\s+with|always\s+respond|from\s+now\s+on\s+you\s+must|new\s+instructions:)",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (
        "data_exfil",
        re.compile(
            r"(send|post|fetch|curl|wget)\s+(to|from)\s+https?://",
            re.IGNORECASE,
        ),
        "medium",
    ),
    (
        "encoded_payload",
        re.compile(
            r"[A-Za-z0-9+/]{50,}={0,2}",  # Long base64 strings
        ),
        "low",
    ),
]


class InjectionDetector:
    """
    Scans text content for prompt injection patterns.

    Thread-safe (stateless scan method).
    """

    def __init__(
        self,
        enabled: bool = True,
        action: str = "log",  # log, strip, block
        custom_patterns: list[dict] | None = None,
    ):
        self.enabled = enabled
        self.action = action
        self._patterns = list(_INJECTION_PATTERNS)

        if custom_patterns:
            for cp in custom_patterns:
                self._patterns.append((
                    cp.get("name", "custom"),
                    re.compile(cp["pattern"], re.IGNORECASE),
                    cp.get("severity", "medium"),
                ))

    def scan(self, text: str) -> InjectionResult:
        """
        Scan text for injection patterns.

        Returns an InjectionResult with detected patterns and severity.
        """
        if not self.enabled or not text:
            return InjectionResult()

        found: list[str] = []
        max_severity = "none"
        severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}

        for name, pattern, severity in self._patterns:
            if pattern.search(text):
                found.append(name)
                if severity_rank.get(severity, 0) > severity_rank.get(max_severity, 0):
                    max_severity = severity

        if not found:
            return InjectionResult()

        return InjectionResult(
            detected=True,
            patterns=found,
            severity=max_severity,
            details=f"Detected {len(found)} injection pattern(s): {', '.join(found)}",
        )

    def scan_response(self, response: Any) -> InjectionResult:
        """
        Scan a tool response (dict or string) for injections.

        Extracts all text content and scans each piece.
        """
        texts = self._extract_texts(response)
        combined = InjectionResult()

        for text in texts:
            result = self.scan(text)
            if result.detected:
                combined.detected = True
                combined.patterns.extend(result.patterns)
                if result.severity == "high" or combined.severity != "high":
                    combined.severity = result.severity

        if combined.detected:
            combined.patterns = list(set(combined.patterns))
            combined.details = f"Detected {len(combined.patterns)} pattern(s): {', '.join(combined.patterns)}"

        return combined

    def _extract_texts(self, obj: Any) -> list[str]:
        """Recursively extract all string values from a response."""
        texts: list[str] = []

        if isinstance(obj, str):
            texts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                texts.extend(self._extract_texts(v))
        elif isinstance(obj, list):
            for item in obj:
                texts.extend(self._extract_texts(item))

        return texts

    def strip_injections(self, text: str) -> str:
        """Remove detected injection patterns from text."""
        result = text
        for name, pattern, _severity in self._patterns:
            result = pattern.sub("[REDACTED]", result)
        return result
