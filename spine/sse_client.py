"""
MCP Spine — SSE Transport Client

Connects to remote MCP servers over HTTP/SSE (Server-Sent Events).
This enables the Spine to proxy cloud-hosted MCP servers alongside
local stdio servers.

SSE MCP protocol:
  - Client sends JSON-RPC requests via HTTP POST to the server's endpoint
  - Server streams responses back via SSE (text/event-stream)
  - The SSE stream carries JSON-RPC responses and notifications

Config example:
    [[servers]]
    name = "remote-tools"
    transport = "sse"
    url = "https://mcp.example.com/sse"
    headers = { Authorization = "Bearer token123" }
    timeout_seconds = 30
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urljoin

from spine.audit import AuditLogger, EventType


class SSEClient:
    """
    Async SSE client for MCP server communication.

    Uses stdlib urllib for HTTP — no external dependencies.
    Runs the SSE reader in a background thread to avoid blocking.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        logger: AuditLogger | None = None,
    ):
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._logger = logger
        self._connected = False
        self._session_url: str | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._request_id = 0

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        """
        Connect to the SSE endpoint.

        Opens the SSE stream and starts reading events in the background.
        The server should send an 'endpoint' event with the POST URL.
        """
        try:
            import urllib.request

            # Initial SSE connection
            req = urllib.request.Request(self._url)
            req.add_header("Accept", "text/event-stream")
            req.add_header("Cache-Control", "no-cache")
            for key, value in self._headers.items():
                req.add_header(key, value)

            loop = asyncio.get_event_loop()

            # Open connection in thread (blocking I/O)
            self._response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=self._timeout),
                ),
                timeout=self._timeout,
            )

            self._connected = True

            # Start reading SSE events in background
            self._reader_task = asyncio.create_task(
                self._read_sse_events(),
                name="sse-reader",
            )

            if self._logger:
                self._logger.info(
                    EventType.SERVER_CONNECT,
                    message=f"SSE connected to {self._url}",
                )

        except Exception as e:
            self._connected = False
            if self._logger:
                self._logger.error(
                    EventType.SERVER_CONNECT,
                    error=f"SSE connection failed: {e}",
                )
            raise

    async def _read_sse_events(self) -> None:
        """Read SSE events from the stream in a background thread."""
        loop = asyncio.get_event_loop()

        def _read_lines():
            """Blocking reader for SSE stream."""
            event_type = None
            data_lines = []

            try:
                for raw_line in self._response:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")

                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].strip())
                    elif line == "":
                        # Empty line = end of event
                        if data_lines:
                            data = "\n".join(data_lines)
                            loop.call_soon_threadsafe(
                                self._handle_event, event_type, data
                            )
                        event_type = None
                        data_lines = []
            except Exception:
                loop.call_soon_threadsafe(self._on_disconnect)

        await loop.run_in_executor(None, _read_lines)

    def _handle_event(self, event_type: str | None, data: str) -> None:
        """Handle an incoming SSE event."""
        if event_type == "endpoint":
            # Server tells us where to POST requests
            self._session_url = urljoin(self._url, data.strip())
            return

        if event_type == "message" or event_type is None:
            try:
                message = json.loads(data)
                msg_id = message.get("id")
                if msg_id is not None and msg_id in self._pending:
                    future = self._pending.pop(msg_id)
                    if not future.done():
                        future.set_result(message)
            except json.JSONDecodeError:
                pass

    def _on_disconnect(self) -> None:
        """Handle SSE stream disconnect."""
        self._connected = False
        # Fail all pending requests
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("SSE disconnected"))
        self._pending.clear()

    async def send_request(
        self, method: str, params: dict | None = None
    ) -> dict[str, Any]:
        """
        Send a JSON-RPC request via HTTP POST, wait for SSE response.
        """
        if not self._connected:
            raise ConnectionError("Not connected to SSE server")

        post_url = self._session_url or self._url

        self._request_id += 1
        msg_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
        }
        if params:
            request["params"] = params

        # Create future for response
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[msg_id] = future

        # POST request in thread
        try:
            import urllib.request

            body = json.dumps(request).encode("utf-8")
            req = urllib.request.Request(
                post_url,
                data=body,
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            for key, value in self._headers.items():
                req.add_header(key, value)

            await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=self._timeout),
            )
        except Exception as e:
            self._pending.pop(msg_id, None)
            raise ConnectionError(f"SSE POST failed: {e}") from e

        # Wait for response via SSE stream
        try:
            return await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise TimeoutError(
                f"SSE request timed out after {self._timeout}s: {method}"
            )

    async def close(self) -> None:
        """Close the SSE connection."""
        self._connected = False
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        try:
            self._response.close()
        except Exception:
            pass
        # Fail pending requests
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("Connection closed"))
        self._pending.clear()
