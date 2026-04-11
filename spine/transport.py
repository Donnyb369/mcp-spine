"""
MCP Spine — Transport Layer

Manages connections to downstream MCP servers as child processes.
Features:
  - Async subprocess management with graceful shutdown
  - Circuit breaker pattern (auto-disable failing servers)
  - Per-server timeouts
  - Secure command validation before spawn
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from spine.audit import AuditLogger, EventType, LogLevel
from spine.config import ServerConfig
from spine.protocol import (
    read_jsonrpc,
    write_jsonrpc,
)

# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreaker:
    """Simple circuit breaker: opens after N consecutive failures."""
    threshold: int = 3
    reset_after: float = 60.0  # seconds before attempting to close again

    _failure_count: int = 0
    _open_since: float | None = None

    @property
    def is_open(self) -> bool:
        if self._open_since is None:
            return False
        # Auto-reset after cooldown
        if time.monotonic() - self._open_since > self.reset_after:
            self._failure_count = 0
            self._open_since = None
            return False
        return True

    def record_success(self) -> None:
        self._failure_count = 0
        self._open_since = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.threshold:
            self._open_since = time.monotonic()


# ---------------------------------------------------------------------------
# Server Connection
# ---------------------------------------------------------------------------

class ServerConnection:
    """
    Manages a single downstream MCP server.

    Supports two transports:
      - stdio: local subprocess with stdin/stdout pipes
      - sse: remote HTTP/SSE server
    """

    def __init__(self, config: ServerConfig, logger: AuditLogger):
        self.config = config
        self.name = config.name
        self._logger = logger
        self._process: asyncio.subprocess.Process | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._circuit = CircuitBreaker(
            threshold=config.circuit_breaker_threshold,
        )
        self._tools: list[dict[str, Any]] = []
        self._tool_names: set[str] = set()
        self._request_id: int = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._sse_client = None  # SSEClient instance for SSE transport
        self._is_sse = config.transport == "sse"

    @property
    def is_available(self) -> bool:
        if self._is_sse:
            return self._sse_client is not None and self._sse_client.is_connected
        return (
            self._process is not None
            and self._process.returncode is None
            and not self._circuit.is_open
        )

    async def start(self) -> None:
        """Start the server connection (stdio subprocess or SSE client)."""
        if self._is_sse:
            await self._start_sse()
        else:
            await self._start_stdio()

    async def _start_sse(self) -> None:
        """Connect to a remote SSE MCP server."""
        self._logger.info(
            EventType.SERVER_CONNECT,
            server_name=self.name,
            transport="sse",
            url=self.config.url,
        )

        from spine.sse_client import SSEClient

        self._sse_client = SSEClient(
            url=self.config.url,
            headers=self.config.headers,
            timeout=self.config.timeout_seconds,
            logger=self._logger,
        )

        try:
            await self._sse_client.connect()
        except Exception as e:
            self._logger.error(
                EventType.SERVER_CONNECT,
                server_name=self.name,
                error=f"SSE connection failed: {e}",
            )
            raise

    async def _start_stdio(self) -> None:
        """Spawn the downstream server subprocess."""
        self._logger.info(
            EventType.SERVER_CONNECT,
            server_name=self.name,
            command=self.config.command,
            args=self.config.args,
        )

        # Resolve the command path — on Windows, npx is actually npx.cmd
        # and create_subprocess_exec can't find it without the full name.
        import shutil
        resolved_cmd = shutil.which(self.config.command)
        if resolved_cmd is None:
            self._logger.error(
                EventType.SERVER_CONNECT,
                server_name=self.name,
                error=f"Command not found: {self.config.command!r}. "
                      f"Make sure it is installed and on your PATH.",
            )
            raise FileNotFoundError(f"Command not found: {self.config.command}")

        try:
            self._process = await asyncio.create_subprocess_exec(
                resolved_cmd,
                *self.config.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.config.env or None,
            )
        except (FileNotFoundError, PermissionError, OSError) as e:
            self._logger.error(
                EventType.SERVER_CONNECT,
                server_name=self.name,
                error=str(e),
            )
            raise

        self._reader = self._process.stdout
        self._writer = self._process.stdin

        # Start background reader for responses
        self._reader_task = asyncio.create_task(
            self._read_loop(),
            name=f"reader-{self.name}",
        )

    async def _read_loop(self) -> None:
        """Background task: read responses from the server."""
        if not self._reader:
            return
        try:
            async for message in read_jsonrpc(self._reader):
                msg_id = message.get("id")
                if msg_id is not None and msg_id in self._pending:
                    self._pending[msg_id].set_result(message)
                # Notifications (no id) are logged but not routed
                elif msg_id is None:
                    self._logger.log(
                        EventType.TOOL_RESPONSE,
                        LogLevel.DEBUG,
                        server_name=self.name,
                        notification=message.get("method", "unknown"),
                    )
        except Exception as e:
            self._logger.error(
                EventType.SERVER_DISCONNECT,
                server_name=self.name,
                error=str(e),
            )
            # Fail all pending requests
            for future in self._pending.values():
                if not future.done():
                    future.set_exception(e)

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a JSON-RPC request and wait for the response."""
        if not self.is_available:
            raise ConnectionError(
                f"Server {self.name} is not available "
                f"(circuit: {'open' if self._circuit.is_open else 'closed'})"
            )

        # Route through SSE client if using SSE transport
        if self._is_sse:
            try:
                result = await self._sse_client.send_request(method, params)
                self._circuit.record_success()
                return result
            except Exception:
                self._circuit.record_failure()
                raise

        self._request_id += 1
        req_id = self._request_id

        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params

        # Create a future for the response
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[req_id] = future

        try:
            await write_jsonrpc(self._writer, message)

            # Wait with timeout
            result = await asyncio.wait_for(
                future, timeout=self.config.timeout_seconds
            )
            self._circuit.record_success()
            return result

        except asyncio.TimeoutError:
            self._circuit.record_failure()
            self._logger.warn(
                EventType.TOOL_CALL,
                server_name=self.name,
                method=method,
                error=f"Timeout after {self.config.timeout_seconds}s",
            )
            raise
        except Exception as e:
            self._circuit.record_failure()
            raise
        finally:
            self._pending.pop(req_id, None)

    async def initialize(self) -> dict[str, Any]:
        """Send MCP initialize handshake."""
        result = await self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-spine",
                "version": "0.1.0",
            },
        })

        # Send initialized notification
        if self._writer:
            await write_jsonrpc(self._writer, {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            })

        return result

    async def list_tools(self) -> list[dict[str, Any]]:
        """Fetch tools from this server."""
        result = await self.send_request("tools/list", {})
        tools = result.get("result", {}).get("tools", [])

        # Tag each tool with its source server
        for tool in tools:
            tool["_spine_server"] = self.name

        self._tools = tools
        self._tool_names = {t["name"] for t in tools}

        self._logger.info(
            EventType.TOOL_LIST,
            server_name=self.name,
            tool_count=len(tools),
        )

        return tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call a tool on this server."""
        return await self.send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self._tool_names

    async def shutdown(self) -> None:
        """Gracefully shut down the server connection."""
        self._logger.info(EventType.SERVER_DISCONNECT, server_name=self.name)

        if self._is_sse:
            if self._sse_client:
                await self._sse_client.close()
            return

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()


# ---------------------------------------------------------------------------
# Server Pool
# ---------------------------------------------------------------------------

class ServerPool:
    """
    Manages all downstream MCP server connections.

    Provides unified tool listing and routing.
    """

    def __init__(self, configs: list[ServerConfig], logger: AuditLogger):
        self._logger = logger
        self._servers: dict[str, ServerConnection] = {
            cfg.name: ServerConnection(cfg, logger)
            for cfg in configs
            if cfg.enabled
        }
        self._tool_to_server: dict[str, str] = {}

    async def start_all(self) -> None:
        """Start all configured servers concurrently."""
        async def _start_one(name: str, server: ServerConnection) -> None:
            try:
                await server.start()
                await server.initialize()
                tools = await server.list_tools()
                for tool in tools:
                    self._tool_to_server[tool["name"]] = name
            except Exception as e:
                self._logger.error(
                    EventType.SERVER_CONNECT,
                    server_name=name,
                    error=str(e),
                )

        # Start all servers concurrently — fast ones don't wait for slow ones
        await asyncio.gather(
            *[_start_one(name, server) for name, server in self._servers.items()],
            return_exceptions=True,
        )

    def all_tools(self) -> list[dict[str, Any]]:
        """Return all tools from all available servers."""
        tools = []
        for server in self._servers.values():
            if server.is_available:
                tools.extend(server._tools)
        return tools

    def route_tool(self, tool_name: str) -> ServerConnection | None:
        """Find which server owns a given tool."""
        server_name = self._tool_to_server.get(tool_name)
        if server_name and server_name in self._servers:
            server = self._servers[server_name]
            if server.is_available:
                return server
        return None

    async def refresh_tools(self) -> list[dict[str, Any]]:
        """Re-fetch tools from all servers (e.g. after schema changes)."""
        self._tool_to_server.clear()
        for server in self._servers.values():
            if server.is_available:
                try:
                    tools = await server.list_tools()
                    for tool in tools:
                        self._tool_to_server[tool["name"]] = server.name
                except Exception as e:
                    self._logger.warn(
                        EventType.TOOL_LIST,
                        server_name=server.name,
                        error=str(e),
                    )
        return self.all_tools()

    async def shutdown_all(self) -> None:
        """Gracefully shut down all servers."""
        for server in self._servers.values():
            try:
                await server.shutdown()
            except Exception as e:
                self._logger.error(
                    EventType.SERVER_DISCONNECT,
                    server_name=server.name,
                    error=str(e),
                )
