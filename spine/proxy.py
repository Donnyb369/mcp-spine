"""
MCP Spine — Core Proxy

The main event loop that sits between the LLM client and downstream
MCP servers. Intercepts all JSON-RPC traffic and applies:
  - Security validation (message size, tool policies, path guards)
  - Rate limiting
  - Tool routing
  - Secret scrubbing
  - Audit logging

Stages 1-4 are wired together:
  1. Dumb Proxy with security hardening
  2. Semantic Router (local embeddings via ChromaDB)
  3. Schema Minifier (progressive JSON pruning)
  4. State Guard (file truth pinning via SHA-256 manifest)
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from typing import Any

from spine.audit import AuditLogger, EventType, LogLevel
from spine.config import SpineConfig
from spine.minifier import SchemaMinifier
from spine.protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    RATE_LIMITED,
    TOOL_BLOCKED,
    TOOL_NOT_FOUND,
    ProtocolError,
    make_error,
    make_response,
    read_jsonrpc,
    write_jsonrpc,
)
from spine.security import (
    RateLimiter,
    ValidationError,
    contains_secret,
    scrub_secrets,
)
from spine.state_guard import StateGuard
from spine.transport import ServerPool


class SpineProxy:
    """
    The MCP Spine proxy core.

    Reads MCP messages from stdin (from the LLM client),
    processes them through security and routing layers,
    and writes responses to stdout.
    """

    def __init__(self, config: SpineConfig):
        self.config = config
        self.logger = AuditLogger(
            db_path=config.audit_db,
            level=LogLevel[config.log_level.upper()],
            scrub=config.security.scrub_secrets_in_logs,
        )
        self.pool = ServerPool(config.servers, self.logger)
        self.rate_limiter = RateLimiter(
            default_max_calls=config.security.per_tool_rate_limit,
            default_window=60.0,
        )
        self._global_call_count = 0
        self._global_window_start = time.monotonic()
        self._running = False

        # Stage 2: Semantic Router
        self._router = None
        try:
            from spine.router import SemanticRouter
            self._router = SemanticRouter(
                model_name=config.routing.embedding_model,
                max_tools=config.routing.max_tools,
                similarity_threshold=config.routing.similarity_threshold,
                always_include=config.routing.always_include,
                rerank=config.routing.rerank,
                logger=self.logger,
            )
        except ImportError:
            self.logger.warn(
                EventType.STARTUP,
                component="router",
                message="ML deps not found, semantic routing disabled",
            )

        # Stage 3: Schema Minifier
        self._minifier = SchemaMinifier(
            level=config.minifier.level,
            max_description_length=config.minifier.max_description_length,
            preserve_required=config.minifier.preserve_required,
        )

        # Stage 4: State Guard
        self._state_guard = None
        if config.state_guard.enabled:
            self._state_guard = StateGuard(
                watch_paths=config.state_guard.watch_paths,
                ignore_patterns=config.state_guard.ignore_patterns,
                max_tracked_files=config.state_guard.max_tracked_files,
                max_pin_files=config.state_guard.max_pin_files,
                snippet_length=config.state_guard.snippet_length,
            )

        # Human-in-the-loop: pending confirmations
        self._pending_confirmations: dict[str, dict] = {}
        self._confirmation_counter = 0

    async def start(self) -> None:
        """Start the proxy: enter message loop immediately, init servers in background."""
        self.logger.info(
            EventType.STARTUP,
            version="0.1.0",
            server_count=len(self.config.servers),
            security_scrub=self.config.security.scrub_secrets_in_logs,
            security_audit=self.config.security.audit_all_tool_calls,
        )

        # Enter main proxy loop FIRST — respond to initialize immediately.
        # Heavy initialization (server connections, ML model loading)
        # happens in the background so we don't miss Claude's handshake.
        self._running = True
        self._ready = False  # True once servers are connected

        # Start background initialization
        asyncio.create_task(
            self._background_init(),
            name="spine-init",
        )

        # Start file watcher in background
        if self._state_guard:
            asyncio.create_task(
                self._state_guard.start_watching(),
                name="state-guard-watcher",
            )
            self.logger.info(
                EventType.STARTUP,
                component="state_guard",
                watch_paths=self.config.state_guard.watch_paths,
            )

        # Enter main proxy loop
        self._running = True

        # Cross-platform stdio: read from stdin in a thread,
        # write to stdout directly. Works on both Unix and Windows.
        import threading

        read_queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def _stdin_reader():
            """Background thread: read lines from stdin and push to queue."""
            try:
                for line in sys.stdin.buffer:
                    if not self._running:
                        break
                    loop.call_soon_threadsafe(read_queue.put_nowait, line)
            except (EOFError, OSError):
                pass
            finally:
                loop.call_soon_threadsafe(read_queue.put_nowait, None)

        reader_thread = threading.Thread(target=_stdin_reader, daemon=True)
        reader_thread.start()

        try:
            while self._running:
                line = await read_queue.get()
                if line is None:
                    break  # EOF

                line = line.strip()
                if not line:
                    continue

                # Validate size
                try:
                    from spine.security import validate_message_size
                    validate_message_size(line)
                except ValidationError as e:
                    self.logger.error(EventType.VALIDATION_ERROR, error=str(e))
                    self._write_error(None, INVALID_PARAMS, str(e))
                    continue

                # Parse JSON
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as e:
                    self.logger.error(EventType.VALIDATION_ERROR, error=f"Invalid JSON: {e}")
                    self._write_error(None, INVALID_PARAMS, f"Invalid JSON: {e}")
                    continue

                # Validate JSON-RPC structure
                try:
                    from spine.security import validate_message as _validate
                    _validate(message)
                except ValidationError as e:
                    self.logger.error(EventType.VALIDATION_ERROR, error=f"Invalid JSON-RPC: {e}")
                    msg_id = message.get("id") if isinstance(message, dict) else None
                    self._write_error(msg_id, INVALID_PARAMS, str(e))
                    continue

                response = await self._handle_message(message)
                if response is not None:
                    out = json.dumps(response, separators=(",", ":")) + "\n"
                    sys.stdout.buffer.write(out.encode())
                    sys.stdout.buffer.flush()

        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Gracefully shut down everything."""
        if not self._running:
            return
        self._running = False
        self.logger.info(EventType.SHUTDOWN)
        await self.pool.shutdown_all()
        self.logger.close()

    async def _background_init(self) -> None:
        """
        Heavy initialization that runs in the background.

        Two phases:
          1. Connect servers → set _ready as soon as ANY has tools (~5s)
          2. Load ML model → enable routing (slow, ~30s)

        tools/list and tools/call wait for phase 1 only.
        Semantic routing activates silently when phase 2 completes.
        """
        try:
            # Start connecting all servers concurrently
            init_task = asyncio.create_task(self.pool.start_all())

            # Poll until at least one server has tools
            for _ in range(300):  # 60 seconds max
                await asyncio.sleep(0.2)
                if self.pool.all_tools():
                    break

            # Mark ready as soon as any tools are available
            self._ready = True
            tool_count = len(self.pool.all_tools())
            self.logger.info(
                EventType.STARTUP,
                message=f"Tools available ({tool_count} tools), accepting requests",
            )

            # Wait for remaining servers to finish connecting
            await init_task

            # Log final tool count (may be higher now)
            final_count = len(self.pool.all_tools())
            if final_count > tool_count:
                self.logger.info(
                    EventType.STARTUP,
                    message=f"All servers connected ({final_count} tools total)",
                )
                # Notify Claude that new tools are available
                self._send_notification("notifications/tools/list_changed")

            # Phase 2: Load ML model in background (slow, non-blocking)
            if self._router:
                asyncio.create_task(
                    self._load_router(),
                    name="spine-router-load",
                )

        except Exception as e:
            self.logger.error(
                EventType.STARTUP,
                error=f"Background init failed: {e}",
            )
            self._ready = True

    async def _load_router(self) -> None:
        """Load the semantic router ML model in the background."""
        try:
            all_tools = self.pool.all_tools()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, self._router.index_tools, all_tools
            )
            self.logger.info(
                EventType.STARTUP,
                component="router",
                message="Semantic routing enabled",
                indexed=self._router.indexed_count,
            )
        except ImportError:
            self.logger.warn(
                EventType.STARTUP,
                component="router",
                message="ML deps not installed, semantic routing disabled. "
                        "Install with: pip install mcp-spine[ml]",
            )
            self._router = None
        except Exception as e:
            self.logger.warn(
                EventType.STARTUP,
                component="router",
                message=f"Router init failed: {e}. Semantic routing disabled.",
            )
            self._router = None

    async def _wait_for_ready(self, timeout: float = 120.0) -> None:
        """Wait for background initialization to complete."""
        waited = 0.0
        while not self._ready and waited < timeout:
            await asyncio.sleep(0.2)
            waited += 0.2

    def _write_error(self, msg_id: int | str | None, code: int, message: str) -> None:
        """Write a JSON-RPC error directly to stdout."""
        resp = make_error(msg_id, code, message)
        out = json.dumps(resp, separators=(",", ":")) + "\n"
        sys.stdout.buffer.write(out.encode())
        sys.stdout.buffer.flush()

    def _send_notification(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification to the client (no id, no response expected)."""
        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            notification["params"] = params
        out = json.dumps(notification, separators=(",", ":")) + "\n"
        sys.stdout.buffer.write(out.encode())
        sys.stdout.buffer.flush()

    async def _handle_message(
        self, message: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Central message dispatcher.

        Returns a JSON-RPC response dict, or None for notifications.
        """
        msg_id = message.get("id")
        method = message.get("method")

        # Notifications (no id) — log and pass through
        if msg_id is None:
            return None

        try:
            match method:
                case "initialize":
                    return await self._handle_initialize(msg_id, message)
                case "tools/list":
                    return await self._handle_tools_list(msg_id, message)
                case "tools/call":
                    return await self._handle_tools_call(msg_id, message)
                case "resources/list" | "resources/read" | "prompts/list" | "prompts/get":
                    return await self._relay_to_all(msg_id, method, message)
                case _:
                    return make_error(
                        msg_id, METHOD_NOT_FOUND,
                        f"Method not found: {method}"
                    )
        except Exception as e:
            self.logger.error(
                EventType.TOOL_CALL,
                method=method,
                error=str(e),
            )
            return make_error(msg_id, INTERNAL_ERROR, str(e))

    async def _handle_initialize(
        self, msg_id: int | str, message: dict
    ) -> dict:
        """Handle MCP initialize handshake."""
        return make_response(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {},
            },
            "serverInfo": {
                "name": "mcp-spine",
                "version": "0.1.0",
            },
        })

    async def _handle_tools_list(
        self, msg_id: int | str, message: dict
    ) -> dict:
        """
        Handle tools/list — the key interception point.

        Waits for background init if servers aren't connected yet.
        Stage 1: Return all tools from all servers
        Stage 2+: Semantic routing filters to top-K
        Stage 3+: Schema minification reduces token count
        """
        # Wait for servers to be ready (background init)
        await self._wait_for_ready()

        all_tools = self.pool.all_tools()

        # Stage 2: Semantic routing — filter to top-K relevant tools
        if self._router:
            # Try to extract context from the message
            context = self._extract_context(message)
            if context:
                all_tools = self._router.route(context, all_tools)

        # Stage 3: Schema minification — reduce token count
        if self._minifier and self._minifier.level > 0:
            all_tools = self._minifier.minify_batch(all_tools)

        # Filter by security policy
        allowed_tools = [
            t for t in all_tools
            if self.config.security.is_tool_allowed(t["name"])
        ]

        # Inject spine_set_context meta-tool if not already present
        tool_names = {t["name"] for t in allowed_tools}
        if "spine_set_context" not in tool_names:
            allowed_tools.append(self._get_spine_meta_tool())

        # Inject confirmation meta-tools if any tool policies use require_confirmation
        has_confirmation_tools = any(
            tp.require_confirmation for tp in self.config.security.tool_policies
        )
        if has_confirmation_tools:
            for meta_tool in self._get_confirmation_meta_tools():
                if meta_tool["name"] not in tool_names:
                    allowed_tools.append(meta_tool)

        # Strip internal metadata before sending to client
        clean_tools = [self._clean_tool(t) for t in allowed_tools]

        self.logger.info(
            EventType.TOOL_LIST,
            total=len(all_tools),
            filtered=len(clean_tools),
        )

        return make_response(msg_id, {"tools": clean_tools})

    async def _handle_tools_call(
        self, msg_id: int | str, message: dict
    ) -> dict:
        """
        Handle tools/call — route to the correct downstream server.

        Waits for background init if servers aren't connected yet.
        Security checks applied:
          1. Policy check (is this tool allowed?)
          2. Rate limiting (per-tool and global)
          3. Path validation (if tool args contain file paths)
          4. Secret scrubbing (in responses, if enabled)
          5. Audit logging (always)
        """
        # Wait for servers to be ready (background init)
        await self._wait_for_ready()

        params = message.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # ── Security Check 1: Policy ──
        if not self.config.security.is_tool_allowed(tool_name):
            self.logger.security(
                EventType.POLICY_DENY,
                tool_name=tool_name,
                reason="Blocked by security policy",
            )
            return make_error(msg_id, TOOL_BLOCKED, f"Tool '{tool_name}' is blocked by policy")

        # ── Security Check 2: Rate Limiting ──
        if not self._check_global_rate_limit():
            self.logger.security(
                EventType.RATE_LIMITED,
                tool_name=tool_name,
                reason="Global rate limit exceeded",
            )
            return make_error(msg_id, RATE_LIMITED, "Global rate limit exceeded")

        if not self.rate_limiter.check(tool_name):
            self.logger.security(
                EventType.RATE_LIMITED,
                tool_name=tool_name,
                remaining=self.rate_limiter.remaining(tool_name),
            )
            return make_error(
                msg_id, RATE_LIMITED,
                f"Rate limit exceeded for tool '{tool_name}'"
            )

        # ── Security Check 3: Path Validation ──
        self._check_path_args(tool_name, arguments)

        # ── Security Check 4: Secret Detection in arguments ──
        args_str = json.dumps(arguments)
        if contains_secret(args_str):
            self.logger.security(
                EventType.SECRET_DETECTED,
                tool_name=tool_name,
                context="tool_call_arguments",
            )
            # We log but don't block — the secret might be intentional
            # (e.g., setting a token in a config file)

        # ── Handle spine_set_context meta-tool ──
        if tool_name == "spine_set_context":
            return await self._handle_set_context(msg_id, arguments)

        # ── Handle spine_confirm meta-tool ──
        if tool_name == "spine_confirm":
            return await self._handle_confirm(msg_id, arguments)

        # ── Handle spine_deny meta-tool ──
        if tool_name == "spine_deny":
            return await self._handle_deny(msg_id, arguments)

        # ── Security Check 5: Human-in-the-loop ──
        policy = self.config.security.get_tool_policy(tool_name)
        if policy and policy.require_confirmation:
            return self._request_confirmation(msg_id, tool_name, arguments, message)

        # ── Route to downstream server ──
        server = self.pool.route_tool(tool_name)
        if server is None:
            return make_error(
                msg_id, TOOL_NOT_FOUND,
                f"No server available for tool '{tool_name}'"
            )

        # ── Execute with timing ──
        with self.logger.timed(
            EventType.TOOL_CALL,
            tool_name=tool_name,
            server_name=server.name,
        ) as ctx:
            result = await server.call_tool(tool_name, arguments)

        # ── Security Check 5: Scrub secrets in response ──
        if self.config.security.scrub_secrets_in_responses:
            result = self._scrub_response(result)

        # Stage 2: Record tool usage for recency-based reranking
        if self._router:
            self._router.record_tool_call(tool_name)

        # Stage 4: Inject state pin into response
        if self._state_guard:
            result = self._state_guard.inject_pin_into_response(result)

        # ── Audit Log ──
        self.logger.info(
            EventType.TOOL_RESPONSE,
            tool_name=tool_name,
            server_name=server.name,
            success="error" not in result,
        )

        return make_response(msg_id, result.get("result", result))

    def _check_global_rate_limit(self) -> bool:
        """Check global rate limit across all tools."""
        now = time.monotonic()
        if now - self._global_window_start > 60.0:
            self._global_call_count = 0
            self._global_window_start = now
        self._global_call_count += 1
        return self._global_call_count <= self.config.security.global_rate_limit

    def _check_path_args(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> None:
        """
        Scan tool arguments for file paths and validate them.

        Logs a security event if a path violation is detected.
        Does NOT block the call (the downstream server has its own guards),
        but creates an audit trail.
        """
        path_keys = {"path", "file_path", "filepath", "filename", "directory", "dir"}
        for key, value in arguments.items():
            if key.lower() in path_keys and isinstance(value, str):
                if not self.config.security.path_policy.is_path_allowed(value):
                    self.logger.security(
                        EventType.PATH_VIOLATION,
                        tool_name=tool_name,
                        path=value,
                        reason="Path matches denied pattern",
                    )

    def _scrub_response(self, result: dict) -> dict:
        """Deep-scrub secrets from a tool response."""
        return json.loads(scrub_secrets(json.dumps(result)))

    def _clean_tool(self, tool: dict) -> dict:
        """Remove internal spine metadata from a tool before sending to client."""
        clean = {k: v for k, v in tool.items() if not k.startswith("_spine_")}
        return clean

    async def _relay_to_all(
        self, msg_id: int | str, method: str, message: dict
    ) -> dict:
        """Relay a request to all servers and merge results."""
        await self._wait_for_ready()

        # For resources/list, prompts/list — aggregate from all servers
        results = []
        for server_name, server in self.pool._servers.items():
            if not server.is_available:
                continue
            try:
                resp = await server.send_request(method, message.get("params"))
                result = resp.get("result", {})
                if isinstance(result, dict):
                    # Merge list fields
                    for key in ("resources", "prompts"):
                        if key in result:
                            results.extend(result[key])
                elif isinstance(result, list):
                    results.extend(result)
            except Exception:
                continue

        # Determine result key from method
        result_key = method.split("/")[0]  # "resources", "prompts"
        return make_response(msg_id, {result_key: results})

    def _extract_context(self, message: dict[str, Any]) -> str | None:
        """
        Try to extract the user's current intent from a message.

        Looks for context hints in params or cursor metadata.
        """
        params = message.get("params", {})

        # Check for explicit context hint
        if "context" in params:
            return params["context"]

        # Check for cursor/meta from the client
        meta = params.get("_meta", {})
        if "context" in meta:
            return meta["context"]

        return None

    async def _handle_set_context(
        self, msg_id: int | str, arguments: dict[str, Any]
    ) -> dict:
        """
        Handle the spine_set_context meta-tool.

        The LLM calls this to explicitly declare what it's working on,
        triggering a re-route of visible tools.
        """
        task = arguments.get("task", "")
        if not task:
            return make_error(
                msg_id, INVALID_PARAMS,
                "spine_set_context requires a 'task' argument"
            )

        tools = []
        if self._router:
            tools = self._router.set_context(task)

        self.logger.info(
            EventType.TOOL_ROUTED,
            tool_name="spine_set_context",
            context=task[:100],
            routed_tools=[t["name"] for t in tools],
        )

        return make_response(msg_id, {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Context updated. {len(tools)} tools are now "
                        f"available for: {task}"
                    ),
                }
            ],
        })

    def _get_spine_meta_tool(self) -> dict[str, Any]:
        """Return the spine_set_context meta-tool definition."""
        return {
            "name": "spine_set_context",
            "description": (
                "Tell the Spine what you are currently working on. "
                "This re-routes which tools are visible to you based "
                "on your current task."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "Description of your current task",
                    }
                },
                "required": ["task"],
            },
        }

    def _get_confirmation_meta_tools(self) -> list[dict[str, Any]]:
        """Return the spine_confirm and spine_deny meta-tool definitions."""
        return [
            {
                "name": "spine_confirm",
                "description": (
                    "Confirm a pending tool call that requires human approval. "
                    "The user must approve before the tool executes. "
                    "Call this with the confirmation_id after the user says yes."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "confirmation_id": {
                            "type": "string",
                            "description": "The confirmation ID from the pending request",
                        }
                    },
                    "required": ["confirmation_id"],
                },
            },
            {
                "name": "spine_deny",
                "description": (
                    "Deny a pending tool call that requires human approval. "
                    "Call this if the user says no or wants to cancel."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "confirmation_id": {
                            "type": "string",
                            "description": "The confirmation ID to deny",
                        }
                    },
                    "required": ["confirmation_id"],
                },
            },
        ]

    def _request_confirmation(
        self, msg_id: int | str, tool_name: str,
        arguments: dict[str, Any], original_message: dict
    ) -> dict:
        """
        Intercept a tool call that requires confirmation.

        Stores the pending call and returns a message asking
        the LLM to get user approval before proceeding.
        """
        self._confirmation_counter += 1
        conf_id = f"confirm_{self._confirmation_counter}"

        self._pending_confirmations[conf_id] = {
            "tool_name": tool_name,
            "arguments": arguments,
            "original_message": original_message,
            "msg_id": msg_id,
        }

        self.logger.security(
            EventType.POLICY_DENY,
            tool_name=tool_name,
            reason=f"Requires confirmation (id={conf_id})",
        )

        # Format arguments for display
        args_display = json.dumps(arguments, indent=2)

        return make_response(msg_id, {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"⚠️ CONFIRMATION REQUIRED\n\n"
                        f"Tool: {tool_name}\n"
                        f"Arguments:\n{args_display}\n\n"
                        f"This tool requires human approval before executing.\n"
                        f"Please ask the user to confirm, then call spine_confirm "
                        f"with confirmation_id=\"{conf_id}\" to proceed, "
                        f"or spine_deny to cancel."
                    ),
                }
            ],
        })

    async def _handle_confirm(
        self, msg_id: int | str, arguments: dict[str, Any]
    ) -> dict:
        """Execute a previously pending tool call after confirmation."""
        conf_id = arguments.get("confirmation_id", "")

        if conf_id not in self._pending_confirmations:
            return make_error(
                msg_id, INVALID_PARAMS,
                f"No pending confirmation with id '{conf_id}'. "
                f"It may have expired or already been processed."
            )

        pending = self._pending_confirmations.pop(conf_id)

        self.logger.info(
            EventType.TOOL_CALL,
            tool_name=pending["tool_name"],
            confirmation_id=conf_id,
            action="confirmed",
        )

        # Route to the downstream server
        server = self.pool.route_tool(pending["tool_name"])
        if server is None:
            return make_error(
                msg_id, TOOL_NOT_FOUND,
                f"No server available for tool '{pending['tool_name']}'"
            )

        # Execute the original call
        with self.logger.timed(
            EventType.TOOL_CALL,
            tool_name=pending["tool_name"],
            confirmed=True,
        ):
            result = await server.send_request(
                "tools/call", pending["original_message"].get("params")
            )

        response_result = result.get("result", result)

        # Apply state guard pin if needed
        if self._state_guard:
            response_result = self._state_guard.inject_pin(response_result)

        return make_response(msg_id, response_result)

    async def _handle_deny(
        self, msg_id: int | str, arguments: dict[str, Any]
    ) -> dict:
        """Cancel a previously pending tool call."""
        conf_id = arguments.get("confirmation_id", "")

        if conf_id not in self._pending_confirmations:
            return make_error(
                msg_id, INVALID_PARAMS,
                f"No pending confirmation with id '{conf_id}'."
            )

        pending = self._pending_confirmations.pop(conf_id)

        self.logger.info(
            EventType.TOOL_CALL,
            tool_name=pending["tool_name"],
            confirmation_id=conf_id,
            action="denied",
        )

        return make_response(msg_id, {
            "content": [
                {
                    "type": "text",
                    "text": f"Tool call '{pending['tool_name']}' was denied by the user.",
                }
            ],
        })
