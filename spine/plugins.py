"""
MCP Spine — Plugin System

Plugins are Python classes that hook into Spine's tool call pipeline.
They can transform arguments before a call, filter or modify responses
after a call, or block calls entirely.

Usage:
    1. Create a .py file in your plugins directory
    2. Define a class that inherits from SpinePlugin
    3. Override the hooks you need
    4. Add [plugins] config to spine.toml

Example plugin (plugins/slack_filter.py):

    from spine.plugins import SpinePlugin

    class SlackFilter(SpinePlugin):
        name = "slack-filter"
        deny_channels = ["hr-private", "exec-salary"]

        def on_tool_response(self, tool_name, arguments, response):
            if "slack" not in tool_name:
                return response
            # Filter out messages from denied channels
            content = response.get("content", [])
            filtered = []
            for block in content:
                text = block.get("text", "")
                if not any(ch in text for ch in self.deny_channels):
                    filtered.append(block)
            return {**response, "content": filtered}

Config (spine.toml):

    [plugins]
    enabled = true
    directory = "plugins"
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SpinePlugin:
    """
    Base class for Spine plugins.

    Override any of the hook methods to intercept the tool call pipeline.
    All hooks are optional — only implement what you need.
    """

    name: str = "unnamed-plugin"

    def on_startup(self, config: Any) -> None:
        """Called once when Spine starts. Use for initialization."""

    def on_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        """
        Called before a tool call is routed to a server.

        Args:
            tool_name: The tool being called
            arguments: The call arguments

        Returns:
            - Modified arguments dict to proceed with changed args
            - None to proceed with original arguments
            - Raise PluginBlockError to block the call entirely
        """
        return None

    def on_tool_response(
        self, tool_name: str, arguments: dict[str, Any], response: Any
    ) -> Any:
        """
        Called after a tool response is received, before it reaches the LLM.

        Args:
            tool_name: The tool that was called
            arguments: The original call arguments
            response: The tool response payload

        Returns:
            Modified response, or the original response unchanged.
        """
        return response

    def on_tool_list(self, tools: list[dict]) -> list[dict]:
        """
        Called when tools/list is requested, after routing and minification.

        Args:
            tools: List of tool schema dicts

        Returns:
            Modified tools list (e.g., add/remove/rename tools).
        """
        return tools

    def on_shutdown(self) -> None:
        """Called when Spine shuts down. Use for cleanup."""


class PluginBlockError(Exception):
    """Raise in on_tool_call to block a tool call with a message."""

    def __init__(self, message: str = "Blocked by plugin"):
        self.message = message
        super().__init__(message)


@dataclass
class PluginConfig:
    """Plugin system configuration."""
    enabled: bool = False
    directory: str = "plugins"
    allow_list: list[str] = field(default_factory=list)
    deny_list: list[str] = field(default_factory=list)


class PluginManager:
    """
    Discovers, loads, and manages Spine plugins.

    Plugins are loaded from .py files in the configured directory.
    Each file can contain one or more SpinePlugin subclasses.
    """

    def __init__(self, config: PluginConfig, logger: Any = None):
        self.config = config
        self.logger = logger
        self.plugins: list[SpinePlugin] = []

    def discover_and_load(self) -> int:
        """
        Scan the plugin directory and load all valid plugins.

        Returns the number of plugins loaded.
        """
        if not self.config.enabled:
            return 0

        plugin_dir = Path(self.config.directory)
        if not plugin_dir.is_dir():
            if self.logger:
                self.logger.warn(
                    "startup",
                    component="plugins",
                    message=f"Plugin directory not found: {plugin_dir}",
                )
            return 0

        loaded = 0
        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            try:
                plugins = self._load_file(py_file)
                for plugin in plugins:
                    if self._is_allowed(plugin):
                        self.plugins.append(plugin)
                        loaded += 1
                        if self.logger:
                            self.logger.info(
                                "startup",
                                component="plugins",
                                message=f"Loaded plugin: {plugin.name} from {py_file.name}",
                            )
                    else:
                        if self.logger:
                            self.logger.warn(
                                "startup",
                                component="plugins",
                                message=f"Plugin {plugin.name} blocked by allow/deny list",
                            )
            except Exception as e:
                if self.logger:
                    self.logger.error(
                        "startup",
                        component="plugins",
                        message=f"Failed to load {py_file.name}: {e}",
                    )

        return loaded

    def _load_file(self, path: Path) -> list[SpinePlugin]:
        """Load all SpinePlugin subclasses from a Python file."""
        spec = importlib.util.spec_from_file_location(
            f"spine_plugin_{path.stem}", str(path)
        )
        if spec is None or spec.loader is None:
            return []

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        plugins = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, SpinePlugin)
                and attr is not SpinePlugin
            ):
                plugins.append(attr())

        return plugins

    def _is_allowed(self, plugin: SpinePlugin) -> bool:
        """Check if a plugin passes the allow/deny list."""
        if self.config.deny_list and plugin.name in self.config.deny_list:
            return False
        if self.config.allow_list and plugin.name not in self.config.allow_list:
            return False
        return True

    def fire_startup(self, config: Any) -> None:
        """Fire on_startup for all loaded plugins."""
        for plugin in self.plugins:
            try:
                plugin.on_startup(config)
            except Exception:
                pass

    def fire_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Fire on_tool_call for all plugins. Returns final arguments.

        Raises PluginBlockError if any plugin blocks the call.
        """
        current_args = arguments
        for plugin in self.plugins:
            try:
                result = plugin.on_tool_call(tool_name, current_args)
                if result is not None:
                    current_args = result
            except PluginBlockError:
                raise
            except Exception:
                pass
        return current_args

    def fire_tool_response(
        self, tool_name: str, arguments: dict[str, Any], response: Any
    ) -> Any:
        """Fire on_tool_response for all plugins. Returns final response."""
        current = response
        for plugin in self.plugins:
            try:
                current = plugin.on_tool_response(tool_name, arguments, current)
            except Exception:
                pass
        return current

    def fire_tool_list(self, tools: list[dict]) -> list[dict]:
        """Fire on_tool_list for all plugins. Returns final tools list."""
        current = tools
        for plugin in self.plugins:
            try:
                current = plugin.on_tool_list(current)
            except Exception:
                pass
        return current

    def fire_shutdown(self) -> None:
        """Fire on_shutdown for all loaded plugins."""
        for plugin in self.plugins:
            try:
                plugin.on_shutdown()
            except Exception:
                pass
