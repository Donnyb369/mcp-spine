"""Tests for the plugin system."""

from __future__ import annotations

import pytest

from spine.plugins import PluginBlockError, PluginConfig, PluginManager, SpinePlugin


class EchoPlugin(SpinePlugin):
    """Test plugin that logs calls."""

    name = "echo"

    def __init__(self):
        self.calls = []
        self.responses = []
        self.started = False
        self.stopped = False

    def on_startup(self, config):
        self.started = True

    def on_tool_call(self, tool_name, arguments):
        self.calls.append((tool_name, arguments))
        return None  # pass through

    def on_tool_response(self, tool_name, arguments, response):
        self.responses.append((tool_name, response))
        return response

    def on_shutdown(self):
        self.stopped = True


class BlockPlugin(SpinePlugin):
    """Test plugin that blocks specific tools."""

    name = "blocker"
    blocked_tools = {"dangerous_tool"}

    def on_tool_call(self, tool_name, arguments):
        if tool_name in self.blocked_tools:
            raise PluginBlockError(f"Tool '{tool_name}' blocked by policy")
        return None


class ArgTransformPlugin(SpinePlugin):
    """Test plugin that transforms arguments."""

    name = "arg-transform"

    def on_tool_call(self, tool_name, arguments):
        if "path" in arguments:
            return {**arguments, "path": arguments["path"].upper()}
        return None


class ResponseFilterPlugin(SpinePlugin):
    """Test plugin that filters response content."""

    name = "response-filter"
    redact_keywords = ["secret", "password"]

    def on_tool_response(self, tool_name, arguments, response):
        if not isinstance(response, dict):
            return response
        content = response.get("content", [])
        if not isinstance(content, list):
            return response
        filtered = []
        for block in content:
            text = block.get("text", "") if isinstance(block, dict) else ""
            if not any(kw in text.lower() for kw in self.redact_keywords):
                filtered.append(block)
        return {**response, "content": filtered}


class TestPluginLifecycle:
    def test_startup_and_shutdown(self):
        plugin = EchoPlugin()
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [plugin]

        mgr.fire_startup({"test": True})
        assert plugin.started

        mgr.fire_shutdown()
        assert plugin.stopped

    def test_tool_call_passthrough(self):
        plugin = EchoPlugin()
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [plugin]

        args = {"path": "/test.txt"}
        result = mgr.fire_tool_call("read_file", args)
        assert result == args
        assert len(plugin.calls) == 1
        assert plugin.calls[0] == ("read_file", args)

    def test_tool_response_passthrough(self):
        plugin = EchoPlugin()
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [plugin]

        response = {"content": [{"type": "text", "text": "hello"}]}
        result = mgr.fire_tool_response("read_file", {}, response)
        assert result == response
        assert len(plugin.responses) == 1


class TestPluginBlocking:
    def test_block_tool_call(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [BlockPlugin()]

        with pytest.raises(PluginBlockError, match="blocked by policy"):
            mgr.fire_tool_call("dangerous_tool", {})

    def test_allowed_tool_passes(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [BlockPlugin()]

        result = mgr.fire_tool_call("safe_tool", {"x": 1})
        assert result == {"x": 1}


class TestPluginArgTransform:
    def test_transforms_arguments(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [ArgTransformPlugin()]

        result = mgr.fire_tool_call("read_file", {"path": "/test.txt"})
        assert result["path"] == "/TEST.TXT"

    def test_no_transform_without_path(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [ArgTransformPlugin()]

        result = mgr.fire_tool_call("list_tools", {"query": "search"})
        assert result == {"query": "search"}


class TestPluginResponseFilter:
    def test_filters_sensitive_content(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [ResponseFilterPlugin()]

        response = {
            "content": [
                {"type": "text", "text": "Normal message"},
                {"type": "text", "text": "Contains secret data"},
                {"type": "text", "text": "Also has password in it"},
            ]
        }
        result = mgr.fire_tool_response("slack_search", {}, response)
        assert len(result["content"]) == 1
        assert result["content"][0]["text"] == "Normal message"

    def test_no_filter_on_clean_content(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [ResponseFilterPlugin()]

        response = {
            "content": [
                {"type": "text", "text": "Hello world"},
                {"type": "text", "text": "All good here"},
            ]
        }
        result = mgr.fire_tool_response("read_file", {}, response)
        assert len(result["content"]) == 2


class TestPluginChaining:
    def test_multiple_plugins_chain(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        echo = EchoPlugin()
        transform = ArgTransformPlugin()
        mgr.plugins = [echo, transform]

        result = mgr.fire_tool_call("read_file", {"path": "/test.txt"})
        assert result["path"] == "/TEST.TXT"
        assert len(echo.calls) == 1

    def test_blocker_stops_chain(self):
        mgr = PluginManager(PluginConfig(enabled=True))
        echo = EchoPlugin()
        blocker = BlockPlugin()
        mgr.plugins = [blocker, echo]

        with pytest.raises(PluginBlockError):
            mgr.fire_tool_call("dangerous_tool", {})
        # Echo should not have been called
        assert len(echo.calls) == 0


class TestPluginToolList:
    def test_tool_list_hook(self):
        class ToolHider(SpinePlugin):
            name = "tool-hider"

            def on_tool_list(self, tools):
                return [t for t in tools if t.get("name") != "hidden_tool"]

        mgr = PluginManager(PluginConfig(enabled=True))
        mgr.plugins = [ToolHider()]

        tools = [
            {"name": "read_file", "description": "Read a file"},
            {"name": "hidden_tool", "description": "Should be hidden"},
            {"name": "write_file", "description": "Write a file"},
        ]
        result = mgr.fire_tool_list(tools)
        assert len(result) == 2
        assert all(t["name"] != "hidden_tool" for t in result)


class TestPluginDiscovery:
    def test_load_from_directory(self, tmp_path):
        plugin_file = tmp_path / "test_plugin.py"
        plugin_file.write_text(
            "from spine.plugins import SpinePlugin\n\n"
            "class MyPlugin(SpinePlugin):\n"
            "    name = 'my-test-plugin'\n"
        )

        config = PluginConfig(enabled=True, directory=str(tmp_path))
        mgr = PluginManager(config)
        count = mgr.discover_and_load()
        assert count == 1
        assert mgr.plugins[0].name == "my-test-plugin"

    def test_skip_underscore_files(self, tmp_path):
        (tmp_path / "_internal.py").write_text(
            "from spine.plugins import SpinePlugin\n\n"
            "class Internal(SpinePlugin):\n"
            "    name = 'internal'\n"
        )

        config = PluginConfig(enabled=True, directory=str(tmp_path))
        mgr = PluginManager(config)
        count = mgr.discover_and_load()
        assert count == 0

    def test_deny_list(self, tmp_path):
        plugin_file = tmp_path / "blocked.py"
        plugin_file.write_text(
            "from spine.plugins import SpinePlugin\n\n"
            "class Blocked(SpinePlugin):\n"
            "    name = 'blocked-plugin'\n"
        )

        config = PluginConfig(
            enabled=True,
            directory=str(tmp_path),
            deny_list=["blocked-plugin"],
        )
        mgr = PluginManager(config)
        count = mgr.discover_and_load()
        assert count == 0

    def test_disabled_skips_loading(self, tmp_path):
        plugin_file = tmp_path / "plugin.py"
        plugin_file.write_text(
            "from spine.plugins import SpinePlugin\n\n"
            "class MyPlugin(SpinePlugin):\n"
            "    name = 'test'\n"
        )

        config = PluginConfig(enabled=False, directory=str(tmp_path))
        mgr = PluginManager(config)
        count = mgr.discover_and_load()
        assert count == 0

    def test_missing_directory(self):
        config = PluginConfig(enabled=True, directory="/nonexistent/path")
        mgr = PluginManager(config)
        count = mgr.discover_and_load()
        assert count == 0
