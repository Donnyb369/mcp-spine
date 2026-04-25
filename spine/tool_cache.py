"""
MCP Spine — Tool Response Cache

Caches responses from read-only tools to avoid redundant downstream
calls when the same tool is called with the same arguments.

Only tools listed in cacheable_tools are cached. Cache entries
expire after TTL seconds and are evicted LRU when max_entries
is reached.

Config example:
    [tool_cache]
    enabled = true
    cacheable_tools = ["read_file", "read_query", "list_directory", "search_files"]
    ttl_seconds = 300
    max_entries = 100
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    """A cached tool response."""
    key: str
    tool_name: str
    arguments_hash: str
    response: Any
    created_at: float
    ttl: float
    hit_count: int = 0

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


class ToolCache:
    """
    LRU cache for read-only tool responses.

    Thread-safe. Only caches tools matching the configured patterns.
    """

    def __init__(
        self,
        cacheable_tools: list[str] | None = None,
        ttl_seconds: float = 300.0,
        max_entries: int = 100,
    ):
        self._patterns = cacheable_tools or []
        self._ttl = ttl_seconds
        self._max = max_entries
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def is_cacheable(self, tool_name: str) -> bool:
        """Check if a tool matches any cacheable pattern."""
        for pattern in self._patterns:
            if fnmatch.fnmatch(tool_name, pattern) or tool_name == pattern:
                return True
        return False

    def _make_key(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Generate a cache key from tool name + arguments."""
        args_json = json.dumps(arguments, sort_keys=True, default=str)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()[:16]
        return f"{tool_name}:{args_hash}"

    def get(self, tool_name: str, arguments: dict[str, Any]) -> Any | None:
        """
        Look up a cached response.

        Returns the cached response or None if not found/expired.
        """
        if not self.is_cacheable(tool_name):
            return None

        key = self._make_key(tool_name, arguments)

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            if entry.is_expired:
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.hit_count += 1
            self._hits += 1
            return entry.response

    def put(
        self, tool_name: str, arguments: dict[str, Any], response: Any
    ) -> None:
        """Store a tool response in the cache."""
        if not self.is_cacheable(tool_name):
            return

        key = self._make_key(tool_name, arguments)
        args_json = json.dumps(arguments, sort_keys=True, default=str)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()[:16]

        with self._lock:
            # Remove if exists (to update position)
            if key in self._cache:
                del self._cache[key]

            # Evict oldest if at capacity
            while len(self._cache) >= self._max:
                self._cache.popitem(last=False)

            self._cache[key] = CacheEntry(
                key=key,
                tool_name=tool_name,
                arguments_hash=args_hash,
                response=response,
                created_at=time.time(),
                ttl=self._ttl,
            )

    def invalidate(self, tool_name: str | None = None) -> int:
        """
        Invalidate cache entries.

        If tool_name is given, only invalidate entries for that tool.
        If None, clear the entire cache.
        Returns the number of entries removed.
        """
        with self._lock:
            if tool_name is None:
                count = len(self._cache)
                self._cache.clear()
                return count

            keys_to_remove = [
                k for k, v in self._cache.items()
                if v.tool_name == tool_name
            ]
            for key in keys_to_remove:
                del self._cache[key]
            return len(keys_to_remove)

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries": len(self._cache),
                "max_entries": self._max,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 3) if total > 0 else 0,
                "ttl_seconds": self._ttl,
                "patterns": self._patterns,
            }
