"""Zero-padded proxy name deduplication, ported from SubConv."""
from __future__ import annotations


class NameRegistry:
    def __init__(self) -> None:
        self._names: dict[str, int] = {}
        self._used: set[str] = set()

    def register(self, name: str) -> str:
        candidate = name or "Proxy"
        index = self._names.get(candidate, 0)
        while candidate in self._used:
            index += 1
            candidate = f"{name}-{index:02d}"
        self._names[name] = index
        self._used.add(candidate)
        return candidate
