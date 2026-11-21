"""Shared utilities ported from SubConv (pure stdlib, no pydantic)."""
from __future__ import annotations

import base64
import binascii
import random
import re
import string
import urllib.parse as urlparse

MAX_PROXY_NODES = 10_000
MAX_CONTENT_BYTES = 10 * 1024 * 1024
INVALID_URL_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_USERINFO_CHARS = string.ascii_letters + string.digits + "-._~!$&'()*+,;=:%@"


class ParseError(Exception):
    """Malformed share link / subscription."""


class ProxyBudget:
    """Node + expanded-scalar budget."""

    def __init__(self, max_nodes=MAX_PROXY_NODES, max_bytes=MAX_CONTENT_BYTES):
        self.max_nodes = max_nodes
        self.max_bytes = max_bytes
        self.nodes = 0
        self.bytes = 0

    def check_count(self, count=1):
        if self.nodes + count > self.max_nodes:
            raise ParseError("Subscription exceeds node limit")

    def add(self, node):
        self.check_count()
        self.nodes += 1
        pending = [node]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, (list, tuple, set)):
                pending.extend(value)
            else:
                try:
                    size = len(value.encode("utf-8")) if isinstance(value, str) else len(str(value))
                except ValueError as exc:
                    raise ParseError("Field exceeds supported size") from exc
                self.bytes += size
                if self.bytes > self.max_bytes:
                    raise ParseError("Expanded nodes exceed size limit")


def parse_query(query: str, *, strict: bool = False, errors: str = "replace") -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for match in re.finditer(r"[^&]+", query):
        pair = match[0]
        escaped = "%" in pair
        if ";" in pair or (escaped and INVALID_URL_ESCAPE.search(pair)):
            if strict:
                raise ParseError("invalid query parameters")
            continue
        key, _, value = pair.partition("=")
        if escaped or "+" in pair:
            key = urlparse.unquote_plus(key, errors=errors)
            value = urlparse.unquote_plus(value, errors=errors)
        values.setdefault(key, []).append(value)
    return values


def first_query_values(query, *, strict: bool = False) -> dict[str, str]:
    """Accept a raw query string or an already parsed multi-value dict."""
    if isinstance(query, dict):
        return {k: (v[0] if isinstance(v, (list, tuple)) and v else v) for k, v in query.items()}
    return {k: v[0] for k, v in parse_query(query, strict=strict).items()}


def qfirst(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key) or []
    return values[0] if values else default


def parse_optional_bool(value: str | None) -> bool | None:
    if value in {"1", "t", "T", "true", "TRUE", "True"}:
        return True
    if value in {"0", "f", "F", "false", "FALSE", "False"}:
        return False
    return None


def parse_go_int(value: str) -> int:
    if not re.fullmatch(r"[+-]?[0-9]+", value):
        raise ValueError("invalid integer")
    digits = value.lstrip("+-").lstrip("0") or "0"
    if len(digits) > 19:
        raise ValueError("integer overflow")
    result = int(("-" if value.startswith("-") else "") + digits)
    if not -(2**63) <= result < 2**63:
        raise ValueError("integer overflow")
    return result


def _decode_base64(encoded: str, *, urlsafe: bool = False) -> str:
    encoded = encoded.replace("\r", "").replace("\n", "")
    padding = len(encoded) - len(encoded.rstrip("="))
    if padding > 2 or (padding and len(encoded) % 4):
        raise binascii.Error("Invalid padding")
    if urlsafe and any(char in encoded for char in "+/"):
        raise binascii.Error("Invalid URL-safe alphabet")
    if not padding:
        encoded += "=" * (-len(encoded) % 4)
    return base64.b64decode(encoded, altchars=b"-_" if urlsafe else None, validate=True).decode("utf-8")


def base64_raw_std_decode(encoded: str) -> str:
    return _decode_base64(encoded)


def base64_raw_url_decode(encoded: str) -> str:
    return _decode_base64(encoded, urlsafe=True)


def normalize_url_userinfo(userinfo: str) -> str:
    if any(char not in _USERINFO_CHARS for char in userinfo) or INVALID_URL_ESCAPE.search(userinfo):
        raise ParseError("invalid URL userinfo")
    username, separator, password = userinfo.partition(":")
    username = urlparse.quote_from_bytes(urlparse.unquote_to_bytes(username), safe="$&+,;=")
    if separator:
        password = urlparse.quote_from_bytes(urlparse.unquote_to_bytes(password), safe="$&+,;=")
        return f"{username}:{password}"
    return username


def url_safe(string: str) -> str:
    return string.replace("+", "-").replace("/", "_")


def proxy_key(line: str) -> str | None:
    """Stable dedup key for a share link."""
    m = re.match(r"vless://([^@]+)@([^/:]+):(\d+)", line.strip())
    if m:
        return f"{m.group(2)}|{m.group(3)}|{m.group(1)}"
    m = re.match(r"(?:hysteria2|hy2)://([^@]+)@([^/:]+):(\d+)", line.strip())
    if m:
        return f"{m.group(2)}|{m.group(3)}|{m.group(1)}"
    m = re.match(r"trojan://([^@]+)@([^/:]+):(\d+)", line.strip())
    if m:
        return f"{m.group(2)}|{m.group(3)}|{m.group(1)}"
    return None


_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
]


def rand_user_agent() -> str:
    return random.choice(_USER_AGENTS)
