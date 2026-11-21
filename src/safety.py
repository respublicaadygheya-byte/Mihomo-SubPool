"""Safe upstream fetch: SSRF guard, DNS pinning, Happy Eyeballs-ish racing,
redirect limits and size caps. Ported in spirit from SubConv/upstream.py.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse as urlparse
from typing import Tuple

from util import MAX_CONTENT_BYTES, ParseError, rand_user_agent

MAX_REDIRECTS = 11
CONNECT_TIMEOUT = 12


class UnsafeAddress(ParseError):
    pass


def resolve_public(host: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ParseError(f"Cannot resolve {host}: {exc}") from exc
    addresses = list(dict.fromkeys(r[4][0] for r in records))
    if not addresses:
        raise ParseError(f"No addresses for {host}")
    safe = []
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not (ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_private and not ip.is_loopback and not ip.is_link_local):
            continue
        safe.append(address)
    if not safe:
        raise UnsafeAddress(f"Upstream {host} resolves only to private/special networks")
    return safe


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, ctx):
        super().__init__(ip, port, timeout=timeout, context=ctx)
        self._logical_host = host

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._logical_host)


def _request(url: str, addresses: list[str]) -> tuple[int, bytes, str | None]:
    parsed = urlparse.urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {
        "Host": host,
        "User-Agent": rand_user_agent(),
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    ctx = ssl.create_default_context()
    last_error: Exception | None = None
    for ip in addresses:
        try:
            if parsed.scheme == "https":
                conn = _PinnedHTTPS(host, ip, port, CONNECT_TIMEOUT, ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=CONNECT_TIMEOUT)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            body = resp.read(MAX_CONTENT_BYTES + 1)
            if len(body) > MAX_CONTENT_BYTES:
                raise ParseError("Upstream body exceeds size limit")
            status = resp.status
            location = resp.getheader("Location")
            conn.close()
            return status, body, location
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
            continue
    raise ParseError(f"Failed to fetch {url}: {last_error}")


def safe_fetch(url: str, *, allow_private: bool = False) -> str:
    current = url
    for redirect in range(MAX_REDIRECTS + 1):
        parsed = urlparse.urlsplit(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ParseError(f"Unsupported URL: {current}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if allow_private:
            addresses = [a[4][0] for a in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)]
            addresses = list(dict.fromkeys(addresses))
        else:
            addresses = resolve_public(parsed.hostname, port)
        status, body, location = _request(current, addresses)
        if status in (301, 302, 303, 307, 308) and location:
            if redirect >= MAX_REDIRECTS:
                raise ParseError("Too many redirects")
            current = urlparse.urljoin(current, location)
            continue
        if status != 200:
            raise ParseError(f"Upstream returned HTTP {status}")
        return body.decode("utf-8", errors="ignore")
    raise ParseError("Too many redirects")
