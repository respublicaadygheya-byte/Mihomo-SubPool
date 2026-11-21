#!/usr/bin/env python3
"""Strict multi-protocol share-link parser, ported from SubConv (pure stdlib).

Usage: parser.py <input_links.txt> <output_proxies.json>
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import urllib.parse as urlparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from name_registry import NameRegistry
from util import (  # noqa: E402
    INVALID_URL_ESCAPE,
    MAX_CONTENT_BYTES,
    ParseError,
    ProxyBudget,
    base64_raw_std_decode,
    base64_raw_url_decode,
    first_query_values,
    normalize_url_userinfo,
    parse_optional_bool,
    parse_query,
    qfirst,
    rand_user_agent,
    url_safe,
)
from yaml_utils import load_yaml_safe  # noqa: E402


def clean_name(raw: str) -> str:
    name = urlparse.unquote(raw).strip()
    name = re.sub(r"\b\d+\s*Mb(?:ps)?\b\s*\|?", "", name, flags=re.I)
    name = re.sub(r"\s+", " ", name).strip(" |-")
    return name or "Proxy"


# ---------- VLESS / VMess shared transport ----------
def handle_v_share_link(url, registry: NameRegistry, scheme: str, query: dict) -> dict:
    try:
        port = url.port
    except ValueError as exc:
        raise ParseError(f"{scheme}: invalid port") from exc
    host = url.hostname
    if not host or port is None:
        raise ParseError(f"{scheme}: missing host or port")
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": scheme,
        "server": host,
        "port": port,
        "uuid": urlparse.unquote(url.username or ""),
        "udp": True,
    }
    security = qfirst(query, "security").lower()
    if security.endswith("tls") or security == "reality":
        proxy["tls"] = True
        proxy["client-fingerprint"] = qfirst(query, "fp") or "chrome"
        alpn = qfirst(query, "alpn")
        if alpn:
            proxy["alpn"] = alpn.split(",")
        pcs = qfirst(query, "pcs")
        if pcs:
            proxy["fingerprint"] = pcs
    sni = qfirst(query, "sni")
    if sni:
        proxy["servername"] = sni
    pbk = qfirst(query, "pbk")
    if pbk:
        proxy["reality-opts"] = {
            "public-key": pbk,
            "short-id": qfirst(query, "sid") or None,
            "support-x25519mlkem768": parse_optional_bool(qfirst(query, "support-x25519mlkem768")),
        }
        proxy["reality-opts"] = {k: v for k, v in proxy["reality-opts"].items() if v is not None}
    packet_encoding = qfirst(query, "packetEncoding")
    if packet_encoding == "packet":
        proxy["packet-addr"] = True
    elif packet_encoding and packet_encoding != "none":
        proxy["xudp"] = True

    network = qfirst(query, "type").lower() or "tcp"
    fake_type = qfirst(query, "headerType").lower()
    if network == "tcp" and fake_type == "http":
        network = "http"
    elif network == "http":
        network = "h2"
    proxy["network"] = network

    if network == "ws":
        ws = {
            "path": qfirst(query, "path") or None,
            "headers": {"User-Agent": rand_user_agent()},
        }
        host_header = qfirst(query, "host")
        if host_header:
            ws["headers"]["Host"] = host_header
        ed = qfirst(query, "ed")
        if ed:
            ws["max-early-data"] = int(ed) if ed.isdigit() else None
            ws["early-data-header-name"] = "Sec-WebSocket-Protocol"
        proxy["ws-opts"] = {k: v for k, v in ws.items() if v is not None}
    elif network == "httpupgrade":
        proxy["ws-opts"] = {
            "path": qfirst(query, "path") or None,
            "headers": {"User-Agent": rand_user_agent(), "Host": qfirst(query, "host")},
            "v2ray-http-upgrade": True,
        }
    elif network == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": qfirst(query, "serviceName") or None}
    elif network == "h2":
        proxy["h2-opts"] = {
            "path": qfirst(query, "path") or "/",
            "host": [qfirst(query, "host")] if qfirst(query, "host") else None,
        }
    elif network == "http":
        proxy["http-opts"] = {
            "method": qfirst(query, "method") or None,
            "path": [qfirst(query, "path") or "/"],
            "headers": {"Host": [qfirst(query, "host")]} if qfirst(query, "host") else None,
        }
    elif network == "xhttp":
        proxy["xhttp-opts"] = {
            "path": qfirst(query, "path") or None,
            "host": qfirst(query, "host") or None,
            "mode": qfirst(query, "mode") or None,
        }
        proxy["xhttp-opts"] = {k: v for k, v in proxy["xhttp-opts"].items() if v is not None}
    return {k: v for k, v in proxy.items() if v is not None}


def parse_vless(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    query = parse_query(url.query)
    proxy = handle_v_share_link(url, registry, "vless", query)
    flow = qfirst(query, "flow")
    if flow:
        proxy["flow"] = flow.lower()
    encryption = qfirst(query, "encryption")
    if encryption:
        proxy["encryption"] = encryption
    return proxy


def parse_vmess(line: str, registry: NameRegistry) -> dict:
    # Strip fragment/query before base64 decoding (some providers append "#name")
    body = line.partition("://")[2].split("#", 1)[0].split("?", 1)[0]
    try:
        decoded = base64_raw_std_decode(body)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        decoded = body  # try AEAD JSON
    try:
        values = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ParseError("vmess: invalid JSON") from exc
    if not isinstance(values, dict):
        raise ParseError("vmess: invalid JSON object")
    server = values.get("add") or values.get("server")
    uuid = values.get("id") or values.get("uuid")
    port = values.get("port")
    if not server or not uuid or not port:
        raise ParseError("vmess: missing server/uuid/port")
    proxy = {
        "name": registry.register(clean_name(str(values.get("ps") or values.get("name") or ""))),
        "type": "vmess",
        "server": str(server),
        "port": int(port),
        "uuid": str(uuid),
        "alterId": int(values.get("aid") or values.get("alterId") or 0),
        "cipher": str(values.get("scy") or values.get("cipher") or "auto"),
        "udp": True,
    }
    if sni := values.get("sni"):
        proxy["servername"] = str(sni)
    if str(values.get("tls") or values.get("tlsEnabled") or "").lower().endswith("tls") or values.get("tls") is True:
        proxy["tls"] = True
    # VMess AEAD fields from share link
    if isinstance(values.get("alpn"), str):
        proxy["alpn"] = values["alpn"].split(",")
    network = str(values.get("net") or values.get("network") or "").lower()
    if network == "ws":
        proxy["network"] = "ws"
        opts = {}
        if path := values.get("path"):
            opts["path"] = str(path)
        if host := values.get("host"):
            opts["headers"] = {"Host": str(host)}
        proxy["ws-opts"] = opts
    elif network == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": str(values.get("path") or "")}
    elif network:
        proxy["network"] = network
    return proxy


def parse_trojan(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname or not url.port or not url.username:
        raise ParseError("trojan: missing password/host/port")
    q = first_query_values(url.query)
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": "trojan",
        "server": url.hostname,
        "port": url.port,
        "password": urlparse.unquote(url.username),
        "udp": True,
        "client-fingerprint": q.get("fp") or "chrome",
    }
    if q.get("allowInsecure"):
        proxy["skip-cert-verify"] = bool(parse_optional_bool(q["allowInsecure"]))
    if q.get("sni"):
        proxy["sni"] = q["sni"]
    if q.get("alpn"):
        proxy["alpn"] = q["alpn"].split(",")
    network = (q.get("type") or "").lower()
    if network:
        proxy["network"] = network
    if network == "ws":
        proxy["ws-opts"] = {"path": q.get("path") or "/", "headers": {"User-Agent": rand_user_agent()}}
    elif network == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName")}
    if q.get("pcs"):
        proxy["fingerprint"] = q["pcs"]
    return {k: v for k, v in proxy.items() if v is not None}


def _split_hy2_ports(line: str) -> tuple[str, str]:
    head, sep, rest = line.partition("://")
    if not sep:
        return line, ""
    end = min((rest.find(c) for c in "/?#" if c in rest), default=len(rest))
    authority, tail = rest[:end], rest[end:]
    userinfo, at, hostport = authority.rpartition("@")
    if not at:
        hostport = authority
    if "]" in hostport:
        return line, ""
    host, colon, ports = hostport.rpartition(":")
    if not colon or not any(c in ports for c in ",-"):
        return line, ""
    first = ports.replace("-", ",").split(",", 1)[0]
    prefix = userinfo + at if at else ""
    return f"{head}://{prefix}{host}:{first}{tail}", ports


def parse_hysteria2(line: str, registry: NameRegistry) -> dict:
    line, ports = _split_hy2_ports(line)
    url = urlparse.urlparse(line)
    port = url.port if url.port is not None else 443
    if not url.hostname:
        raise ParseError("hysteria2: missing host")
    q = {k: v[0] for k, v in parse_query(url.query).items()}
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": "hysteria2",
        "server": url.hostname,
        "port": port,
        "ports": ports or None,
        "obfs": q.get("obfs") or None,
        "obfs-password": q.get("obfs-password") or None,
        "sni": q.get("sni") or None,
    }
    if q.get("insecure"):
        proxy["skip-cert-verify"] = bool(parse_optional_bool(q["insecure"]))
    if q.get("alpn"):
        proxy["alpn"] = q["alpn"].split(",")
    userinfo, _, authority = url.netloc.rpartition("@")
    if url.scheme.lower().endswith("+realm"):
        proxy["realm-opts"] = {
            "server-url": "https://" + authority,
            "token": urlparse.unquote(userinfo) or None,
            "realm-id": urlparse.unquote(url.path.lstrip("/")) or None,
        }
        if q.get("auth"):
            proxy["password"] = q["auth"]
    elif userinfo:
        proxy["password"] = urlparse.unquote(userinfo)
    if q.get("pinSHA256"):
        proxy["fingerprint"] = q["pinSHA256"]
    if q.get("down"):
        proxy["down"] = q["down"]
    if q.get("up"):
        proxy["up"] = q["up"]
    return {k: v for k, v in proxy.items() if v is not None}


def parse_hysteria(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname or not url.port:
        raise ParseError("hysteria: missing host/port")
    q = first_query_values(url.query)
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": "hysteria",
        "server": url.hostname,
        "port": url.port,
        "sni": q.get("peer") or None,
        "obfs": q.get("obfs") or None,
        "auth-str": q.get("auth") or None,
        "protocol": q.get("protocol") or None,
        "up": q.get("up") or q.get("upmbps") or None,
        "down": q.get("down") or q.get("downmbps") or None,
    }
    if q.get("alpn"):
        proxy["alpn"] = q["alpn"].split(",")
    if q.get("insecure"):
        proxy["skip-cert-verify"] = bool(parse_optional_bool(q["insecure"]))
    return {k: v for k, v in proxy.items() if v is not None}


def _b64_any(value: str) -> str:
    for decoder in (base64_raw_url_decode, base64_raw_std_decode):
        try:
            return decoder(value)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue
    raise ParseError("invalid base64")


def parse_ss(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname:
        raise ParseError("ss: missing host")
    try:
        port = url.port
    except ValueError as exc:
        raise ParseError("ss: invalid port") from exc
    if port is None:
        decoded = _b64_any(url.netloc.rsplit("@", 1)[-1])
        url = urlparse.urlparse(f"ss://{decoded}")._replace(query=url.query, fragment=url.fragment)
        port = url.port
    raw_userinfo, _, _ = url.netloc.rpartition("@")
    if not raw_userinfo:
        raise ParseError("ss: missing userinfo")
    if url.username and url.password is not None:
        cipher, password = urlparse.unquote(url.username), urlparse.unquote(url.password)
    else:
        info = _b64_any(urlparse.unquote(raw_userinfo))
        cipher, sep, password = info.partition(":")
        if not sep:
            raise ParseError("ss: invalid credentials")
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": "ss",
        "server": url.hostname,
        "port": port,
        "cipher": cipher,
        "password": password,
        "udp": True,
    }
    q = first_query_values(url.query)
    if q.get("plugin"):
        parts = first_query_values("pluginName=" + q["plugin"].replace(";", "&"))
        pname = parts.get("pluginName", "")
        if "obfs" in pname:
            proxy["plugin"] = "obfs"
            proxy["plugin-opts"] = {k: v for k, v in {"mode": parts.get("obfs"), "host": parts.get("obfs-host")}.items() if v}
        elif "v2ray" in pname:
            proxy["plugin"] = "v2ray-plugin"
            opts = {"mode": parts.get("mode") or parts.get("obfs"), "host": parts.get("host") or parts.get("obfs-host"), "path": parts.get("path")}
            if "tls" in q["plugin"]:
                opts["tls"] = True
            proxy["plugin-opts"] = {k: v for k, v in opts.items() if v}
    if q.get("udp-over-tcp") == "true" or q.get("uot") == "1":
        proxy["udp-over-tcp"] = True
    return proxy


def parse_ssr(line: str, registry: NameRegistry) -> dict:
    if line.partition("://")[0].lower() != "ssr":
        raise ParseError("ssr: invalid scheme")
    decoded = base64_raw_url_decode(url_safe(line[6:]))
    before, sep, after = decoded.partition("/?")
    if not sep:
        raise ParseError("ssr: missing /?")
    parts = before.split(":")
    if len(parts) != 6:
        raise ParseError("ssr: invalid fields")
    q = first_query_values(url_safe(after), strict=True)
    return {
        "name": registry.register(clean_name(base64_raw_url_decode(url_safe(q.get("remarks", ""))))),
        "type": "ssr",
        "server": parts[0],
        "port": int(parts[1]),
        "protocol": parts[2],
        "cipher": parts[3],
        "obfs": parts[4],
        "password": base64_raw_url_decode(url_safe(parts[5])),
        "obfs-param": base64_raw_url_decode(url_safe(q["obfsparam"])) if q.get("obfsparam") else None,
        "protocol-param": base64_raw_url_decode(url_safe(q["protoparam"])) if q.get("protoparam") else None,
        "udp": True,
    }


def parse_tuic(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname or not url.port:
        raise ParseError("tuic: missing host/port")
    q = first_query_values(url.query)
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment))),
        "type": "tuic",
        "server": url.hostname,
        "port": url.port,
        "udp": True,
    }
    if url.password is not None:
        proxy["uuid"] = urlparse.unquote(url.username or "")
        proxy["password"] = urlparse.unquote(url.password)
    else:
        proxy["token"] = urlparse.unquote(url.username or "")
    if q.get("congestion_control"):
        proxy["congestion-controller"] = q["congestion_control"]
    if q.get("alpn"):
        proxy["alpn"] = q["alpn"].split(",")
    if q.get("sni"):
        proxy["sni"] = q["sni"]
    if q.get("disable_sni") == "1":
        proxy["disable-sni"] = True
    if q.get("udp_relay_mode"):
        proxy["udp-relay-mode"] = q["udp_relay_mode"]
    return {k: v for k, v in proxy.items() if v is not None}


def parse_anytls(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname or not url.port:
        raise ParseError("anytls: missing host/port")
    username = urlparse.unquote(url.username) if url.username is not None else None
    password = urlparse.unquote(url.password) if url.password is not None else username
    if not password:
        raise ParseError("anytls: missing password")
    q = first_query_values(url.query)
    return {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment) or f"{url.hostname}:{url.port}")),
        "type": "anytls",
        "server": url.hostname,
        "port": url.port,
        "username": username,
        "password": password,
        "sni": q.get("sni") or None,
        "fingerprint": q.get("hpkp") or None,
        "skip-cert-verify": q.get("insecure") == "1",
        "udp": True,
    }


def parse_mieru(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    q = first_query_values(url.query)
    if not url.hostname or not url.port:
        raise ParseError("mieru: missing host/port")
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment) or "mieru")),
        "type": "mieru",
        "server": url.hostname,
        "port": url.port,
        "udp": True,
    }
    if q.get("protocol"):
        proxy["protocol"] = q["protocol"]
    if q.get("username"):
        proxy["username"] = q["username"]
    if q.get("password"):
        proxy["password"] = q["password"]
    return proxy


def parse_http_socks(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if not url.hostname or not url.port:
        raise ParseError("http/socks: missing host/port")
    scheme = url.scheme.lower()
    ptype = "socks5" if scheme in {"socks", "socks5", "socks5h"} else "http" if scheme in {"http", "https"} else None
    if not ptype:
        raise ParseError("http/socks: unsupported scheme")
    raw_userinfo, _, _ = url.netloc.rpartition("@")
    username = password = None
    if raw_userinfo:
        userinfo = normalize_url_userinfo(raw_userinfo)
        encoded = userinfo if "=" in userinfo else userinfo + "=" * (-len(userinfo) % 4)
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8", errors="replace")
        except binascii.Error:
            decoded = userinfo
        parts = decoded.split(":", 1)
        username = parts[0] or None
        password = parts[1] if len(parts) == 2 else None
    proxy = {
        "name": registry.register(clean_name(urlparse.unquote(url.fragment) or f"{url.hostname}:{url.port}")),
        "type": ptype,
        "server": url.hostname,
        "port": url.port,
        "skip-cert-verify": True,
    }
    if username:
        proxy["username"] = username
    if password:
        proxy["password"] = password
    if scheme == "https":
        proxy["tls"] = True
    return proxy


def parse_tg(line: str, registry: NameRegistry) -> dict:
    url = urlparse.urlparse(line)
    if url.scheme == "https":
        if (url.hostname or "") != "t.me":
            raise ParseError("telegram: invalid host")
        ptype = url.path.strip("/")
    else:
        ptype = url.hostname or ""
    q = first_query_values(url.query)
    if ptype not in {"socks", "socks5"}:
        raise ParseError("telegram: unsupported proxy type")
    if not q.get("server") or not q.get("port"):
        raise ParseError("telegram: missing server/port")
    return {
        "name": registry.register(clean_name(q.get("remark") or q.get("remarks") or ptype)),
        "type": "socks5",
        "server": q["server"],
        "port": int(q["port"]),
        "username": q.get("user") or None,
        "password": q.get("pass") or None,
    }


_DISPATCH = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "hysteria": parse_hysteria,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria2+realm": parse_hysteria2,
    "hy2+realm": parse_hysteria2,
    "ss": parse_ss,
    "ssr": parse_ssr,
    "tuic": parse_tuic,
    "anytls": parse_anytls,
    "mieru": parse_mieru,
    "socks": parse_http_socks,
    "socks5": parse_http_socks,
    "socks5h": parse_http_socks,
    "http": parse_http_socks,
    "https": parse_http_socks,
    "tg": parse_tg,
}


def decode_subscription(buf: str) -> str:
    if ":" in buf:
        return buf
    try:
        return base64_raw_std_decode(buf)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return buf


def parse_links(text: str) -> list[dict]:
    text = decode_subscription(text)
    proxies, budget = [], ProxyBudget()
    registry = NameRegistry()
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        scheme = line.partition("://")[0].partition("/")[0].lower()
        if "://" not in line:
            continue
        parser = _DISPATCH.get(scheme)
        if parser is None:
            raise ParseError(f"Line {number} ({scheme or 'unknown'}): unsupported protocol")
        budget.check_count()
        try:
            proxy = parser(line, registry)
        except (ParseError, ValueError) as exc:
            raise ParseError(f"Line {number} ({scheme}): {exc}") from exc
        budget.add(proxy)
        proxies.append(proxy)
    if not proxies:
        raise ParseError("No valid proxies found")
    return proxies


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: parser.py <input_links.txt> <output_proxies.json>", file=sys.stderr)
        sys.exit(1)
    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
    if len(text.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise SystemExit("Subscription exceeds size limit")
    try:
        # Clash-style YAML subscription
        if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text.strip().splitlines()[0] if text.strip() else ""):
            data = load_yaml_safe(text)
            if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                registry, budget, proxies = NameRegistry(), ProxyBudget(), []
                for node in data["proxies"]:
                    budget.check_count()
                    node = dict(node)
                    node["name"] = registry.register(str(node.get("name") or "Proxy"))
                    budget.add(node)
                    proxies.append(node)
            else:
                proxies = parse_links(text)
        else:
            proxies = parse_links(text)
    except (ParseError, ValueError) as exc:
        print(f"PARSE ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    Path(sys.argv[2]).write_text(json.dumps(proxies, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Импортировано: {len(proxies)} корректных прокси")


if __name__ == "__main__":
    main()
