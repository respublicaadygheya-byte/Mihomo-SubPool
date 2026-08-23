#!/usr/bin/env python3

import base64
import binascii
import json
from json import JSONDecodeError
import re
import sys
from urllib.parse import unquote, urlparse

def clean_name(name):
    name = unquote(name).strip()
    name = re.sub(r'\b\d+\s*Mb(?:ps)?\b\s*\|?\s*', '', name, flags=re.IGNORECASE)
    name = re.sub(r'\s+', ' ', name).strip(' |-')
    return name if name else "Proxy"

def parse_query(query):
    params = {}
    for item in query.split("&"):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        params[key] = unquote(value)
    return params

def parse_vless(link):
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    try:
        body = link[len("vless://"):]
        if "#" in body:
            body, raw_name = body.split("#", 1)
            name = clean_name(raw_name)
        else:
            name = "VLESS Proxy"

        if "?" not in body:
            return None

        user_host, query = body.split("?", 1)
        if "@" not in user_host:
            return None

        uuid, server_port = user_host.rsplit("@", 1)
        if ":" not in server_port:
            return None

        server, port = server_port.rsplit(":", 1)

        if server.startswith("[") and server.endswith("]"):
            server = server[1:-1]

        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": int(port),
            "uuid": uuid,
            "udp": True,
            "client-fingerprint": "chrome"
        }

        params = parse_query(query)

        if "type" in params:
            proxy["network"] = params["type"]

        if "encryption" in params:
            proxy["encryption"] = params["encryption"]

        if "flow" in params and params["flow"]:
            proxy["flow"] = params["flow"]

        packet_encoding = params.get("packetEncoding")

        if packet_encoding == "packet":
            proxy["packet-addr"] = True
        elif packet_encoding != "none":
            proxy["xudp"] = True

        security = params.get("security")

        if security == "reality":
            proxy["tls"] = True

            public_key = params.get("pbk")

            if public_key:
                reality_opts = {
                    "public-key": public_key
                }

                if params.get("sid"):
                    reality_opts["short-id"] = params["sid"]

                proxy["reality-opts"] = reality_opts

            if params.get("sni"):
                proxy["servername"] = params["sni"]

            if params.get("fp"):
                proxy["client-fingerprint"] = params["fp"]

        elif security == "tls":
            proxy["tls"] = True
            if params.get("sni"):
                proxy["servername"] = params["sni"]
            if params.get("fp"):
                proxy["client-fingerprint"] = params["fp"]

        if params.get("type") == "ws":
            ws_opts = {}

            if params.get("path"):
                path = params["path"]

                if "?ed=" in path:
                    try:
                        base_path, ed_part = path.split("?ed=", 1)
                        ed = ed_part.split("&", 1)[0]

                        ws_opts["path"] = base_path
                        ws_opts["max-early-data"] = int(ed)

                    except ValueError:
                        ws_opts["path"] = path
                else:
                    ws_opts["path"] = path

            ws_opts["headers"] = {
                "User-Agent": "Mozilla/5.0",
                "Host": params.get("host", "")
            }

            if params.get("ed"):
                try:
                    ws_opts["max-early-data"] = int(params["ed"])
                except ValueError:
                    pass

            if params.get("eh"):
                ws_opts["early-data-header-name"] = params["eh"]
            elif "max-early-data" in ws_opts:
                ws_opts["early-data-header-name"] = "Sec-WebSocket-Protocol"

            proxy["ws-opts"] = ws_opts

        if params.get("type") == "httpupgrade":
            ws_opts = {}

            if params.get("path"):
                ws_opts["path"] = params["path"]

            ws_opts["headers"] = {
                "User-Agent": "Mozilla/5.0",
                "Host": params.get("host", "")
            }

            if params.get("eh"):
                ws_opts["early-data-header-name"] = params["eh"]

            if params.get("ed"):
                ws_opts["v2ray-http-upgrade-fast-open"] = True

            proxy["ws-opts"] = ws_opts


        if params.get("type") == "grpc":
            grpc_opts = {}

            if params.get("serviceName"):
                grpc_opts["grpc-service-name"] = params["serviceName"]

            if grpc_opts:
                proxy["grpc-opts"] = grpc_opts


        if params.get("type") == "xhttp":
            xhttp_opts = {}

            if params.get("path"):
                xhttp_opts["path"] = params["path"]

            if params.get("mode"):
                xhttp_opts["mode"] = params["mode"]

            if params.get("host"):
                xhttp_opts["host"] = params["host"]

            if xhttp_opts:
                proxy["xhttp-opts"] = xhttp_opts


        return proxy
    except Exception:
        return None



def _decode_vmess_base64(value):
    value = value.strip()

    padded = value + "=" * (-len(value) % 4)

    for decoder in (
        base64.b64decode,
        base64.urlsafe_b64decode,
    ):
        try:
            return decoder(padded).decode("utf-8")
        except (
            ValueError,
            UnicodeDecodeError,
            binascii.Error,
        ):
            continue

    raise ValueError("invalid vmess base64")


def parse_vmess(link):
    if not link.startswith("vmess://"):
        return None

    try:
        body = link[len("vmess://"):]

        if "#" in body:
            body = body.split("#", 1)[0]

        decoded = _decode_vmess_base64(body)
        values = json.loads(decoded)

        if not isinstance(values, dict):
            return None

        server = values.get("add")
        port = values.get("port")
        uuid = values.get("id")

        if not server or not port or not uuid:
            return None

        proxy = {
            "name": clean_name(values.get("ps", "")),
            "type": "vmess",
            "server": server,
            "port": int(port),
            "uuid": uuid,
            "alterId": int(values.get("aid", 0)),
            "cipher": values.get("scy") or "auto",
            "udp": True,
        "tls": False,
        "skip-cert-verify": False,
            "xudp": True,
        }

        tls = str(values.get("tls", "")).lower()

        if tls.endswith("tls"):
            proxy["tls"] = True

        if values.get("sni"):
            proxy["servername"] = values["sni"]

        if values.get("alpn"):
            proxy["alpn"] = values["alpn"].split(",")

        network = str(
            values.get("net")
            or values.get("type")
            or ""
        ).lower()

        if network == "http":
            network = "h2"

        if network:
            proxy["network"] = network

        host = values.get("host")
        path = values.get("path")

        if network == "ws":
            ws_opts = {
                "path": path or "/",
                "headers": {},
            }

            if host:
                ws_opts["headers"]["Host"] = host

            proxy["ws-opts"] = ws_opts

        elif network == "h2":
            h2_opts = {
                "path": path or "/",
                "headers": {},
            }

            if host:
                h2_opts["headers"]["Host"] = [host]

            proxy["h2-opts"] = h2_opts

        elif network == "grpc":
            if path:
                proxy["grpc-opts"] = {
                    "grpc-service-name": path
                }

        return proxy

    except (
        ValueError,
        JSONDecodeError,
        TypeError,
        KeyError,
    ):
        return None


def parse_trojan(link):
    link = link.strip()

    if not link.startswith("trojan://"):
        return None

    try:
        body = link[len("trojan://"):]

        if "#" in body:
            body, raw_name = body.split("#", 1)
            name = clean_name(raw_name)
        else:
            name = "Trojan Proxy"

        query = ""

        if "?" in body:
            body, query = body.split("?", 1)

        if "@" not in body:
            return None

        password, server_port = body.rsplit("@", 1)

        if ":" not in server_port:
            return None

        server, port = server_port.rsplit(":", 1)

        if server.startswith("[") and server.endswith("]"):
            server = server[1:-1]

        proxy = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": int(port),
            "password": password,
            "udp": True,
            "client-fingerprint": "chrome"
        }

        params = parse_query(query) if query else {}

        if params.get("sni"):
            proxy["sni"] = params["sni"]

        if params.get("fp"):
            proxy["client-fingerprint"] = params["fp"]

        if params.get("alpn"):
            proxy["alpn"] = params["alpn"].split(",")

        if params.get("pcs"):
            proxy["fingerprint"] = params["pcs"]

        if params.get("allowInsecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True

        network = params.get("type", "").lower()

        if network:
            proxy["network"] = network

        if network == "ws":
            ws_opts = {}

            if params.get("path"):
                ws_opts["path"] = params["path"]

            ws_opts["headers"] = {
                "User-Agent": "Mozilla/5.0"
            }

            proxy["ws-opts"] = ws_opts

        if network == "grpc":
            grpc_opts = {}

            if params.get("serviceName"):
                grpc_opts["grpc-service-name"] = params["serviceName"]

            if grpc_opts:
                proxy["grpc-opts"] = grpc_opts

        return proxy

    except Exception:
        return None



def _decode_ss_base64(value):
    value = value.strip()

    for decoder in (
        base64.urlsafe_b64decode,
        base64.b64decode,
    ):
        try:
            padded = value + "=" * (-len(value) % 4)
            return decoder(padded).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            continue

    raise ValueError("invalid base64")


def _parse_ss_plugin(plugin):
    parts = plugin.split(";")

    if not parts:
        return None, None

    name = parts[0]
    opts = {}

    for item in parts[1:]:
        if "=" in item:
            k, v = item.split("=", 1)
            opts[k] = v

    if "obfs" in name:
        result = {}

        if opts.get("obfs"):
            result["mode"] = opts["obfs"]

        if opts.get("obfs-host"):
            result["host"] = opts["obfs-host"]

        return "obfs", result or None

    if "v2ray-plugin" in name:
        result = {}

        for key in ("mode", "host", "path"):
            if opts.get(key):
                result[key] = opts[key]

        if "tls" in plugin:
            result["tls"] = True

        return "v2ray-plugin", result or None

    return None, None


def parse_ss(link):
    link = link.strip()

    if not link.startswith("ss://"):
        return None

    try:
        raw = link[len("ss://"):]

        if "#" in raw:
            raw, raw_name = raw.split("#", 1)
            name = clean_name(raw_name)
        else:
            name = ""

        query = ""

        if "?" in raw:
            raw, query = raw.split("?", 1)

        parsed = urlparse("ss://" + raw)

        try:
            port = parsed.port
        except ValueError:
            port = None

        if parsed.hostname is None or port is None:
            decoded = _decode_ss_base64(raw)
            parsed = urlparse("ss://" + decoded)

        if parsed.username is not None:
            cipher = parsed.username
            password = parsed.password or ""
            server = parsed.hostname
            port = parsed.port
        else:
            decoded = _decode_ss_base64(raw)
            userinfo, server_port = decoded.rsplit("@", 1)

            cipher, password = userinfo.split(":", 1)
            server, port = server_port.rsplit(":", 1)

            port = int(port)

        if not server or not port:
            return None

        if server.startswith("[") and server.endswith("]"):
            server = server[1:-1]

        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(port),
            "password": password,
            "cipher": cipher,
            "udp": True,
        }

        params = parse_query(query) if query else {}

        if params.get("plugin"):
            plugin_name, plugin_opts = _parse_ss_plugin(
                params["plugin"]
            )

            if plugin_name:
                proxy["plugin"] = plugin_name

            if plugin_opts:
                proxy["plugin-opts"] = plugin_opts

        if params.get("udp-over-tcp") == "true" or params.get("uot") == "1":
            proxy["udp-over-tcp"] = True

        return proxy

    except Exception:
        return None


def parse_hysteria2(link):
    link = link.strip()

    prefix = (
        "hysteria2://"
        if link.startswith("hysteria2://")
        else "hy2://"
        if link.startswith("hy2://")
        else None
    )

    if not prefix:
        return None

    try:
        body = link[len(prefix):]

        if "#" in body:
            body, raw_name = body.split("#", 1)
            name = clean_name(raw_name)
        else:
            name = ""

        query = ""

        if "?" in body:
            body, query = body.split("?", 1)

        if "@" not in body:
            return None

        password, server_port = body.rsplit("@", 1)

        if ":" not in server_port:
            return None

        server, port = server_port.rsplit(":", 1)

        if server.startswith("[") and server.endswith("]"):
            server = server[1:-1]

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": int(port),
            "password": unquote(password),
        }

        params = parse_query(query) if query else {}

        if params.get("sni"):
            proxy["sni"] = params["sni"]

        if params.get("insecure"):
            if params["insecure"].lower() in ("1", "true", "yes"):
                proxy["skip-cert-verify"] = True

        if params.get("obfs") and params["obfs"] != "none":
            proxy["obfs"] = params["obfs"]

        if params.get("obfs-password"):
            proxy["obfs-password"] = params["obfs-password"]

        if params.get("alpn"):
            proxy["alpn"] = params["alpn"].split(",")

        if params.get("pinSHA256"):
            proxy["fingerprint"] = params["pinSHA256"]

        if params.get("down"):
            proxy["down"] = params["down"]

        if params.get("up"):
            proxy["up"] = params["up"]

        return proxy

    except Exception:
        return None


def main():
    if len(sys.argv) != 3:
        print("Usage: parser.py <input_file> <output_file>")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    proxies = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("vless://"):
            p = parse_vless(line)
        elif line.startswith("vmess://"):
            p = parse_vmess(line)
        elif line.startswith(("hysteria2://", "hy2://")):
            p = parse_hysteria2(line)
        elif line.startswith("trojan://"):
            p = parse_trojan(line)
        elif line.startswith("ss://"):
            p = parse_ss(line)
        else:
            p = None

        if p:
            proxies.append(p)

    seen_configs = set()
    unique = []
    name_counts = {}

    for p in proxies:
        key = json.dumps(
            {
                "type": p.get("type"),
                "server": p.get("server"),
                "port": p.get("port"),
                "uuid": p.get("uuid"),
                "password": p.get("password"),
                "cipher": p.get("cipher"),
                "plugin": p.get("plugin"),
                "plugin-opts": p.get("plugin-opts"),
                "udp-over-tcp": p.get("udp-over-tcp"),
                "network": p.get("network"),
                "flow": p.get("flow"),
                "tls": p.get("tls"),
                "reality": p.get("reality-opts"),
                "ws": p.get("ws-opts"),
                "grpc": p.get("grpc-opts"),
                "xhttp": p.get("xhttp-opts"),
            },
            sort_keys=True,
            ensure_ascii=False
        )
        if key in seen_configs:
            continue
        seen_configs.add(key)

        base_name = p["name"]
        if base_name in name_counts:
            name_counts[base_name] += 1
            p["name"] = f"{base_name} [{name_counts[base_name]}]"
        else:
            name_counts[base_name] = 1

        unique.append(p)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(unique, f, indent=2, ensure_ascii=False)

    print(f"Импортировано: {len(unique)} корректных прокси")

if __name__ == "__main__":
    main()
