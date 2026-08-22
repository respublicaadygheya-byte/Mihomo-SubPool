#!/usr/bin/env python3

import json
import re
import sys
from urllib.parse import unquote

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

        security = params.get("security")

        if security == "reality":
            public_key = params.get("pbk")
            if not public_key:
                return None

            proxy["tls"] = True
            reality_opts = {"public-key": public_key}

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
                ws_opts["path"] = params["path"]
            if params.get("host"):
                ws_opts["headers"] = {"Host": params["host"]}
            if ws_opts:
                proxy["ws-opts"] = ws_opts

        return proxy
    except Exception:
        return None

def parse_hysteria2(link):
    link = link.strip()
    prefix = "hysteria2://" if link.startswith("hysteria2://") else "hy2://" if link.startswith("hy2://") else None
    if not prefix:
        return None

    try:
        body = link[len(prefix):]
        if "#" in body:
            body, raw_name = body.split("#", 1)
            name = clean_name(raw_name)
        else:
            name = "Hysteria2 Proxy"

        query = ""
        if "?" in body:
            body, query = body.split("?", 1)

        if "@" not in body:
            return None

        password, server_port = body.rsplit("@", 1)
        if ":" not in server_port:
            return None

        server, port = server_port.rsplit(":", 1)

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": int(port),
            "password": unquote(password),
            "udp": True
        }

        params = parse_query(query) if query else {}
        if params.get("sni"):
            proxy["sni"] = params["sni"]
        if params.get("insecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True
        if params.get("obfs") and params["obfs"] != "none":
            proxy["obfs"] = params["obfs"]
        if params.get("obfs-password"):
            proxy["obfs-password"] = params["obfs-password"]

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
        elif line.startswith(("hysteria2://", "hy2://")):
            p = parse_hysteria2(line)
        else:
            p = None

        if p:
            proxies.append(p)

    seen_configs = set()
    unique = []
    name_counts = {}

    for p in proxies:
        key = (p.get("server"), p.get("port"), p.get("uuid") or p.get("password"))
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
