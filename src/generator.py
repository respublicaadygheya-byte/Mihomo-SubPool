#!/usr/bin/env python3
"""Mihomo config generator with SubConv-inspired improvements:
- NameRegistry with reserved names and zero-padded dedup
- configurable regex groups (config/groups.yaml) with server-side filtering
- optional proxy-providers / rule-providers
- user rules ALWAYS first (highest priority)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from name_registry import NameRegistry  # noqa: E402
from filters import compile_group_filter, filter_names  # noqa: E402
from yaml_utils import dump_yaml  # noqa: E402

BASE = Path(__file__).resolve().parent.parent
RESERVED = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PROXY", "FOREIGN", "GLOBAL", "COMPATIBLE"}
TEST_URL = "http://www.gstatic.com/generate_204"


def sanitize_name(name) -> str:
    name = str(name)
    cleaned = []
    for ch in name:
        category = unicodedata.category(ch)
        if category in {"Cc", "Cf"}:
            cleaned.append(" ")
            continue
        if ch in "|,*()[]":
            cleaned.append(" ")
            continue
        cleaned.append(ch)
    name = "".join(cleaned)
    name = re.sub(r"\s+", " ", name).strip()
    name = re.sub(r"-+", "-", name).strip(" -")
    return name[:60].strip(" -") or "Proxy"


def clean_proxy(proxy: dict) -> dict:
    internal = {
        "alive", "_id", "latency", "provider", "protocol", "_source", "_uploaded_source",
        "_source", "diagnostics", "fail_reason", "timeout", "checked_at", "source",
    }
    proxy = dict(proxy)
    for key in list(proxy):
        if key in internal or key.startswith("_"):
            proxy.pop(key, None)
    awg = proxy.get("amnezia-wg-option")
    if isinstance(awg, dict):
        fixed = {}
        for k, v in awg.items():
            if isinstance(v, int):
                fixed[k] = v
            elif isinstance(v, str):
                m = re.search(r"0x([0-9a-fA-F]+)", v)
                if m:
                    fixed[k] = int(m.group(1), 16)
        if fixed:
            proxy["amnezia-wg-option"] = fixed
        else:
            proxy.pop("amnezia-wg-option", None)
    return proxy


def load_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]


def load_groups() -> list[dict]:
    path = BASE / "config" / "groups.yaml"
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except Exception as exc:
        print(f"[GROUPS] error loading config/groups.yaml: {exc}", file=sys.stderr)
        return []
    return data if isinstance(data, list) else []


def build_groups(names: list[str], warp_names: set[str], groups_cfg: list[dict]) -> list[dict]:
    groups: list[dict] = []
    available = set(names)
    if groups_cfg:
        for cfg in groups_cfg:
            name = cfg.get("name")
            gtype = cfg.get("type", "select")
            regex = cfg.get("regex")
            if not name or not isinstance(name, str):
                continue
            selected = list(names)
            client_filter = None
            if regex:
                try:
                    patterns, client_filter = compile_group_filter(regex)
                    selected = filter_names(patterns, names)
                except ValueError as exc:
                    print(f"[GROUPS] invalid regex for {name}: {exc}", file=sys.stderr)
                    continue
            if not selected:
                continue
            group = {"name": name, "type": gtype}
            if gtype in {"url-test", "fallback", "load-balance"}:
                group.update({"url": TEST_URL, "interval": 300, "tolerance": 50})
                if gtype == "load-balance":
                    group["strategy"] = "consistent-hashing"
            if client_filter:
                group["filter"] = client_filter
            group["proxies"] = [n for n in selected if n in available]
            groups.append(group)
    # Fallback: legacy WARP split pools
    if not groups:
        foreign = [n for n in names if n not in warp_names]
        groups.append({"name": "PROXY", "type": "select", "proxies": ["FOREIGN"] + (["WARP AUTO"] if warp_names else [])})
        if foreign:
            groups.append({"name": "FOREIGN", "type": "url-test", "url": TEST_URL, "interval": 300, "tolerance": 100, "proxies": foreign})
        if warp_names:
            groups.append({"name": "WARP AUTO", "type": "url-test", "url": TEST_URL, "interval": 300, "tolerance": 50, "proxies": [n for n in names if n in warp_names]})
    return groups


def generate_config(proxy_list: list[dict], ru_domains, ru_ips, use_providers: bool = False) -> dict:
    # MASQUE requires a very recent core; drop it for broad client compatibility
    proxy_list = [
        p for p in proxy_list
        if str(p.get("type", "")).lower() != "masque"
        and str(p.get("protocol", "")).lower() != "masque"
    ]

    registry = NameRegistry()
    for reserved in RESERVED:
        registry.register(reserved)

    proxies, warp_names = [], []
    for p in proxy_list:
        p = clean_proxy(p)
        p["name"] = registry.register(sanitize_name(p.get("name", "Proxy")))
        proxies.append(p)
        if p.get("provider") == "warp" or p.get("protocol") in {"wireguard", "amnezia-wg"}:
            warp_names.append(p["name"])

    names = [p["name"] for p in proxies]
    groups = build_groups(names, set(warp_names), load_groups())
    if not any(g.get("name") == "PROXY" for g in groups):
        proxies_for_select = ([groups[0]["name"]] if groups else []) + ["DIRECT"]
        groups.insert(0, {"name": "PROXY", "type": "select", "proxies": proxies_for_select})
    else:
        for g in groups:
            if g.get("name") == "PROXY" and len(groups) > 1:
                candidate = [x["name"] for x in groups if x["name"] != "PROXY"]
                g["proxies"] = candidate + ["DIRECT"]

    # USER RULES ALWAYS FIRST
    user_rules = load_list(BASE / "config" / "user_rules.txt")
    rules = [
        *user_rules,
        "GEOSITE,category-ru,DIRECT",
        "GEOIP,RU,DIRECT,no-resolve",
        "MATCH,PROXY",
    ]

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "ipv6": False,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        },
        "sniffer": {"enable": True, "parse-pure-ip": True, "override-destination": False},
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules,
    }

    if use_providers:
        config["proxy-providers"] = {
            "subscription": {
                "type": "http",
                "url": "https://raw.githubusercontent.com/respublicaadygheya-byte/Mihomo-SubPool/main/publish/subscription.txt",
                "interval": 7200,
                "path": "./sub/subscription.yaml",
                "health-check": {"enable": True, "interval": 300, "url": TEST_URL},
            }
        }
        config["rule-providers"] = {
            "ru_apps": {
                "type": "http",
                "behavior": "classical",
                "format": "text",
                "interval": 604800,
                "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/rule/ruapps.txt",
                "path": "./rule/ru_apps.txt",
            }
        }

    return config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxies")
    parser.add_argument("--output", required=True)
    parser.add_argument("--providers", action="store_true")
    args = parser.parse_args()

    proxies = []
    if args.proxies:
        proxies = json.load(open(args.proxies, encoding="utf-8"))
    config = generate_config(proxies, [], [], use_providers=args.providers)
    Path(args.output).write_text(dump_yaml(config), encoding="utf-8")
    print(f"✅ Конфиг сгенерирован: {args.output}")
    print(f"   Всего прокси: {len(proxies)}")
    print(f"   Групп: {len(config['proxy-groups'])}")
    print(f"   DIRECT доменов: 0")
    print(f"   DIRECT IP: 0")


if __name__ == "__main__":
    main()
