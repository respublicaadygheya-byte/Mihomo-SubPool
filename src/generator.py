#!/usr/bin/env python3
import json
import sys
import argparse
import yaml
from pathlib import Path

used_names = set()


def sanitize_name(name):
    import re
    import unicodedata

    name = str(name)

    # Сохраняем Unicode, включая флаги стран.
    # Убираем только управляющие символы и явно проблемные YAML/OpenClash
    # разделители. Не пытаемся фильтровать Unicode через ASCII regex.

    cleaned = []

    for ch in name:
        category = unicodedata.category(ch)

        # Управляющие и невидимые форматирующие символы.
        if category in {"Cc", "Cf"}:
            cleaned.append(" ")
            continue

        # Проблемные символы для имени прокси.
        if ch in "|,*()[]":
            cleaned.append(" ")
            continue

        cleaned.append(ch)

    name = "".join(cleaned)

    # Нормализуем whitespace.
    name = re.sub(r"\s+", " ", name).strip()

    # Убираем повторные дефисы.
    name = re.sub(r"-+", "-", name)

    # Убираем пробелы/дефисы по краям.
    name = name.strip(" -")

    # Ограничение длины.
    name = name[:60].strip(" -")

    return name


def unique_name(name):
    original = name
    counter = 2

    reserved = {
        'FOREIGN',
        'PROXY',
        'DIRECT'
    }

    if name in reserved:
        name = f"{name}-node"

    while name in used_names:
        name = f"{original}-{counter}"
        counter += 1

    used_names.add(name)
    return name



def load_list(filepath):
    """Загружает список доменов/IP из файла"""
    if not filepath or not Path(filepath).exists():
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith('#')
        ]


def clean_proxy(proxy):
    """Remove ALL internal pipeline fields so third-party clients can parse the config."""
    internal = {
        "alive", "_id", "latency", "provider", "protocol",
        "_uploaded_source", "_source", "diagnostics", "fail_reason",
        "timeout", "checked_at", "source",
    }
    for key in list(proxy.keys()):
        if key in internal or key.startswith("_"):
            proxy.pop(key, None)

    # Fix AmneziaWG options that were serialized as Python bytes repr like "<b 0x1234>"
    awg = proxy.get("amnezia-wg-option")
    if isinstance(awg, dict):
        fixed = {}
        for k, v in awg.items():
            if isinstance(v, int):
                fixed[k] = v
            else:
                import re
                m = re.search(r"0x([0-9a-fA-F]+)", str(v))
                if m:
                    fixed[k] = int(m.group(1), 16)
        if fixed:
            proxy["amnezia-wg-option"] = fixed
        else:
            proxy.pop("amnezia-wg-option", None)
    return proxy


def generate_config(proxy_list, ru_domains, ru_ips):
    """Генерация простой целевой Mihomo-схемы."""

    proxies = []
    proxy_names = []

    # Все VPN-ноды идут в единый пул.
    # FOREIGN содержит весь набор доступных прокси.
    # MASQUE requires a very recent Mihomo core; drop it for broad client compatibility
    all_proxies = [
        p for p in proxy_list
        if str(p.get("type", "")).lower() != "masque"
        and str(p.get("protocol", "")).lower() != "masque"
    ]

    for p in all_proxies:
        p = clean_proxy(p)

        original_name = p.get('name', 'PROXY')
        p['name'] = unique_name(sanitize_name(original_name))

        proxy_names.append(p['name'])
        proxies.append(p)

    # --------------------------------------------------------
    # GEO ROUTING
    # RU -> DIRECT
    # Everything else -> PROXY
    # --------------------------------------------------------

    # --------------------------------------------------------
    # USER RULES - HIGHEST PRIORITY
    # Everything from config/user_rules.txt is inserted BEFORE
    # generated rules, so user overrides always win.
    # --------------------------------------------------------
    user_rules_file = Path(__file__).resolve().parent.parent / 'config' / 'user_rules.txt'
    user_rules = load_list(user_rules_file)

    rules = [
        *user_rules,
        "GEOSITE,category-ru,DIRECT",
        "GEOIP,RU,DIRECT,no-resolve",
        "MATCH,PROXY"
    ]

    # --------------------------------------------------------
    # Целевая схема:
    #
    # PROXY
    #   ├── FOREIGN
    #   ├── node1
    #   ├── node2
    #   └── ...
    #
    # FOREIGN
    #   └── url-test -> все VPN-ноды
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Split WARP and normal VPN nodes
    # --------------------------------------------------------

    warp_nodes = [
        p
        for p in proxies
        if p.get('provider') == 'warp'
        and p.get('protocol') == 'wireguard'
    ]

    awg_nodes = [
        p
        for p in proxies
        if p.get('provider') == 'warp'
        and p.get('protocol') == 'amnezia-wg'
    ]

    warp_nodes.sort(
        key=lambda x: x.get(
            'latency',
            9999
        )
    )

    awg_nodes.sort(
        key=lambda x: x.get(
            'latency',
            9999
        )
    )

    WARP_LIMIT = 100

    warp_nodes = warp_nodes[:WARP_LIMIT]

    warp_names = [
        p['name']
        for p in warp_nodes
    ]

    awg_names = [
        p['name']
        for p in awg_nodes
    ]

    masque_nodes = [
        p
        for p in proxies
        if p.get('provider') == 'warp'
        and p.get('protocol') == 'masque'
    ]

    masque_nodes.sort(
        key=lambda x: x.get(
            'latency',
            9999
        )
    )

    masque_names = [
        p['name']
        for p in masque_nodes
    ]

    vpn_names = [
        p['name']
        for p in proxies
        if p.get('provider') != 'warp'
    ]

    config = {
        'mixed-port': 7890,
        'allow-lan': True,
        'bind-address': '*',
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',

        'dns': {
            'enable': True,
            'listen': '0.0.0.0:1053',
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://1.1.1.1/dns-query',
                'https://8.8.8.8/dns-query'
            ]
        },

        'sniffer': {
            'enable': True,
            'parse-pure-ip': True,
            'override-destination': False
        },

        'proxies': proxies,

        'proxy-groups': [

            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': (
                    (['🔥 AWG AUTO'] if awg_names else [])
                    + (['🚀 WARP AUTO'] if warp_names else [])
                    + (['🌀 MASQUE AUTO'] if masque_names else [])
                    + (['FOREIGN'] if vpn_names else [])
                )
            },

            *(
                [{
                    'name': 'FOREIGN',
                    'type': 'url-test',
                    'url': 'http://cp.cloudflare.com/generate_204',
                    'interval': 300,
                    'tolerance': 100,
                    'proxies': vpn_names
                }]
                if vpn_names else []
            ),

            *(
                [{
                    'name': '🔥 AWG AUTO',
                    'type': 'url-test',
                    'url': 'http://cp.cloudflare.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': awg_names
                }]
                if awg_names else []
            ),

            *(
                [{
                    'name': '🚀 WARP AUTO',
                    'type': 'url-test',
                    'url': 'http://cp.cloudflare.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': warp_names
                }]
                if warp_names else []
            ),

            *(
                [{
                    'name': '🌀 MASQUE AUTO',
                    'type': 'url-test',
                    'url': 'https://cloudflare.com/cdn-cgi/trace',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': masque_names
                }]
                if masque_names else []
            )
        ],

        'rules': rules
    }

    return config


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--proxies',
        help='All proxy JSON'
    )

    parser.add_argument(
        '--ru',
        help='Legacy RU proxies JSON'
    )

    parser.add_argument(
        '--foreign',
        help='Legacy foreign proxies JSON'
    )

    parser.add_argument(
        '--output',
        required=True,
        help='Output file'
    )

    args = parser.parse_args()


    proxies = []

    if args.proxies:
        with open(args.proxies, 'r', encoding='utf-8') as f:
            proxies = json.load(f)

    else:
        if args.ru:
            with open(args.ru, 'r', encoding='utf-8') as f:
                proxies.extend(json.load(f))

        if args.foreign:
            with open(args.foreign, 'r', encoding='utf-8') as f:
                proxies.extend(json.load(f))


    ru_domains = []
    ru_ips = []




    # --------------------------------------------------------
    # Provider metadata already resolved upstream.
    # Generator must not classify WARP by transport type.
    # --------------------------------------------------------


    config = generate_config(
        proxies,
        ru_domains,
        ru_ips
    )


    with open(args.output, 'w', encoding='utf-8') as f:

        yaml.dump(
            config,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False
        )


    print(f"✅ Конфиг сгенерирован: {args.output}")
    print(f"   Всего прокси: {len(proxies)}")
    print(f"   DIRECT доменов: {len(ru_domains)}")
    print(f"   DIRECT IP: {len(ru_ips)}")


if __name__ == '__main__':
    main()
