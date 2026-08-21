import os
import yaml
import glob
import json
import configparser

from src.core.fingerprint import proxy_fingerprint


from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]

UPLOADED_DIR = BASE_DIR / "UPLOADED"
CACHE_DIR = BASE_DIR / "cache/providers"
OUTPUT = os.path.join(CACHE_DIR, "uploaded-custom.json")


def deduplicate_proxies(proxies):
    """
    Remove technical duplicates.
    Names and source filenames are ignored.
    """

    result = []
    seen = set()

    removed = 0

    for proxy in proxies:
        fp = proxy_fingerprint(proxy)

        if fp in seen:
            removed += 1
            continue

        seen.add(fp)
        result.append(proxy)

    print()
    print("=== UPLOADED DEDUPE ===")
    print(f"Before: {len(proxies)}")
    print(f"After:  {len(result)}")
    print(f"Removed:{removed}")

    return result



def normalize_proxy(proxy, source_file=None):
    """
    Нормализует загруженную WARP/WireGuard/AWG-ноду
    под внутреннюю схему генератора.
    """

    if not isinstance(proxy, dict):
        return None

    proxy = dict(proxy)

    # Все ноды из UPLOADED — это пользовательские WARP-ноды.
    proxy["provider"] = "warp"

    ptype = str(proxy.get("type", "")).lower()
    protocol = str(proxy.get("protocol", "")).lower()

    # MASQUE должен определяться раньше WireGuard.
    if ptype == "masque" or protocol == "masque":
        proxy["protocol"] = "masque"

    else:
        # AWG определяется наличием Amnezia WireGuard options.
        has_awg = bool(proxy.get("amnezia-wg-option"))

        if has_awg or protocol in ("amnezia-wg", "awg", "amnezia"):
            proxy["protocol"] = "amnezia-wg"
        elif ptype == "wireguard" or protocol == "wireguard":
            proxy["protocol"] = "wireguard"

    # Для WireGuard/AWG генератор использует type=wireguard.
    if proxy.get("protocol") in ("wireguard", "amnezia-wg"):
        proxy["type"] = "wireguard"

    # Для MASQUE сохраняем type=masque.
    elif proxy.get("protocol") == "masque":
        proxy["type"] = "masque"

    if source_file:
        proxy.setdefault("_uploaded_source", os.path.basename(source_file))

    return proxy


def parse_wg_conf(file_path):
    """Парсит WireGuard / AmneziaWG .conf."""

    config = configparser.ConfigParser(
        delimiters=("=",),
        strict=False
    )

    try:
        config.read(file_path, encoding="utf-8")
    except Exception as e:
        print(f"[UPLOADED] Error reading WG conf {file_path}: {e}")
        return None

    if not config.has_section("Interface") or not config.has_section("Peer"):
        return None

    interface = config["Interface"]
    peer = config["Peer"]

    private_key = interface.get("PrivateKey", "").strip()
    address = interface.get("Address", "").strip()
    endpoint = peer.get("Endpoint", "").strip()
    public_key = peer.get("PublicKey", "").strip()

    if not private_key or not endpoint or not public_key:
        return None

    ip_address = (
        address.split(",")[0].strip()
        if address
        else "10.2.0.2/32"
    )

    # Endpoint может быть:
    # example.com:2408
    # [IPv6]:2408
    if endpoint.startswith("["):
        end = endpoint.find("]")
        if end == -1:
            return None
        server = endpoint[1:end]
        rest = endpoint[end + 1:]
        if not rest.startswith(":"):
            return None
        port = int(rest[1:])
    else:
        server, sep, port_str = endpoint.rpartition(":")
        if not sep:
            return None
        port = int(port_str)

    proxy_name = os.path.splitext(
        os.path.basename(file_path)
    )[0]

    proxy = {
        "type": "wireguard",
        "name": proxy_name,
        "server": server,
        "port": port,
        "ip": ip_address.split("/")[0],
        "private-key": private_key,
        "public-key": public_key,
        "udp": True,
        "provider": "warp",
        "protocol": "wireguard",
    }

    # Остальные WG-параметры.
    if interface.get("DNS"):
        proxy["dns"] = [
            x.strip()
            for x in interface.get("DNS").replace(",", " ").split()
            if x.strip()
        ]

    if interface.get("MTU"):
        try:
            proxy["mtu"] = int(interface.get("MTU"))
        except ValueError:
            pass

    if peer.get("AllowedIPs"):
        proxy["allowed-ips"] = [
            x.strip()
            for x in peer.get("AllowedIPs").replace(",", " ").split()
            if x.strip()
        ]
    else:
        proxy["allowed-ips"] = ["0.0.0.0/0"]

    # AmneziaWG parameters.
    awg = {}

    for key in (
        "Jc", "Jmin", "Jmax",
        "S1", "S2",
        "H1", "H2", "H3", "H4",
        "I1", "I2", "I3", "I4", "I5",
    ):
        if interface.get(key) is not None:
            value = interface.get(key)

            try:
                value = int(value)
            except ValueError:
                pass

            awg[key.lower()] = value

    # Некоторые конфиги кладут AWG параметры в Peer.
    for key in (
        "Jc", "Jmin", "Jmax",
        "S1", "S2",
        "H1", "H2", "H3", "H4",
        "I1", "I2", "I3", "I4", "I5",
    ):
        if peer.get(key) is not None:
            value = peer.get(key)

            try:
                value = int(value)
            except ValueError:
                pass

            awg[key.lower()] = value

    if awg:
        proxy["amnezia-wg-option"] = awg
        proxy["protocol"] = "amnezia-wg"

    return normalize_proxy(proxy, file_path)


def load_yaml_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"[UPLOADED] Error reading YAML {file_path}: {e}")
        return []

    result = []

    if isinstance(data, list):
        for item in data:
            item = normalize_proxy(item, file_path)
            if item:
                result.append(item)

    elif isinstance(data, dict):
        # Один proxy.
        if "type" in data and "name" in data:
            item = normalize_proxy(data, file_path)
            if item:
                result.append(item)

        # Возможный формат:
        # proxies:
        #   - ...
        elif isinstance(data.get("proxies"), list):
            for item in data["proxies"]:
                item = normalize_proxy(item, file_path)
                if item:
                    result.append(item)

    return result


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    all_proxies = []

    print(f"[UPLOADED PROVIDER] Scanning directory: {UPLOADED_DIR}")

    yaml_files = sorted(
        glob.glob(os.path.join(UPLOADED_DIR, "*.yaml"))
        + glob.glob(os.path.join(UPLOADED_DIR, "*.yml"))
    )

    print(
        f"[UPLOADED PROVIDER] Found YAML files: {len(yaml_files)}"
    )

    for file_path in yaml_files:
        proxies = load_yaml_file(file_path)

        if proxies:
            all_proxies.extend(proxies)
            print(
                f"[UPLOADED] Loaded {len(proxies)} proxies "
                f"from {os.path.basename(file_path)}"
            )

    conf_files = sorted(
        glob.glob(os.path.join(UPLOADED_DIR, "*.conf"))
        + glob.glob(os.path.join(UPLOADED_DIR, "*.ini"))
    )

    print(
        f"[UPLOADED PROVIDER] Found WG/AWG .conf files: "
        f"{len(conf_files)}"
    )

    for file_path in conf_files:
        proxy = parse_wg_conf(file_path)

        if proxy:
            all_proxies.append(proxy)
            print(
                f"[UPLOADED] Loaded WG/AWG proxy from "
                f"{os.path.basename(file_path)}"
            )

    # Финальная нормализация всех нод.
    normalized = []

    for proxy in all_proxies:
        proxy = normalize_proxy(proxy)

        if proxy:
            normalized.append(proxy)

    all_proxies = deduplicate_proxies(normalized)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(
            all_proxies,
            f,
            indent=2,
            ensure_ascii=False
        )

    warp = [
        x for x in all_proxies
        if x.get("provider") == "warp"
    ]

    wg = [
        x for x in all_proxies
        if x.get("protocol") == "wireguard"
    ]

    awg = [
        x for x in all_proxies
        if x.get("protocol") == "amnezia-wg"
    ]

    print()
    print("=== UPLOADED RESULT ===")
    print(f"Total:       {len(all_proxies)}")
    print(f"WARP:        {len(warp)}")
    print(f"WireGuard:   {len(wg)}")
    print(f"AWG:         {len(awg)}")
    print(f"Saved:       {OUTPUT}")


if __name__ == "__main__":
    main()
