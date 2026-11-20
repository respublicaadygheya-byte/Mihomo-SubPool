#!/usr/bin/env python3
import json
import os
import re
import urllib.request
import base64
import sys

# DISABLED 2026-11-20: HTTP 404, source/file no longer exists
# "https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/top_600.txt",
# "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/23.txt",

SOURCES = [
    ("igareck_BLACK", "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt"),
    ("hiztin_PO_GRIBI", "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt"),
    ("igareck_WHITE", "https://raw.githack.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"),
]


def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as response:
            content = response.read().decode("utf-8", errors="ignore").strip()
            if not any(content.startswith(p) for p in ["vless://", "hysteria2://", "hy2://", "ss://", "trojan://"]):
                try:
                    decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                    if any(p in decoded for p in ["vless://", "hy2://", "hysteria2://"]):
                        return decoded
                except Exception:
                    pass
            return content
    except Exception as e:
        print(f"Oshibka skachivaniya {url}: {e}")
        return ""


def proxy_key(line):
    m = re.match(r'vless://([^@]+)@([^/:]+):(\d+)', line.strip())
    if m:
        return f"{m.group(2)}|{m.group(3)}|{m.group(1)}"
    m = re.match(r'(?:hysteria2|hy2)://([^@]+)@([^/:]+):(\d+)', line.strip())
    if m:
        return f"{m.group(2)}|{m.group(3)}|{m.group(1)}"
    return None


def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else "cache/imported/raw_proxies.txt"
    out_dir = os.path.dirname(output_file) or "."
    os.makedirs(out_dir, exist_ok=True)
    all_lines = []
    sources = {}

    for label, url in SOURCES:
        print(f"Download: {url} [{label}]")
        data = fetch_url(url)
        if not data:
            continue
        lines = [line.strip() for line in data.splitlines() if line.strip()]
        all_lines.extend(lines)
        for line in lines:
            key = proxy_key(line)
            if key:
                sources[key] = label

    with open(output_file, "w", encoding="utf-8") as f:
        for line in all_lines:
            f.write(line + "\n")

    with open(os.path.join(out_dir, "sources.json"), "w", encoding="utf-8") as f:
        json.dump(sources, f, ensure_ascii=False)

    print(f"Skachano vsego strok: {len(all_lines)}")
    print(f"Source map: {len(sources)} keys")


if __name__ == "__main__":
    main()
