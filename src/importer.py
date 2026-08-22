#!/usr/bin/env python3
import urllib.request
import base64
import sys
import os

SOURCES = [
    "https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/top_600.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/23.txt",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://cloudioxa.duckdns.org/s/XQaBflDpwPvLXDDvL1FVg1dWJmFlRtBdISOf5EMchf9hdGT4/RIXXX/b64"
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

def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else "cache/imported/raw_proxies.txt"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    all_lines = []

    for url in SOURCES:
        print(f"Download: {url}")
        data = fetch_url(url)
        if data:
            lines = [line.strip() for line in data.splitlines() if line.strip()]
            all_lines.extend(lines)

    with open(output_file, "w", encoding="utf-8") as f:
        for line in all_lines:
            f.write(line + "\n")

    print(f"Skachano vsego strok: {len(all_lines)}")

if __name__ == "__main__":
    main()
