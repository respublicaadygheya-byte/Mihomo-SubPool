#!/usr/bin/env python3
"""Importer with safe upstream fetching (SSRF guard, size limits, pinned DNS)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from safety import UnsafeAddress, safe_fetch  # noqa: E402
from util import ParseError, proxy_key  # noqa: E402

# DISABLED 2026-11-20: HTTP 404, source/file no longer exists
# "https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/top_600.txt",
# "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/23.txt",

SOURCES = [
    # DISABLED 2026-11-20 by user request: overloaded nodes, YouTube video fails
    # ("igareck_BLACK", "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt"),
    ("hiztin_PO_GRIBI", "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt"),
    ("igareck_WHITE", "https://raw.githack.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"),
]


def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else "cache/imported/raw_proxies.txt"
    out_dir = os.path.dirname(output_file) or "."
    os.makedirs(out_dir, exist_ok=True)
    all_lines, sources = [], {}

    for label, url in SOURCES:
        print(f"Download: {url} [{label}]")
        try:
            data = safe_fetch(url)
        except (ParseError, UnsafeAddress) as exc:
            print(f"  ERROR: {exc}")
            continue
        lines = [line.strip() for line in data.splitlines() if line.strip()]
        all_lines.extend(lines)
        for line in lines:
            key = proxy_key(line)
            if key:
                sources[key] = label

    Path(output_file).write_text("\n".join(all_lines) + "\n", encoding="utf-8")
    Path(out_dir, "sources.json").write_text(json.dumps(sources, ensure_ascii=False), encoding="utf-8")
    print(f"Skachano vsego strok: {len(all_lines)}")
    print(f"Source map: {len(sources)} keys")


if __name__ == "__main__":
    main()
