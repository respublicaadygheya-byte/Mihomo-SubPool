#!/usr/bin/env python3
"""NON-BLOCKING social-media reachability check.
Checks Telegram / Instagram / WhatsApp per proxy, records latency + results in diagnostics,
sorts by latency, but ALWAYS outputs all input proxies (never returns empty).
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

import requests
import yaml

MIHOMO = "./bin/mihomo.bin"
MAX_WORKERS = 10
TIMEOUT = 6
ENDPOINTS = [
    ("telegram", "https://api.telegram.org/"),
    ("instagram", "https://www.instagram.com/"),
    ("whatsapp", "https://www.whatsapp.com/"),
]
OUT_DIR = "cache/filtered"


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check_one(proxy):
    name = proxy.get("name", "unknown")
    info = {
        "name": name,
        "source": proxy.get("_source", "UNKNOWN"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "results": {},
        "latency_ms": None,
    }
    proc = None
    try:
        port = get_free_port()
        cfg = {
            "mixed-port": port,
            "allow-lan": False,
            "mode": "global",
            "log-level": "info",
            "proxies": [proxy],
            "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [proxy["name"]]}],
            "rules": ["MATCH,TEST"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = os.path.join(tmp, "config.yaml")
            with open(cfg_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
            proc = subprocess.Popen(
                [MIHOMO, "-d", tmp, "-f", cfg_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            )
            deadline = time.time() + 5
            port_open = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    return proxy, info
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        port_open = True
                        break
                time.sleep(0.1)
            if not port_open:
                return proxy, info

            pu = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
            latencies = []
            for label, url in ENDPOINTS:
                t0 = time.time()
                try:
                    r = requests.get(
                        url, proxies=pu, timeout=TIMEOUT,
                        headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True,
                    )
                    ms = int((time.time() - t0) * 1000)
                    ok = r.status_code in (200, 204, 301, 302, 401, 403)
                    info["results"][label] = f"{r.status_code}/{ms}ms" + ("" if ok else " BAD")
                    if ok:
                        latencies.append(ms)
                except Exception as e:
                    info["results"][label] = "ERR:" + str(e)[:30]
            if latencies:
                info["latency_ms"] = int(sum(latencies) / len(latencies))
            return proxy, info
    except Exception as e:
        info["results"]["exception"] = str(e)[:50]
        return proxy, info
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def main():
    inp = sys.argv[1] if len(sys.argv) > 1 else f"{OUT_DIR}/available.json"
    outp = sys.argv[2] if len(sys.argv) > 2 else f"{OUT_DIR}/social-sorted.json"
    diagp = sys.argv[3] if len(sys.argv) > 3 else f"{OUT_DIR}/social.diagnostics.json"

    proxies = json.load(open(inp, encoding="utf-8"))
    print(f"SOCIAL check (non-blocking): {len(proxies)} proxies -> " +
          ", ".join(label for label, _ in ENDPOINTS))

    enriched, diagnostics = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_one, p): p for p in proxies}
        for i, fut in enumerate(as_completed(futures), 1):
            proxy, info = fut.result()
            enriched.append((proxy, info))
            diagnostics.append(info)
            if i % 20 == 0:
                print(f"  checked {i}/{len(proxies)}")

    # Sort: reachable-first, then by latency; unreachable keep original order at the end
    reachable = [(p, i) for p, i in enriched if i["latency_ms"] is not None]
    unreachable = [(p, i) for p, i in enriched if i["latency_ms"] is None]
    reachable.sort(key=lambda x: x[1]["latency_ms"])
    ordered = [p for p, _ in reachable] + [p for p, _ in unreachable]

    json.dump(ordered, open(outp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump(diagnostics, open(diagp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    print()
    print("=== SOCIAL CHECK RESULT (non-blocking) ===")
    print(f"Input:      {len(proxies)}")
    print(f"Output:     {len(ordered)} (always all, never empty)")
    print(f"Reachable:  {len(reachable)}")
    for label, _ in ENDPOINTS:
        n = sum(1 for d in diagnostics if not str(d["results"].get(label, "")).startswith(("ERR", "502")))
        print(f"  {label:12} {n}")
    print("By source:", dict(Counter(p.get("_source", "UNKNOWN") for p in ordered)))
    if reachable:
        print(f"Best:  {reachable[0][1]['name']} {reachable[0][1]['latency_ms']}ms")
        print(f"Worst: {reachable[-1][1]['name']} {reachable[-1][1]['latency_ms']}ms")


if __name__ == "__main__":
    main()
