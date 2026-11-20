#!/usr/bin/env python3
"""YouTube second-stage checker with double validation, ping sorting and source quotas."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed

MIHOMO = "./bin/mihomo.bin"
TEST_URL = "http://www.youtube.com/generate_204"
MAX_WORKERS = 10
TIMEOUT = 8
RECHECK_DELAY = 2
CAP_RATIO = 0.40

SOURCES_FILE = Path("cache/imported/sources.json")


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_config(proxy, port):
    return {
        "mixed-port": port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "info",
        "proxies": [proxy],
        "proxy-groups": [
            {"name": "TEST", "type": "select", "proxies": [proxy["name"]]}
        ],
        "rules": ["MATCH,TEST"],
    }


def attempt(proxy_url):
    t0 = time.time()
    try:
        response = requests.get(
            TEST_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        latency = int((time.time() - t0) * 1000)
        if response.status_code in (200, 204):
            return True, latency, None
        return False, latency, f"HTTP {response.status_code}"
    except Exception as e:
        return False, None, str(e)[:300]


def check_one(proxy):
    diag = {
        "name": proxy.get("name"),
        "source": proxy.get("_source", "UNKNOWN"),
        "server": proxy.get("server"),
        "port": proxy.get("port"),
        "protocol": proxy.get("type"),
        "error": None,
        "reason": None,
        "latency_ms": None,
        "attempts": 0,
    }
    proc = None
    try:
        port = get_free_port()
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = os.path.join(tmp, "config.yaml")
            with open(cfg_file, "w", encoding="utf-8") as f:
                yaml.safe_dump(make_config(proxy, port), f, allow_unicode=True, sort_keys=False)

            proc = subprocess.Popen(
                [MIHOMO, "-d", tmp, "-f", cfg_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )

            deadline = time.time() + 5
            port_open = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    diag["error"] = "mihomo exited early"
                    return None, diag
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex(("127.0.0.1", port)) == 0:
                        port_open = True
                        break
                time.sleep(0.1)

            if not port_open:
                diag["error"] = "local proxy port not open"
                return None, diag

            proxy_url = f"http://127.0.0.1:{port}"

            # First check
            ok1, lat1, err1 = attempt(proxy_url)
            diag["attempts"] = 1
            if not ok1:
                diag["error"] = err1
                return None, diag

            # Second check after short delay (filters flapping nodes)
            time.sleep(RECHECK_DELAY)
            ok2, lat2, err2 = attempt(proxy_url)
            diag["attempts"] = 2
            if not ok2:
                diag["error"] = err2
                diag["reason"] = "failed_recheck"
                return None, diag

            latency = int(((lat1 or 0) + (lat2 or 0)) / 2)
            diag["latency_ms"] = latency
            out = dict(proxy)
            out["latency"] = latency
            return out, diag
    except Exception as e:
        diag["error"] = str(e)[:300]
        return None, diag
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def apply_quota(passing, diagnostics):
    cap = max(5, int(len(passing) * CAP_RATIO))
    counts = {}
    kept = []
    for p in passing:
        src = p.get("_source", "UNKNOWN")
        if src == "UPLOADED/WARP":
            kept.append(p)
            continue
        if counts.get(src, 0) >= cap:
            diagnostics.append({
                "name": p.get("name"),
                "source": src,
                "reason": "source_quota",
                "latency_ms": p.get("latency"),
            })
            continue
        counts[src] = counts.get(src, 0) + 1
        kept.append(p)
    return kept, cap


def main():
    if len(sys.argv) < 3:
        print("Usage: checker_youtube.py input.json output.json [diagnostics.json]")
        sys.exit(1)

    inp, outp = sys.argv[1], sys.argv[2]
    diagp = sys.argv[3] if len(sys.argv) > 3 else "youtube.diagnostics.json"

    srcmap = {}
    if SOURCES_FILE.exists():
        srcmap = json.load(open(SOURCES_FILE, encoding="utf-8"))

    proxies = json.load(open(inp, encoding="utf-8"))
    for p in proxies:
        key = f"{p.get('server')}|{p.get('port')}|{p.get('uuid') or p.get('password')}"
        if "_source" not in p:
            p["_source"] = srcmap.get(key, "UPLOADED/WARP")

    print(f"YouTube check (double): {len(proxies)} proxies -> {TEST_URL}")

    passing, failed = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_one, p): p for p in proxies}
        for i, fut in enumerate(as_completed(futures), 1):
            p = futures[fut]
            try:
                result, diag = fut.result()
            except Exception as e:
                result, diag = None, {"name": p.get("name"), "source": p.get("_source"), "error": str(e)}
            if result:
                passing.append(result)
                print(f"[{i}/{len(proxies)}] OK {diag['name']} {diag['latency_ms']}ms [{diag['source']}]")
            else:
                failed.append(diag)
                print(f"[{i}/{len(proxies)}] FAIL {diag['name']} | {diag.get('reason') or diag.get('error')} [{diag['source']}]")

    total_before = len(passing)
    passing, cap = apply_quota(passing, failed)
    passing.sort(key=lambda x: x.get("latency", 999999))

    json.dump(passing, open(outp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump(failed, open(diagp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    from collections import Counter
    print()
    print("=== YOUTUBE CHECK RESULT ===")
    print(f"Input:          {len(proxies)}")
    print(f"Passed (raw):   {total_before}")
    print(f"Source cap:     {cap} per source ({int(CAP_RATIO*100)}%)")
    print(f"Kept:           {len(passing)}")
    print(f"Dropped/failed: {len(failed)}")
    print("By source:", dict(Counter(p.get("_source", "UNKNOWN") for p in passing)))
    if passing:
        print(f"Best:  {passing[0]['name']} {passing[0].get('latency')}ms")
        print(f"Worst: {passing[-1]['name']} {passing[-1].get('latency')}ms")


if __name__ == "__main__":
    main()
