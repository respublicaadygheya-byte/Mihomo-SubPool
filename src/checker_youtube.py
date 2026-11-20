#!/usr/bin/env python3
"""Second-stage checker: keep only proxies that can actually reach YouTube.
Measures response time (ping) to YouTube and sorts passing proxies by latency.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed

MIHOMO = "./bin/mihomo.bin"
TEST_URL = "http://www.youtube.com/generate_204"
MAX_WORKERS = 10
TIMEOUT = 8


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
        "ipv6": False,
        "dns": {"enable": False},
        "proxies": [proxy],
        "proxy-groups": [
            {"name": "TEST", "type": "select", "proxies": [proxy["name"]]}
        ],
        "rules": ["MATCH,TEST"],
    }


def check_one(proxy):
    name = proxy.get("name", "unknown")
    diag = {"name": name, "error": None, "latency_ms": None, "status": None}
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
            t0 = time.time()
            try:
                response = requests.get(
                    TEST_URL,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=TIMEOUT,
                    allow_redirects=True,
                    verify=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                status = response.status_code
            except Exception as e:
                diag["error"] = str(e)[:300]
                return None, diag

            latency_ms = int((time.time() - t0) * 1000)
            diag["status"] = status
            diag["latency_ms"] = latency_ms
            if status in (200, 204):
                out = dict(proxy)
                out["latency"] = latency_ms
                return out, diag
            diag["error"] = f"HTTP {status}"
            return None, diag
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


def main():
    if len(sys.argv) < 3:
        print("Usage: checker_youtube.py input.json output.json [diagnostics.json]")
        sys.exit(1)

    inp, outp = sys.argv[1], sys.argv[2]
    diagp = sys.argv[3] if len(sys.argv) > 3 else "youtube.diagnostics.json"

    proxies = json.load(open(inp, encoding="utf-8"))
    print(f"YouTube check: {len(proxies)} proxies -> {TEST_URL}")

    passing, failed = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check_one, p): p for p in proxies}
        for i, fut in enumerate(as_completed(futures), 1):
            p = futures[fut]
            try:
                result, diag = fut.result()
            except Exception as e:
                result, diag = None, {"name": p.get("name"), "error": str(e)}
            if result:
                passing.append(result)
                print(f"[{i}/{len(proxies)}] OK {diag['name']} {diag['latency_ms']}ms")
            else:
                failed.append(diag)
                print(f"[{i}/{len(proxies)}] FAIL {diag['name']} | {diag.get('error')}")

    passing.sort(key=lambda x: x.get("latency", 999999))
    json.dump(passing, open(outp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump(failed, open(diagp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

    print()
    print("=== YOUTUBE CHECK RESULT ===")
    print(f"Input:    {len(proxies)}")
    print(f"Passed:   {len(passing)}")
    print(f"Failed:   {len(failed)}")
    if passing:
        print(f"Best:     {passing[0]['name']} {passing[0].get('latency')}ms")
        print(f"Worst:    {passing[-1]['name']} {passing[-1].get('latency')}ms")


if __name__ == "__main__":
    main()
