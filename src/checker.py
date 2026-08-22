#!/usr/bin/env python3

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

TEST_URL = "https://cp.cloudflare.com/generate_204"

MAX_WORKERS = 10
TIMEOUT = 5

BASE_PORT = 20000
MAX_PORT = BASE_PORT + MAX_WORKERS + 100

_port_lock = threading.Lock()
_next_port = BASE_PORT


def get_free_port():
    """
    Ask OS for an unused local TCP port.

    Avoids exhausting a manual port range during large checks.
    """
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_config(proxy, port):
    return {
        "mixed-port": port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": [
                "https://1.1.1.1/dns-query"
            ]
        },
        "proxies": [
            proxy
        ],
        "proxy-groups": [
            {
                "name": "TEST",
                "type": "select",
                "proxies": [
                    proxy["name"]
                ]
            }
        ],
        "rules": [
            "MATCH,TEST"
        ]
    }


def read_stderr(proc):
    if proc is None or proc.stderr is None:
        return ""

    try:
        if proc.poll() is None:
            return ""

        return proc.stderr.read(10000).strip()

    except Exception:
        return ""



def check_proxy(proxy):
    name = proxy.get("name", "unknown")

    result = {
        "proxy": proxy,
        "stage": "init",
        "error": None,
        "mihomo_log": "",
        "delay_ms": None,
    }

    proc = None

    try:
        port = get_free_port()
        result["port"] = port

        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_config(proxy, port)

            cfg_file = os.path.join(tmp, "config.yaml")

            with open(
                cfg_file,
                "w",
                encoding="utf-8"
            ) as f:
                yaml.safe_dump(
                    cfg,
                    f,
                    allow_unicode=True,
                    sort_keys=False
                )

            result["stage"] = "mihomo_start"

            proc = subprocess.Popen(
                [
                    MIHOMO,
                    "-d",
                    tmp,
                    "-f",
                    cfg_file
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )

            result["stage"] = "local_port"

            deadline = time.time() + 5
            port_open = False

            while time.time() < deadline:

                if proc.poll() is not None:
                    result["mihomo_log"] = read_stderr(proc)

                    result["error"] = (
                        f"Mihomo exited early: "
                        f"{result['mihomo_log'][:1000]}"
                    )

                    return None, result

                with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                ) as s:
                    s.settimeout(0.2)

                    if s.connect_ex(
                        ("127.0.0.1", port)
                    ) == 0:
                        port_open = True
                        break

                time.sleep(0.1)

            if not port_open:
                result["mihomo_log"] = read_stderr(proc)

                result["error"] = (
                    "Mihomo proxy port did not open"
                )

                return None, result

            result["stage"] = "request"

            proxy_url = f"http://127.0.0.1:{port}"

            started = time.monotonic()

            try:
                response = requests.get(
                    TEST_URL,
                    proxies={
                        "http": proxy_url,
                        "https": proxy_url,
                    },
                    timeout=TIMEOUT
                )

            except requests.RequestException as e:
                result["delay_ms"] = round(
                    (time.monotonic() - started) * 1000,
                    1
                )

                result["mihomo_log"] = read_stderr(proc)
                result["error"] = str(e)

                return None, result

            result["delay_ms"] = round(
                (time.monotonic() - started) * 1000,
                1
            )

            result["http_status"] = response.status_code

            if response.status_code in (200, 204):
                result["stage"] = "success"
                return proxy, result

            result["mihomo_log"] = read_stderr(proc)

            result["error"] = (
                f"HTTP status {response.status_code}"
            )

            return None, result

    except Exception as e:
        result["stage"] = "exception"
        result["error"] = str(e)

        if proc is not None:
            result["mihomo_log"] = read_stderr(proc)

        return None, result

    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()

                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        pass


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: checker.py input.json output.json "
            "[diagnostics.json]"
        )
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    if len(sys.argv) >= 4:
        diagnostics_file = sys.argv[3]
    else:
        diagnostics_file = os.path.splitext(
            output_file
        )[0] + ".diagnostics.json"

    with open(
        input_file,
        encoding="utf-8"
    ) as f:
        proxies = json.load(f)

    print(
        f"Проверка прокси: {len(proxies)}"
    )

    working = []
    failed = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                check_proxy,
                proxy
            ): proxy
            for proxy in proxies
        }

        for i, future in enumerate(
            as_completed(futures),
            1
        ):
            proxy = futures[future]

            try:
                result, diagnostic = future.result()

            except Exception as e:
                result = None

                diagnostic = {
                    "proxy": proxy,
                    "stage": "future",
                    "error": str(e),
                    "mihomo_log": "",
                }

            if result:
                working.append(result)

                print(
                    f"[{i}/{len(proxies)}] "
                    f"OK {result.get('name')}"
                )

            else:
                failed.append(diagnostic)

                print(
                    f"[{i}/{len(proxies)}] "
                    f"FAIL {proxy.get('name')} "
                    f"| stage={diagnostic.get('stage')} "
                    f"| {diagnostic.get('error')}"
                )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            working,
            f,
            indent=2,
            ensure_ascii=False
        )

    with open(
        diagnostics_file,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            failed,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("=== CHECK RESULT ===")
    print(f"Input:       {len(proxies)}")
    print(f"Working:     {len(working)}")
    print(f"Failed:      {len(failed)}")
    print(f"Output:      {output_file}")
    print(f"Diagnostics: {diagnostics_file}")

    print()
    print("=== FAILURE STAGES ===")

    stages = {}

    for item in failed:
        stage = item.get("stage", "unknown")
        stages[stage] = stages.get(stage, 0) + 1

    for stage, count in sorted(
        stages.items(),
        key=lambda x: (-x[1], x[0])
    ):
        print(f"{stage:20} {count}")


if __name__ == "__main__":
    main()
