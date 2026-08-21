#!/usr/bin/env python3

import json
from pathlib import Path

from src.core.fingerprint import proxy_fingerprint


IMPORTED = Path("cache/imported/proxies.json")
UPLOADED = Path("cache/providers/uploaded-custom.json")
OUTPUT = Path("cache/filtered/all.json")


def load_json(path):

    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

    except Exception as e:
        print(f"[MERGE] Error reading {path}: {e}")

    return []


def deduplicate(proxies):

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

    return result, removed


def main():

    imported = load_json(IMPORTED)
    uploaded = load_json(UPLOADED)

    combined = imported + uploaded

    print("=== MERGE RESULT ===")
    print(f"Imported: {len(imported)}")
    print(f"Uploaded:  {len(uploaded)}")
    print(f"Before dedupe: {len(combined)}")


    merged, removed = deduplicate(combined)


    print(f"After dedupe:  {len(merged)}")
    print(f"Removed: {removed}")


    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            merged,
            f,
            indent=2,
            ensure_ascii=False
        )


    print(f"Output: {OUTPUT}")


if __name__ == "__main__":
    main()
