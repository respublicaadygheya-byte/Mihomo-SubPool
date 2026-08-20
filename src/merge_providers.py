import json
from pathlib import Path


IMPORTED = Path("cache/imported/proxies.json")
AVAILABLE = Path("cache/filtered/available.json")
UPLOADED = Path("cache/providers/uploaded-custom.json")
OUTPUT = Path("cache/filtered/all.json")


def load_json(path):
    if not path.exists():
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[MERGE] Error reading {path}: {e}")
        return []

    if not isinstance(data, list):
        print(f"[MERGE] WARNING: {path} does not contain a list")
        return []

    return data


def main():
    imported = load_json(IMPORTED)
    available = load_json(AVAILABLE)
    uploaded = load_json(UPLOADED)

    proxies = []
    proxies.extend(imported)
    proxies.extend(available)
    proxies.extend(uploaded)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(
            proxies,
            f,
            indent=2,
            ensure_ascii=False
        )

    print("=== MERGE RESULT ===")
    print(f"Imported:  {len(imported)}")
    print(f"Available: {len(available)}")
    print(f"Uploaded:  {len(uploaded)}")
    print("WARP:      0")
    print("MASQUE:    0")
    print(f"Total:     {len(proxies)}")


if __name__ == "__main__":
    main()
