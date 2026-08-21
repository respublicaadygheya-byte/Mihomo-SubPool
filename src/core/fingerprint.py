#!/usr/bin/env python3

import hashlib
import json


IGNORE_FIELDS = {
    "name",
    "_uploaded_source",
    "alive",
    "latency",
    "delay",
    "ping",
}


def normalize(value):

    if value is None:
        return ""

    if isinstance(value, dict):
        return {
            k: normalize(v)
            for k, v in sorted(value.items())
            if k not in IGNORE_FIELDS
        }

    if isinstance(value, list):
        return sorted(
            normalize(x)
            for x in value
        )

    return value


def proxy_fingerprint(proxy):
    """
    Stable fingerprint.

    WARP:
    same endpoint + keys = same node.

    Others:
    full normalized config.
    """

    provider = proxy.get("provider")
    protocol = proxy.get("protocol")

    if provider == "warp":

        data = {
            "protocol": protocol,
            "server": proxy.get("server"),
            "port": proxy.get("port"),
            "private-key": proxy.get("private-key"),
            "public-key": proxy.get("public-key"),
            "ip": proxy.get("ip"),
            "amnezia-wg-option": proxy.get(
                "amnezia-wg-option",
                {}
            ),
            "type": proxy.get("type"),
        }

    else:

        data = normalize(proxy)


    raw = json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()
