"""Safe YAML loader with size / node limits (ported from SubConv/yaml_utils.py)."""
from __future__ import annotations

import yaml

from util import MAX_CONTENT_BYTES, MAX_PROXY_NODES

MAX_DEPTH = 100


def _check(value, depth: int, state: list[int]) -> None:
    state[0] += 1
    if state[0] > MAX_PROXY_NODES:
        raise ValueError("YAML structure exceeds node limit")
    if depth > MAX_DEPTH:
        raise ValueError("YAML structure exceeds depth limit")
    if isinstance(value, dict):
        for k, v in value.items():
            _check(k, depth + 1, state)
            _check(v, depth + 1, state)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _check(item, depth + 1, state)
    elif isinstance(value, str):
        state[1] += len(value.encode("utf-8"))
        if state[1] > MAX_CONTENT_BYTES:
            raise ValueError("YAML structure exceeds size limit")


def load_yaml_safe(text: str):
    if len(text.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise ValueError("Subscription exceeds size limit")
    loader = yaml.SafeLoader(text)
    loader.construct_mapping = _limited_mapping(loader)
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    _check(data, 0, [0, 0])
    return data


def _limited_mapping(loader):
    original = yaml.SafeLoader.construct_mapping

    def construct(node, deep=False):
        if len(node.value) > MAX_PROXY_NODES:
            raise ValueError("YAML mapping exceeds node limit")
        return original(loader, node, deep)

    return construct


def dump_yaml(data) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)
