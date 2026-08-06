"""Artifact (de)serialization shared by stage6."""

import json
from typing import Dict, Set, Tuple


def load_program_index(path: str) -> Tuple[dict, Set[str]]:
    """Load program_index.json; return (raw_dict, entrypoint_id_set)."""
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    entrypoints = set(d.get("entrypoints", []))
    return d, entrypoints


def load_order(path: str) -> dict:
    """Load bottom_up_order.json; return dict with order/cycles/unreachable."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
