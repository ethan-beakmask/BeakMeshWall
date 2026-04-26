"""JSON schema and driver capability loaders.

See docs/ROADMAP-CONFIG-MANAGEMENT.md for the normative spec.
"""
import json
from functools import lru_cache
from pathlib import Path

_SCHEMA_DIR = Path(__file__).parent


@lru_cache(maxsize=1)
def load_firewall_rule_schema() -> dict:
    with (_SCHEMA_DIR / "firewall_rule.json").open("r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_driver_capabilities() -> dict:
    with (_SCHEMA_DIR / "driver_capabilities.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def supported_drivers() -> list[str]:
    return list(load_driver_capabilities()["drivers"].keys())
