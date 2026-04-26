"""JSON schema and driver capability loaders, plus rule fingerprint.

See docs/ROADMAP-CONFIG-MANAGEMENT.md for the normative spec.
"""
import hashlib
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


@lru_cache(maxsize=1)
def load_nginx_rule_schema() -> dict:
    with (_SCHEMA_DIR / "nginx_rule.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def supported_drivers() -> list[str]:
    return list(load_driver_capabilities()["drivers"].keys())


def nginx_fingerprint(rule: dict) -> str:
    """Short stable id for an nginx access rule. Identical to Go side.

    Canonical form: {"A": action, "S": src} JSON-encoded with no whitespace,
    sha256, take first 8 hex chars. Comment excluded (re-comment must not
    change id).
    """
    canon = {"A": rule.get("action", "") or "", "S": rule.get("src", "") or ""}
    encoded = json.dumps(canon, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:8]


def fingerprint(rule: dict) -> str:
    """Short stable id for a rule, identical to driver.Fingerprint() in Go.

    The canonical form is a JSON object with keys A,D,P,S,T,SP,DP in that
    declaration order, with empty values defaulting to "any" for the
    optional matching fields. Comment is intentionally excluded so that
    re-comments do not change the id.

    The Go and Python implementations must stay byte-identical or rule
    identification across central/agent will break.
    """
    canon = {
        "A": rule.get("action", "") or "",
        "D": rule.get("direction", "") or "",
        "P": rule.get("proto") or "any",
        "S": rule.get("src") or "any",
        "T": rule.get("dst") or "any",
        "SP": rule.get("sport") or "any",
        "DP": rule.get("dport") or "any",
    }
    encoded = json.dumps(canon, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:8]
