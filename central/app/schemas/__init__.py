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

    Canonical key order: A, D, P, S, T, SP, DP, ST, LE, LP, LL, RL, SS, DS.
    Defaults are inserted for omitted fields so logically equivalent rules
    produce the same id. Comment is excluded.

    Schema-evolution warning: changing this canonical form invalidates all
    previously computed fingerprints, including any persisted ManagedRule
    rows. Coordinate with driver.Fingerprint in Go.
    """
    state = rule.get("state") or []
    state_canon = ",".join(sorted(state))
    rl = rule.get("rate_limit") or {}
    rl_canon = ""
    if rl:
        rl_canon = f"{rl.get('count','')}/{rl.get('period','')}/{rl.get('burst', 0)}"
    canon = {
        "A": rule.get("action", "") or "",
        "D": rule.get("direction", "") or "",
        "P": rule.get("proto") or "any",
        "S": rule.get("src") or "any",
        "T": rule.get("dst") or "any",
        "SP": rule.get("sport") or "any",
        "DP": rule.get("dport") or "any",
        "ST": state_canon,
        "LE": bool(rule.get("log_enabled", False)),
        "LP": rule.get("log_prefix") or "BMW: ",
        "LL": rule.get("log_level") or "info",
        "RL": rl_canon,
        "SS": rule.get("src_set") or "",
        "DS": rule.get("dst_set") or "",
    }
    encoded = json.dumps(canon, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:8]
