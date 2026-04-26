"""Firewall rule validator.

Two-pass validation:
  1. Schema pass: structural / type / enum / pattern check via jsonschema.
  2. Capability pass: every field used must be supported by the target driver,
     and every enum value must be in the driver's supported value set.

See docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.

Raises ValidationError on any violation. Caller (Central API) should map this
to a 400 response with a human-readable detail.
"""
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as _JSONSchemaError

from app.schemas import load_driver_capabilities, load_firewall_rule_schema


class RuleValidationError(ValueError):
    """Raised when a rule fails schema or capability validation."""


def _schema_validate(rule: dict[str, Any]) -> None:
    schema = load_firewall_rule_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(rule), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors
        )
        raise RuleValidationError(f"schema validation failed: {details}")


def _capability_validate(rule: dict[str, Any], driver: str) -> None:
    caps = load_driver_capabilities()["drivers"]
    if driver not in caps:
        raise RuleValidationError(
            f"unknown driver '{driver}'. Known: {sorted(caps.keys())}"
        )

    driver_caps = caps[driver]["fields"]

    for field_name, field_value in rule.items():
        if field_name == "stage":
            continue

        field_caps = driver_caps.get(field_name)
        if field_caps is None or not field_caps.get("supported", False):
            raise RuleValidationError(
                f"driver '{driver}' does not support field '{field_name}'"
            )

        allowed_values = field_caps.get("values")
        if allowed_values is not None and field_value not in allowed_values:
            unsupported = field_caps.get("unsupported_values", {})
            reason = unsupported.get(
                field_value, f"not in supported set {allowed_values}"
            )
            raise RuleValidationError(
                f"driver '{driver}' does not support {field_name}='{field_value}': {reason}"
            )


def validate_rule(rule: dict[str, Any], driver: str) -> dict[str, Any]:
    """Validate a rule against the schema and a target driver's capabilities.

    Returns the rule dict with defaults applied (proto, src, dst, sport, dport
    default to 'any' if missing). Raises RuleValidationError on any violation.
    """
    if not isinstance(rule, dict):
        raise RuleValidationError("rule must be an object")

    _schema_validate(rule)

    normalized = dict(rule)
    schema = load_firewall_rule_schema()
    for field, spec in schema["properties"].items():
        if field not in normalized and "default" in spec:
            normalized[field] = spec["default"]

    _capability_validate(normalized, driver)
    return normalized


__all__ = [
    "RuleValidationError",
    "validate_rule",
]
