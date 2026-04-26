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


def _is_noop_value(field_name: str, value: Any) -> bool:
    """Whether a field's value is functionally inert and can skip the
    capability check.

    Reason: Stage B added optional fields (log_enabled, state, ...). A rule
    that explicitly sets log_enabled=false or state=[] is semantically
    identical to one that omits them, so capability validation should not
    reject such a rule on a driver that doesn't support the feature.
    """
    if field_name in ("log_enabled",) and not value:
        return True
    if field_name in ("log_prefix", "log_level", "comment") and (value is None or value == ""):
        return True
    if field_name == "state" and (value is None or (isinstance(value, list) and len(value) == 0)):
        return True
    return False


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
        if _is_noop_value(field_name, field_value):
            continue

        field_caps = driver_caps.get(field_name)
        if field_caps is None or not field_caps.get("supported", False):
            reason = (field_caps or {}).get(
                "frozen_reason", f"field '{field_name}' is not implemented for this driver"
            )
            raise RuleValidationError(
                f"driver '{driver}' does not support field '{field_name}': {reason}"
            )

        allowed_values = field_caps.get("values")
        if allowed_values is None:
            continue

        # Enum-array fields (e.g. state): each element must be in allowed.
        if isinstance(field_value, list):
            for v in field_value:
                if v not in allowed_values:
                    raise RuleValidationError(
                        f"driver '{driver}' does not support {field_name} value '{v}'"
                    )
            continue

        if field_value not in allowed_values:
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

    # Stage B: log_prefix and log_level are sub-fields of log_enabled.
    # When logging is off they have no effect, so drop them from the
    # normalized rule. Drivers that don't support Stage B logging will
    # then accept any Stage A rule without tripping on default values.
    if not normalized.get("log_enabled"):
        normalized.pop("log_prefix", None)
        normalized.pop("log_level", None)

    _capability_validate(normalized, driver)
    return normalized


__all__ = [
    "RuleValidationError",
    "validate_rule",
]
