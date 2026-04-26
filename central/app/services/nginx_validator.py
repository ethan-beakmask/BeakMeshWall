"""Nginx rule validator (Stage alpha).

See docs/NGINX-MANAGEMENT.md section 3.
"""
from typing import Any

from jsonschema import Draft202012Validator

from app.schemas import load_nginx_rule_schema


class NginxRuleValidationError(ValueError):
    """Raised when an nginx rule fails schema validation."""


def validate_nginx_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate an nginx rule against the Stage alpha schema.

    Returns a normalized copy of the rule (currently identical to input;
    the schema has no fields with defaults). Raises NginxRuleValidationError
    on any violation.

    Unlike firewall rules, nginx rules have no per-driver capability check:
    nginx behavior is uniform across distros, and we generate a single
    canonical config file.
    """
    if not isinstance(rule, dict):
        raise NginxRuleValidationError("rule must be an object")

    schema = load_nginx_rule_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(rule), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors
        )
        raise NginxRuleValidationError(f"schema validation failed: {details}")

    return dict(rule)
