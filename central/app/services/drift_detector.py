"""Drift detector and policy executor.

Compares the agent-reported managed-area BMW-IDs against the expected set
recorded in managed_rules, records DriftEvent rows, and dispatches actions
according to the per-node-per-subsystem drift policy.

See docs/ROADMAP-CONFIG-MANAGEMENT.md section 4.
"""
import json
from datetime import datetime, timezone
from typing import Iterable

from app.extensions import db
from app.models.managed_rule import DriftEvent, ManagedRule
from app.models.node import Node
from app.models.task import Task

VALID_POLICIES = {"detect-only", "notify", "overwrite"}
DEFAULT_POLICY = "notify"


def get_policy(node: Node, subsystem: str) -> str:
    """Resolve the drift policy for a (node, subsystem) pair.

    Falls back to DEFAULT_POLICY when the node has no policy stored or the
    subsystem is missing from the JSON map.
    """
    if not node.drift_policies:
        return DEFAULT_POLICY
    try:
        policies = json.loads(node.drift_policies)
    except (TypeError, ValueError):
        return DEFAULT_POLICY
    policy = policies.get(subsystem, DEFAULT_POLICY)
    if policy not in VALID_POLICIES:
        return DEFAULT_POLICY
    return policy


def expected_fingerprints(node_id: int, subsystem: str = "firewall") -> set[str]:
    rows = ManagedRule.query.filter_by(
        node_id=node_id, subsystem=subsystem, status="active"
    ).all()
    return {r.fingerprint for r in rows}


def detect_and_handle(
    node: Node, subsystem: str, actual_ids: Iterable[str]
) -> DriftEvent | None:
    """Compare expected vs actual BMW-IDs; record + act if they diverge.

    Returns the DriftEvent created (or None if no drift).
    Caller is responsible for committing the session.
    """
    expected = expected_fingerprints(node.id, subsystem)
    actual = set(actual_ids or [])

    missing = sorted(expected - actual)
    extra = sorted(actual - expected)

    if not missing and not extra:
        return None

    policy = get_policy(node, subsystem)
    event = DriftEvent(
        node_id=node.id,
        subsystem=subsystem,
        detected_at=datetime.now(timezone.utc),
        missing_in_actual=json.dumps(missing),
        extra_in_actual=json.dumps(extra),
        policy_applied=policy,
        notification_sent=False,
    )
    db.session.add(event)
    db.session.flush()

    if policy == "detect-only":
        return event

    if policy in ("notify", "overwrite"):
        try:
            from app.services.drift_notifier import send_drift_alert
            send_drift_alert(node, event, missing=missing, extra=extra)
            event.notification_sent = True
        except Exception as exc:  # noqa: BLE001
            # Notification failure must not block detection logic; record it.
            event.notification_sent = False
            event.backup_path = f"notify-failed: {exc}"

    if policy == "overwrite":
        task_ids = _dispatch_reconcile_tasks(node, missing, extra)
        event.reconcile_task_ids = json.dumps(task_ids)

    return event


def _dispatch_reconcile_tasks(
    node: Node, missing: list[str], extra: list[str]
) -> list[int]:
    """Schedule reconcile tasks for the overwrite policy.

    For each missing fingerprint, the agent will re-apply the schema rule
    pulled from managed_rules. Extra fingerprints are removed via
    `unmanaged_cleanup` action: BMW-IDs not in our expected set may have been
    left over from a different BMW Central or by a manual edit.
    """
    task_ids: list[int] = []

    if missing:
        rules = ManagedRule.query.filter(
            ManagedRule.node_id == node.id,
            ManagedRule.subsystem == "firewall",
            ManagedRule.fingerprint.in_(missing),
            ManagedRule.status == "active",
        ).all()
        for r in rules:
            try:
                rule_obj = json.loads(r.schema_rule)
            except (TypeError, ValueError):
                continue
            t = Task(
                node_id=node.id,
                action="apply_rule",
                payload=json.dumps({"rule": rule_obj}),
                created_by="drift-reconcile",
            )
            db.session.add(t)
            db.session.flush()
            task_ids.append(t.id)

    if extra:
        t = Task(
            node_id=node.id,
            action="cleanup_unmanaged",
            payload=json.dumps({"keep_ids": list(expected_fingerprints(node.id))}),
            created_by="drift-reconcile",
        )
        db.session.add(t)
        db.session.flush()
        task_ids.append(t.id)

    return task_ids


def upsert_managed_rule(
    node_id: int, schema_rule: dict, fingerprint: str, subsystem: str = "firewall"
) -> None:
    """Mark a rule as active for this node. Called when apply_rule succeeds."""
    existing = ManagedRule.query.filter_by(
        node_id=node_id, subsystem=subsystem, fingerprint=fingerprint
    ).first()
    if existing:
        existing.status = "active"
        existing.applied_at = datetime.now(timezone.utc)
        existing.removed_at = None
        existing.schema_rule = json.dumps(schema_rule)
        return
    db.session.add(
        ManagedRule(
            node_id=node_id,
            subsystem=subsystem,
            fingerprint=fingerprint,
            schema_rule=json.dumps(schema_rule),
            status="active",
        )
    )


def mark_managed_rule_removed(
    node_id: int, fingerprint: str, subsystem: str = "firewall"
) -> None:
    """Mark a rule as removed for this node. Called when remove_rule succeeds."""
    existing = ManagedRule.query.filter_by(
        node_id=node_id, subsystem=subsystem, fingerprint=fingerprint
    ).first()
    if not existing:
        return
    existing.status = "removed"
    existing.removed_at = datetime.now(timezone.utc)
