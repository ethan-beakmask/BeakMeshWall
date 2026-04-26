"""ManagedRule and DriftEvent models for Stage D drift detection.

See docs/ROADMAP-CONFIG-MANAGEMENT.md section 4.
"""
from datetime import datetime, timezone

from app.extensions import db


class ManagedRule(db.Model):
    """A firewall rule that BMW expects to be present on a given node.

    Created when an apply_rule task succeeds; status flips to 'removed' when a
    remove_rule task succeeds. Drift detection compares the set of rules with
    status='active' against the agent's reported BMW-ID set.
    """

    __tablename__ = "managed_rules"

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("nodes.id"), nullable=False, index=True)
    subsystem = db.Column(db.String(32), nullable=False, default="firewall", index=True)
    fingerprint = db.Column(db.String(32), nullable=False, index=True)
    schema_rule = db.Column(db.Text, nullable=False)  # JSON-serialized SchemaRule
    status = db.Column(db.String(16), nullable=False, default="active", index=True)
    applied_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    removed_at = db.Column(db.DateTime(timezone=True))

    __table_args__ = (
        db.UniqueConstraint(
            "node_id", "subsystem", "fingerprint", name="uq_managed_rule_node_fp"
        ),
    )


class DriftEvent(db.Model):
    """One occurrence of state divergence between expected and actual.

    Recorded regardless of policy; for detect-only it stops here, for notify a
    mail is sent, for overwrite reconcile tasks are also scheduled.
    """

    __tablename__ = "drift_events"

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("nodes.id"), nullable=False, index=True)
    subsystem = db.Column(db.String(32), nullable=False, default="firewall")
    detected_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    missing_in_actual = db.Column(db.Text)  # JSON list of fingerprints expected but absent
    extra_in_actual = db.Column(db.Text)    # JSON list of fingerprints present but unmanaged
    policy_applied = db.Column(db.String(16), nullable=False)  # detect-only / notify / overwrite
    notification_sent = db.Column(db.Boolean, default=False)
    reconcile_task_ids = db.Column(db.Text)  # JSON list of task ids dispatched (overwrite policy)
    backup_path = db.Column(db.String(512))
