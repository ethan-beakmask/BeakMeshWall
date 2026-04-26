"""NamedSet and NamedSetMember models for P6 Stage C.

Per docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1 (Stage C named sets).
"""
from datetime import datetime, timezone

from app.extensions import db


class NamedSet(db.Model):
    """A named IP set bound to a single node.

    Created when central dispatches a successful create_set task. Removed
    when delete_set succeeds. Sets are referenced by name from schema rules
    via the src_set / dst_set fields.
    """

    __tablename__ = "named_sets"

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("nodes.id"), nullable=False, index=True)
    name = db.Column(db.String(32), nullable=False)
    family = db.Column(db.String(8), nullable=False, default="ipv4")
    created_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    members = db.relationship(
        "NamedSetMember",
        backref="named_set",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        db.UniqueConstraint("node_id", "name", name="uq_named_set_node_name"),
    )


class NamedSetMember(db.Model):
    """One IP / CIDR address within a NamedSet."""

    __tablename__ = "named_set_members"

    id = db.Column(db.Integer, primary_key=True)
    set_id = db.Column(
        db.Integer, db.ForeignKey("named_sets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    address = db.Column(db.String(45), nullable=False)
    added_at = db.Column(
        db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        db.UniqueConstraint("set_id", "address", name="uq_named_set_member"),
    )
