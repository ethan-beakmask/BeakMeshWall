"""
AuditLog model for recording security-relevant events.
"""

from ..extensions import db


class AuditLog(db.Model):
    """Immutable audit trail entry for system events."""

    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime, server_default=db.func.now(), index=True
    )
    actor = db.Column(db.String(100), nullable=False)
    # Actor format: 'user:admin', 'api:key-name', 'system', 'agent:<id>'
    action = db.Column(db.String(50), nullable=False, index=True)
    # Actions: create_rule, delete_rule, block_threat, unblock_threat,
    #          register_node, task_completed, task_failed, login, logout, etc.
    resource_type = db.Column(db.String(50))
    # Resource types: rule, node, api_key, task, user
    resource_id = db.Column(db.String(50))
    detail = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6

    def to_dict(self):
        """Return a dictionary representation of the audit log entry."""
        return {
            'id': self.id,
            'timestamp': (
                self.timestamp.isoformat() if self.timestamp else None
            ),
            'actor': self.actor,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'detail': self.detail,
            'ip_address': self.ip_address,
        }

    def __repr__(self):
        return f'<AuditLog {self.id} {self.action} by {self.actor}>'
