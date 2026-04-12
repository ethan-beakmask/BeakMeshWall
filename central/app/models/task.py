"""
Task model for dispatching work to agents and tracking execution.
"""

from uuid import uuid4
from datetime import datetime, timezone

from ..extensions import db


class Task(db.Model):
    """A unit of work dispatched to one or more agents.

    Lifecycle: pending -> dispatched -> completed / failed
    """

    __tablename__ = 'tasks'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    module = db.Column(db.String(50), nullable=False, default='firewall')
    action = db.Column(db.String(50), nullable=False)
    params = db.Column(db.JSON, default=dict)
    target_node_id = db.Column(
        db.String(36), db.ForeignKey('nodes.id'), nullable=True
    )  # null = broadcast to all nodes at creation time
    status = db.Column(db.String(20), nullable=False, default='pending')
    result = db.Column(db.JSON)
    error_message = db.Column(db.Text)
    created_by = db.Column(db.String(50))  # username, 'api:<key_name>', 'threat_feed'
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    dispatched_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    target_node = db.relationship('Node', backref='tasks')

    def to_dispatch_dict(self):
        """Serialize for agent poll response."""
        return {
            'id': self.id,
            'module': self.module,
            'action': self.action,
            'params': self.params or {},
        }

    def to_dict(self):
        """Full serialization for API responses."""
        return {
            'id': self.id,
            'module': self.module,
            'action': self.action,
            'params': self.params or {},
            'target_node_id': self.target_node_id,
            'status': self.status,
            'result': self.result,
            'error_message': self.error_message,
            'created_by': self.created_by,
            'created_at': (
                self.created_at.isoformat() if self.created_at else None
            ),
            'dispatched_at': (
                self.dispatched_at.isoformat() if self.dispatched_at else None
            ),
            'completed_at': (
                self.completed_at.isoformat() if self.completed_at else None
            ),
        }

    def __repr__(self):
        return f'<Task {self.id[:8]} {self.module}:{self.action} [{self.status}]>'
