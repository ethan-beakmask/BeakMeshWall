"""
Node model representing a managed firewall agent endpoint.
"""

import uuid
from datetime import datetime, timezone, timedelta

from ..extensions import db


class Node(db.Model):
    """A managed node running the BeakMeshWall agent."""

    __tablename__ = 'nodes'

    id = db.Column(
        db.String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    os_info = db.Column(db.String(255))
    agent_version = db.Column(db.String(20))
    agent_secret_hash = db.Column(db.String(256), nullable=False)
    status = db.Column(db.String(20), default='approved')  # approved, disabled
    last_heartbeat_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )

    # Default heartbeat timeout: 90 seconds
    HEARTBEAT_TIMEOUT = 90

    @property
    def is_online(self):
        """Return True if the agent sent a heartbeat within the timeout window."""
        if self.status != 'approved':
            return False
        if self.last_heartbeat_at is None:
            return False
        now = datetime.now(timezone.utc)
        heartbeat = self.last_heartbeat_at
        # Ensure timezone-aware comparison
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        return (now - heartbeat) < timedelta(seconds=self.HEARTBEAT_TIMEOUT)

    def __repr__(self):
        return f'<Node {self.hostname} ({self.id[:8]})>'
