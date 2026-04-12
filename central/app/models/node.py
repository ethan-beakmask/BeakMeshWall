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
    last_counters = db.Column(db.JSON)      # Latest rule counters from agent
    last_tables = db.Column(db.JSON)        # Latest nftables table list from agent
    last_report_at = db.Column(db.DateTime)  # When the agent last sent a report
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

    def to_dict(self):
        """Return a dictionary representation of the node."""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_info': self.os_info,
            'agent_version': self.agent_version,
            'status': self.status,
            'is_online': self.is_online,
            'last_heartbeat_at': (
                self.last_heartbeat_at.isoformat()
                if self.last_heartbeat_at else None
            ),
            'last_counters': self.last_counters,
            'last_tables': self.last_tables,
            'last_report_at': (
                self.last_report_at.isoformat()
                if self.last_report_at else None
            ),
            'created_at': (
                self.created_at.isoformat()
                if self.created_at else None
            ),
            'updated_at': (
                self.updated_at.isoformat()
                if self.updated_at else None
            ),
        }

    def __repr__(self):
        return f'<Node {self.hostname} ({self.id[:8]})>'
