"""
FirewallRule model representing an IP-based firewall rule managed by BeakMeshWall.
"""

from datetime import datetime, timezone

from ..extensions import db


class FirewallRule(db.Model):
    """A firewall rule (block/allow) applied to one or all managed nodes."""

    __tablename__ = 'firewall_rules'

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(
        db.String(36), db.ForeignKey('nodes.id'), nullable=True
    )  # null = applies to all nodes
    rule_type = db.Column(db.String(20), nullable=False)  # block, allow, custom
    ip_address = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    direction = db.Column(db.String(10), default='inbound')  # inbound, outbound, both
    action = db.Column(db.String(10), default='drop')  # drop, accept, reject
    comment = db.Column(db.String(255))
    source = db.Column(db.String(50))  # manual, threat_feed, api
    source_detail = db.Column(db.String(255))  # e.g. "beakplatform:brute_force"
    duration = db.Column(db.Integer)  # seconds, null = permanent
    expires_at = db.Column(db.DateTime)  # computed from duration at creation
    status = db.Column(db.String(20), default='active')  # active, expired, removed
    created_by = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )

    node = db.relationship('Node', backref='firewall_rules')

    @property
    def is_expired(self):
        """Return True if the rule has passed its expiration time."""
        if self.expires_at is None:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def to_dict(self):
        """Full serialization for API responses."""
        return {
            'id': self.id,
            'node_id': self.node_id,
            'rule_type': self.rule_type,
            'ip_address': self.ip_address,
            'direction': self.direction,
            'action': self.action,
            'comment': self.comment,
            'source': self.source,
            'source_detail': self.source_detail,
            'duration': self.duration,
            'expires_at': (
                self.expires_at.isoformat() if self.expires_at else None
            ),
            'status': self.status,
            'created_by': self.created_by,
            'created_at': (
                self.created_at.isoformat() if self.created_at else None
            ),
            'updated_at': (
                self.updated_at.isoformat() if self.updated_at else None
            ),
        }

    def __repr__(self):
        target = self.node_id[:8] if self.node_id else 'ALL'
        return f'<FirewallRule {self.id} {self.rule_type} {self.ip_address} -> {target}>'
