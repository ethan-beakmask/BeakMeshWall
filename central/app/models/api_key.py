"""
API Key and Registration Token models.
"""

from datetime import datetime, timezone

from ..extensions import db


class APIKey(db.Model):
    """API key for system-to-system integration."""

    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    key_hash = db.Column(db.String(256), nullable=False)
    prefix = db.Column(db.String(8), nullable=False)  # first 8 chars for identification
    scope = db.Column(db.String(20), default='full')  # full, threat_only
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    last_used_at = db.Column(db.DateTime)

    created_by = db.relationship('User', backref='api_keys', lazy=True)

    @property
    def is_expired(self):
        """Return True if the key has passed its expiration date."""
        if self.expires_at is None:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def __repr__(self):
        return f'<APIKey {self.prefix}... ({self.name})>'


class RegistrationToken(db.Model):
    """One-time (or multi-use) token for agent registration."""

    __tablename__ = 'registration_tokens'

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(256), nullable=False)
    prefix = db.Column(db.String(8), nullable=False)
    description = db.Column(db.String(255))
    max_uses = db.Column(db.Integer, default=1)
    use_count = db.Column(db.Integer, default=0)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    created_by = db.relationship('User', backref='registration_tokens', lazy=True)

    @property
    def is_valid(self):
        """Return True if the token has not expired and has remaining uses."""
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if now > expires:
            return False
        if self.use_count >= self.max_uses:
            return False
        return True

    def __repr__(self):
        return f'<RegistrationToken {self.prefix}... uses={self.use_count}/{self.max_uses}>'
