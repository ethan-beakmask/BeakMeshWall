"""
User model for local authentication.
"""

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import db


class User(UserMixin, db.Model):
    """Local user account for Central Server authentication."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(120))
    role = db.Column(db.String(20), nullable=False, default='viewer')  # admin, operator, viewer
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), onupdate=db.func.now()
    )
    last_login_at = db.Column(db.DateTime)

    def set_password(self, password):
        """Hash and store the password. Never store plaintext."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        """Return True if user has admin role."""
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username}>'
