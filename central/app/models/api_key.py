from datetime import datetime, timezone
from app.extensions import db


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(256), unique=True, nullable=False)
    prefix = db.Column(db.String(8), nullable=False)  # First 8 chars for identification
    scope = db.Column(db.String(50), default="threat")  # threat, full
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_used_at = db.Column(db.DateTime(timezone=True))
