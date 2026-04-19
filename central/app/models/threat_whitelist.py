from datetime import datetime, timezone
from app.extensions import db


class ThreatWhitelist(db.Model):
    __tablename__ = "threat_whitelist"

    id = db.Column(db.Integer, primary_key=True)
    ip_cidr = db.Column(db.String(45), nullable=False, unique=True)  # IP or CIDR
    description = db.Column(db.String(255), default="")
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
