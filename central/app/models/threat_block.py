from datetime import datetime, timezone
from app.extensions import db


class ThreatBlock(db.Model):
    """Central record of an active/historical IP block from threat feed or manual action."""

    __tablename__ = "threat_blocks"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    source = db.Column(db.String(50), nullable=False, default="manual")  # beakplatform, manual, etc.
    reason = db.Column(db.String(100), default="")
    detail = db.Column(db.String(255), default="")
    duration = db.Column(db.Integer)  # seconds, null = permanent
    status = db.Column(db.String(20), nullable=False, default="active", index=True)  # active, expired, removed
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime(timezone=True))  # null = permanent
    removed_at = db.Column(db.DateTime(timezone=True))
    removed_by = db.Column(db.String(80))
