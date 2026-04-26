from datetime import datetime, timezone
from app.extensions import db


class Node(db.Model):
    __tablename__ = "nodes"

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    os_type = db.Column(db.String(50), nullable=False)  # linux, windows, macos
    fw_driver = db.Column(db.String(50), nullable=False)  # nftables, iptables, windows_firewall, pf
    agent_version = db.Column(db.String(20))
    status = db.Column(db.String(20), default="pending")  # pending, online, offline, error
    token_hash = db.Column(db.String(256), unique=True)  # Agent auth token (hashed)
    last_seen_at = db.Column(db.DateTime(timezone=True))
    registered_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    config_json = db.Column(db.Text)  # Agent-reported config snapshot (JSON)

    # Drift handling per docs/ROADMAP-CONFIG-MANAGEMENT.md section 4.3.
    # JSON keyed by subsystem -> policy. Currently only "firewall" is honored;
    # future subsystems (nginx) will plug in here.
    # policy: detect-only | notify | overwrite. Default: notify.
    drift_policies = db.Column(db.Text, default='{"firewall":"notify"}')

    # Per-node override for drift detection cadence in seconds.
    # Allowed range 60-3600. NULL means use the global default (300s).
    drift_check_interval = db.Column(db.Integer)
