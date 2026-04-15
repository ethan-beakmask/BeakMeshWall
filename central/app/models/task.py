from datetime import datetime, timezone
from app.extensions import db


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("nodes.id"), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False)  # block_ip, unblock_ip, add_rule, delete_rule, flush
    payload = db.Column(db.Text, nullable=False)  # JSON
    status = db.Column(db.String(20), default="pending", index=True)  # pending, sent, success, failed
    result = db.Column(db.Text)  # Agent execution result (JSON)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    sent_at = db.Column(db.DateTime(timezone=True))
    completed_at = db.Column(db.DateTime(timezone=True))
    created_by = db.Column(db.String(80))  # username or "api:<key_prefix>"

    node = db.relationship("Node", backref="tasks")
