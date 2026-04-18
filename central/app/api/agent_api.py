import json
import secrets
from datetime import datetime, timezone
from functools import wraps
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app.api import api_bp
from app.extensions import db
from app.models.node import Node
from app.models.task import Task


def require_agent_token(f):
    """Verify agent token from Authorization header."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = auth[7:]
        nodes = Node.query.filter(Node.status != "pending").all()
        for node in nodes:
            if node.token_hash and check_password_hash(node.token_hash, token):
                kwargs["node"] = node
                return f(*args, **kwargs)
        return jsonify({"error": "invalid token"}), 401
    return wrapper


@api_bp.route("/agent/register", methods=["POST"])
def agent_register():
    """Agent self-registration. Returns a bearer token for future requests."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    required = ["hostname", "os_type", "fw_driver"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"missing field: {field}"}), 400

    token = secrets.token_hex(32)

    node = Node(
        hostname=data["hostname"],
        ip_address=request.remote_addr,
        os_type=data["os_type"],
        fw_driver=data["fw_driver"],
        agent_version=data.get("agent_version", ""),
        status="online",
        token_hash=generate_password_hash(token),
        last_seen_at=datetime.now(timezone.utc),
    )
    db.session.add(node)
    db.session.commit()

    return jsonify({
        "node_id": node.id,
        "token": token,
        "poll_interval": 30,
    }), 201


@api_bp.route("/agent/poll", methods=["GET"])
@require_agent_token
def agent_poll(node=None):
    """Agent polls for pending tasks. Returns pending tasks and marks them as sent."""
    node.last_seen_at = datetime.now(timezone.utc)
    node.status = "online"

    # Fetch pending tasks for this node
    pending = Task.query.filter_by(
        node_id=node.id, status="pending"
    ).order_by(Task.created_at).all()

    tasks_out = []
    now = datetime.now(timezone.utc)
    for t in pending:
        tasks_out.append({
            "id": t.id,
            "action": t.action,
            "payload": json.loads(t.payload),
        })
        t.status = "sent"
        t.sent_at = now

    db.session.commit()

    return jsonify({
        "node_id": node.id,
        "tasks": tasks_out,
    })


@api_bp.route("/agent/report", methods=["POST"])
@require_agent_token
def agent_report(node=None):
    """Agent reports task execution results and current firewall state."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node.last_seen_at = datetime.now(timezone.utc)

    # Process task results
    now = datetime.now(timezone.utc)
    for result in data.get("task_results", []):
        task_id = result.get("task_id")
        if not task_id:
            continue
        task = Task.query.filter_by(id=task_id, node_id=node.id).first()
        if task:
            task.status = "success" if result.get("success") else "failed"
            task.result = json.dumps(result.get("detail", ""))
            task.completed_at = now

    # Store state snapshot (firewall + nginx + service)
    state = {}
    if node.config_json:
        try:
            state = json.loads(node.config_json)
        except (json.JSONDecodeError, TypeError):
            state = {}

    for key in ("fw_state", "nginx_state", "service_state"):
        if key in data:
            state[key] = data[key]

    node.config_json = json.dumps(state)

    db.session.commit()
    return jsonify({"status": "ok"})
