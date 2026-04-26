"""Nginx (P6 subsystem) API: validate, apply, remove, list, enablement.

See docs/NGINX-MANAGEMENT.md.
"""
import json

from flask import jsonify, request
from flask_login import current_user, login_required

from app.api import api_bp
from app.extensions import db
from app.models.managed_rule import ManagedRule
from app.models.node import Node
from app.models.task import Task
from app.schemas import nginx_fingerprint
from app.services.drift_detector import (
    mark_managed_rule_removed,
    upsert_managed_rule,
)
from app.services.nginx_generator import generate_access_conf
from app.services.nginx_validator import (
    NginxRuleValidationError,
    validate_nginx_rule,
)

ACCESS_CONF_PATH = "/etc/nginx/conf.d/beakmeshwall/access.conf"


@api_bp.route("/nginx/rules/validate", methods=["POST"])
@login_required
def nginx_validate_rule():
    """Dry-run validation. Body: {"rule": {...}}."""
    data = request.get_json()
    if not data or not isinstance(data.get("rule"), dict):
        return jsonify({"error": "rule (object) is required"}), 400
    try:
        normalized = validate_nginx_rule(data["rule"])
    except NginxRuleValidationError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    return jsonify({
        "valid": True,
        "normalized": normalized,
        "fingerprint": nginx_fingerprint(normalized),
    }), 200


@api_bp.route("/nginx/rules/apply", methods=["POST"])
@login_required
def nginx_apply_rule():
    """Add (or re-apply) an nginx access rule on a node.

    Body: {"node_id": int, "rule": {action, src, comment?}}.
    Effect: upsert ManagedRule(subsystem='nginx'), regenerate the full
    access.conf, dispatch one apply_nginx_access task.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    rule = data.get("rule")
    if not node_id or not isinstance(rule, dict):
        return jsonify({"error": "node_id and rule (object) are required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404
    if not getattr(node, "nginx_managed", False):
        return jsonify({"error": "nginx_managed flag is disabled on this node"}), 409

    try:
        normalized = validate_nginx_rule(rule)
    except NginxRuleValidationError as e:
        return jsonify({"error": str(e)}), 400

    fp = nginx_fingerprint(normalized)
    upsert_managed_rule(node_id, normalized, fp, subsystem="nginx")
    task_id = _dispatch_full_file_task(node_id)
    db.session.commit()

    return jsonify({
        "task_id": task_id,
        "status": "pending",
        "fingerprint": fp,
        "normalized": normalized,
    }), 201


@api_bp.route("/nginx/rules/remove", methods=["POST"])
@login_required
def nginx_remove_rule():
    """Remove an nginx access rule on a node.

    Body: {"node_id": int, "rule": {action, src}} OR {"node_id": int, "fingerprint": "..."}.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    rule = data.get("rule")
    fp = data.get("fingerprint")

    if not node_id:
        return jsonify({"error": "node_id is required"}), 400
    if not fp and isinstance(rule, dict):
        try:
            fp = nginx_fingerprint(validate_nginx_rule(rule))
        except NginxRuleValidationError as e:
            return jsonify({"error": str(e)}), 400
    if not fp:
        return jsonify({"error": "rule or fingerprint is required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404
    if not getattr(node, "nginx_managed", False):
        return jsonify({"error": "nginx_managed flag is disabled on this node"}), 409

    mark_managed_rule_removed(node_id, fp, subsystem="nginx")
    task_id = _dispatch_full_file_task(node_id)
    db.session.commit()

    return jsonify({"task_id": task_id, "status": "pending", "fingerprint": fp}), 200


@api_bp.route("/nginx/rules/<int:node_id>", methods=["GET"])
@login_required
def nginx_list_rules(node_id):
    """List active nginx rules for a node."""
    rows = ManagedRule.query.filter_by(
        node_id=node_id, subsystem="nginx", status="active"
    ).order_by(ManagedRule.applied_at).all()
    out = []
    for r in rows:
        try:
            rule_obj = json.loads(r.schema_rule)
        except (TypeError, ValueError):
            rule_obj = {}
        out.append({
            "fingerprint": r.fingerprint,
            "rule": rule_obj,
            "applied_at": r.applied_at.isoformat() if r.applied_at else None,
        })
    return jsonify({"node_id": node_id, "rules": out})


@api_bp.route("/nginx/managed", methods=["POST"])
@login_required
def nginx_set_managed():
    """Toggle the nginx_managed flag on a node.

    Body: {"node_id": int, "enabled": bool}.
    """
    data = request.get_json()
    node_id = (data or {}).get("node_id")
    enabled = bool((data or {}).get("enabled"))

    node = db.session.get(Node, node_id) if node_id else None
    if not node:
        return jsonify({"error": "node not found"}), 404

    node.nginx_managed = enabled
    db.session.commit()
    return jsonify({"node_id": node.id, "nginx_managed": enabled})


# ---------------------------------------------------------------------------


def _dispatch_full_file_task(node_id: int) -> int:
    """Regenerate access.conf from current ManagedRule rows and queue a task.

    Returns the new task id. Caller must commit().
    """
    rows = ManagedRule.query.filter_by(
        node_id=node_id, subsystem="nginx", status="active"
    ).all()
    rules = []
    for r in rows:
        try:
            rules.append(json.loads(r.schema_rule))
        except (TypeError, ValueError):
            continue

    content = generate_access_conf(rules)
    task = Task(
        node_id=node_id,
        action="apply_nginx_access",
        payload=json.dumps({"path": ACCESS_CONF_PATH, "content": content}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.flush()
    return task.id
