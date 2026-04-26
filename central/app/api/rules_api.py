import ipaddress
import json
from datetime import datetime, timedelta, timezone

from flask import request, jsonify
from flask_login import login_required, current_user

from app.api import api_bp
from app.extensions import db
from app.models.node import Node
from app.models.task import Task
from app.models.threat_block import ThreatBlock
from app.models.threat_whitelist import ThreatWhitelist
from app.models.named_set import NamedSet
from app.services.edl_export import export_blocklist, export_whitelist
from app.services.rule_validator import RuleValidationError, validate_rule


@api_bp.route("/rules/block", methods=["POST"])
@login_required
def create_block_task():
    """Create a block_ip task for a node."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    ip = data.get("ip", "").strip()
    comment = data.get("comment", "")

    if not node_id or not ip:
        return jsonify({"error": "node_id and ip are required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404

    task = Task(
        node_id=node.id,
        action="block_ip",
        payload=json.dumps({"ip": ip, "comment": comment}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({"task_id": task.id, "status": "pending"}), 201


@api_bp.route("/rules/unblock", methods=["POST"])
@login_required
def create_unblock_task():
    """Create an unblock_ip task for a node."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    ip = data.get("ip", "").strip()

    if not node_id or not ip:
        return jsonify({"error": "node_id and ip are required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404

    task = Task(
        node_id=node.id,
        action="unblock_ip",
        payload=json.dumps({"ip": ip}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({"task_id": task.id, "status": "pending"}), 201


@api_bp.route("/rules/add", methods=["POST"])
@login_required
def create_add_rule_task():
    """Create an add_rule task for a node."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    chain = data.get("chain", "filter_input")
    rule = data.get("rule", "").strip()
    comment = data.get("comment", "")

    if not node_id or not rule:
        return jsonify({"error": "node_id and rule are required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404

    task = Task(
        node_id=node.id,
        action="add_rule",
        payload=json.dumps({"chain": chain, "rule": rule, "comment": comment}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({"task_id": task.id, "status": "pending"}), 201


@api_bp.route("/rules/delete", methods=["POST"])
@login_required
def create_delete_rule_task():
    """Create a delete_rule task for a node."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    node_id = data.get("node_id")
    chain = data.get("chain", "filter_input")
    handle = data.get("handle")

    if not node_id or handle is None:
        return jsonify({"error": "node_id and handle are required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404

    task = Task(
        node_id=node.id,
        action="delete_rule",
        payload=json.dumps({"chain": chain, "handle": handle}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({"task_id": task.id, "status": "pending"}), 201


@api_bp.route("/rules/apply", methods=["POST"])
@login_required
def create_apply_rule_task():
    """Create an apply_rule task using the unified Stage A schema.

    Body: {"node_id": int, "rule": {schema...}}
    See docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.
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

    try:
        normalized = validate_rule(rule, node.fw_driver)
    except RuleValidationError as e:
        return jsonify({"error": str(e), "driver": node.fw_driver}), 400

    # Stage C: rules referencing a named set must point at one that exists
    # on this node, otherwise the agent will fail at apply time and we'll
    # waste a round-trip + a drift event.
    for set_field in ("src_set", "dst_set"):
        set_name = normalized.get(set_field)
        if not set_name:
            continue
        if not NamedSet.query.filter_by(node_id=node.id, name=set_name).first():
            return jsonify({
                "error": f"{set_field} '{set_name}' does not exist on this node; "
                         f"create it via /api/v1/sets/create first",
            }), 409

    task = Task(
        node_id=node.id,
        action="apply_rule",
        payload=json.dumps({"rule": normalized}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()

    return jsonify({
        "task_id": task.id,
        "status": "pending",
        "normalized_rule": normalized,
    }), 201


@api_bp.route("/rules/validate", methods=["POST"])
@login_required
def validate_rule_endpoint():
    """Dry-run validation. Body: {"driver": str, "rule": {...}}.

    Returns 200 with normalized rule on success, 400 with error otherwise.
    Does not create any task. Useful for UI preview.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    driver = data.get("driver")
    rule = data.get("rule")
    if not driver or not isinstance(rule, dict):
        return jsonify({"error": "driver and rule (object) are required"}), 400

    try:
        normalized = validate_rule(rule, driver)
    except RuleValidationError as e:
        return jsonify({"valid": False, "error": str(e)}), 400

    return jsonify({"valid": True, "normalized": normalized}), 200


@api_bp.route("/tasks/<int:node_id>", methods=["GET"])
@login_required
def get_node_tasks(node_id):
    """Get recent tasks for a node."""
    tasks = Task.query.filter_by(node_id=node_id).order_by(
        Task.created_at.desc()
    ).limit(50).all()

    return jsonify([{
        "id": t.id,
        "action": t.action,
        "payload": json.loads(t.payload),
        "status": t.status,
        "result": t.result,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "completed_at": t.completed_at.isoformat() if t.completed_at else None,
        "created_by": t.created_by,
    } for t in tasks])


@api_bp.route("/task/<int:task_id>", methods=["GET"])
@login_required
def get_task_status(task_id):
    """Get single task status (for polling)."""
    task = db.session.get(Task, task_id)
    if not task:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "id": task.id,
        "status": task.status,
        "result": task.result,
    })


# ---------------------------------------------------------------------------
# Web UI threat operations (session auth)
# ---------------------------------------------------------------------------

def _validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        pass
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except (ValueError, TypeError):
        return False


def _check_whitelist(ip_str):
    try:
        target = ipaddress.ip_address(ip_str)
    except ValueError:
        try:
            target = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            return None
    for entry in ThreatWhitelist.query.all():
        try:
            network = ipaddress.ip_network(entry.ip_cidr, strict=False)
        except ValueError:
            continue
        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if target in network:
                return entry
        else:
            if target.overlaps(network):
                return entry
    return None


@api_bp.route("/web/threat/block", methods=["POST"])
@login_required
def web_threat_block():
    """Block IP from Web UI. Creates ThreatBlock record + tasks."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    ip = data.get("ip", "").strip()
    if not ip or not _validate_ip(ip):
        return jsonify({"error": "Invalid IP address."}), 400

    wl = _check_whitelist(ip)
    if wl:
        return jsonify({
            "error": f"IP is whitelisted ({wl.ip_cidr}: {wl.description})"
        }), 409

    existing = ThreatBlock.query.filter_by(ip_address=ip, status="active").first()
    if existing:
        return jsonify({"error": "IP already blocked.", "block_id": existing.id}), 409

    reason = data.get("reason", "manual")
    comment = data.get("comment", "")
    duration = data.get("duration")
    node_ids = data.get("node_ids")  # null = all online nodes

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=duration) if duration else None
    created_by = f"web:{current_user.username}"

    block = ThreatBlock(
        ip_address=ip,
        source="manual",
        reason=reason,
        detail=comment,
        duration=duration,
        status="active",
        created_by=created_by,
        created_at=now,
        expires_at=expires_at,
    )
    db.session.add(block)

    nft_comment = f"[manual] {reason}" if reason else "[manual]"
    if comment:
        nft_comment += f" - {comment}"
    payload = {"ip": ip, "comment": nft_comment}

    tasks = []
    if node_ids:
        for nid in node_ids:
            node = db.session.get(Node, nid)
            if node:
                t = Task(node_id=node.id, action="block_ip",
                         payload=json.dumps(payload), created_by=created_by)
                db.session.add(t)
                tasks.append(t)
    else:
        for node in Node.query.filter_by(status="online").all():
            t = Task(node_id=node.id, action="block_ip",
                     payload=json.dumps(payload), created_by=created_by)
            db.session.add(t)
            tasks.append(t)

    db.session.commit()
    export_blocklist()
    return jsonify({
        "status": "accepted",
        "block_id": block.id,
        "tasks_created": len(tasks),
        "task_ids": [t.id for t in tasks],
    }), 201


@api_bp.route("/web/threat/unblock", methods=["POST"])
@login_required
def web_threat_unblock():
    """Unblock IP from Web UI."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    ip = data.get("ip", "").strip()
    if not ip or not _validate_ip(ip):
        return jsonify({"error": "Invalid IP address."}), 400

    now = datetime.now(timezone.utc)
    created_by = f"web:{current_user.username}"

    active = ThreatBlock.query.filter_by(ip_address=ip, status="active").all()
    for b in active:
        b.status = "removed"
        b.removed_at = now
        b.removed_by = created_by

    payload = {"ip": ip}
    tasks = []
    for node in Node.query.filter_by(status="online").all():
        t = Task(node_id=node.id, action="unblock_ip",
                 payload=json.dumps(payload), created_by=created_by)
        db.session.add(t)
        tasks.append(t)

    db.session.commit()
    export_blocklist()
    return jsonify({
        "status": "accepted",
        "blocks_removed": len(active),
        "tasks_created": len(tasks),
    }), 200


@api_bp.route("/web/threat/whitelist", methods=["POST"])
@login_required
def web_whitelist_add():
    """Add whitelist entry from Web UI."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid request"}), 400

    ip_cidr = data.get("ip_cidr", "").strip()
    if not ip_cidr or not _validate_ip(ip_cidr):
        return jsonify({"error": "Invalid IP or CIDR."}), 400

    try:
        net = ipaddress.ip_network(ip_cidr, strict=False)
        ip_cidr = str(net)
    except ValueError:
        pass

    if ThreatWhitelist.query.filter_by(ip_cidr=ip_cidr).first():
        return jsonify({"error": f"'{ip_cidr}' already in whitelist."}), 409

    entry = ThreatWhitelist(
        ip_cidr=ip_cidr,
        description=data.get("description", ""),
        created_by=current_user.username,
    )
    db.session.add(entry)
    db.session.commit()
    export_whitelist()
    return jsonify({"status": "created", "id": entry.id, "ip_cidr": entry.ip_cidr}), 201


@api_bp.route("/web/threat/whitelist/<int:entry_id>", methods=["DELETE"])
@login_required
def web_whitelist_delete(entry_id):
    """Remove whitelist entry from Web UI."""
    entry = db.session.get(ThreatWhitelist, entry_id)
    if not entry:
        return jsonify({"error": "not found"}), 404
    ip_cidr = entry.ip_cidr
    db.session.delete(entry)
    db.session.commit()
    export_whitelist()
    return jsonify({"status": "deleted", "ip_cidr": ip_cidr})
