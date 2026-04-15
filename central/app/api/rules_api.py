import json
from flask import request, jsonify
from flask_login import login_required, current_user
from app.api import api_bp
from app.extensions import db
from app.models.node import Node
from app.models.task import Task


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
