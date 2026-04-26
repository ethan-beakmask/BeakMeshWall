"""Named-set CRUD API (P6 Stage C).

Sets are per-node. Each operation:
  1. Validates input.
  2. Updates the central NamedSet / NamedSetMember rows.
  3. Dispatches a task (create_set / delete_set / set_add / set_remove)
     to the agent so the kernel-side set follows.

If the agent task fails, the central state is intentionally left as-is so the
operator can see the divergence in DriftEvents (Stage D's job to surface).

See docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1.
"""
import ipaddress
import json
import re

from flask import jsonify, request
from flask_login import current_user, login_required

from app.api import api_bp
from app.extensions import db
from app.models.named_set import NamedSet, NamedSetMember
from app.models.node import Node
from app.models.task import Task

NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def _validate_name(name: str) -> bool:
    return bool(name) and NAME_RE.match(name) is not None


def _validate_addr(addr: str) -> bool:
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except (ValueError, TypeError):
        try:
            ipaddress.ip_address(addr)
            return True
        except (ValueError, TypeError):
            return False


@api_bp.route("/sets/create", methods=["POST"])
@login_required
def create_set():
    """Body: {node_id, name}. Creates the central record and dispatches a task."""
    data = request.get_json() or {}
    node_id = data.get("node_id")
    name = (data.get("name") or "").strip()

    if not node_id or not _validate_name(name):
        return jsonify({"error": "node_id and name (1-32 chars, [a-zA-Z0-9_-]) required"}), 400

    node = db.session.get(Node, node_id)
    if not node:
        return jsonify({"error": "node not found"}), 404
    if node.fw_driver == "windows_firewall":
        return jsonify({"error": "named sets not supported on windows_firewall"}), 409

    if NamedSet.query.filter_by(node_id=node_id, name=name).first():
        return jsonify({"error": f"set '{name}' already exists on this node"}), 409

    nset = NamedSet(node_id=node_id, name=name, family="ipv4")
    db.session.add(nset)

    task = Task(
        node_id=node_id,
        action="create_set",
        payload=json.dumps({"name": name}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({"set_id": nset.id, "task_id": task.id, "name": name}), 201


@api_bp.route("/sets/<int:set_id>", methods=["DELETE"])
@login_required
def delete_set(set_id):
    """Remove the set: dispatch delete_set task, drop central rows."""
    nset = db.session.get(NamedSet, set_id)
    if not nset:
        return jsonify({"error": "set not found"}), 404

    task = Task(
        node_id=nset.node_id,
        action="delete_set",
        payload=json.dumps({"name": nset.name}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.delete(nset)
    db.session.commit()
    return jsonify({"task_id": task.id, "deleted_set_id": set_id})


@api_bp.route("/sets/<int:set_id>/members", methods=["POST"])
@login_required
def add_set_member(set_id):
    """Body: {address}. Adds the address and dispatches a set_add task."""
    data = request.get_json() or {}
    addr = (data.get("address") or "").strip()
    if not _validate_addr(addr):
        return jsonify({"error": "invalid address (expect IPv4 / CIDR)"}), 400

    nset = db.session.get(NamedSet, set_id)
    if not nset:
        return jsonify({"error": "set not found"}), 404
    if NamedSetMember.query.filter_by(set_id=set_id, address=addr).first():
        return jsonify({"error": "address already in set"}), 409

    member = NamedSetMember(set_id=set_id, address=addr)
    db.session.add(member)

    task = Task(
        node_id=nset.node_id,
        action="set_add",
        payload=json.dumps({"name": nset.name, "address": addr}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({"member_id": member.id, "task_id": task.id, "address": addr}), 201


@api_bp.route("/sets/<int:set_id>/members/<path:address>", methods=["DELETE"])
@login_required
def remove_set_member(set_id, address):
    """Remove an address from the set."""
    nset = db.session.get(NamedSet, set_id)
    if not nset:
        return jsonify({"error": "set not found"}), 404

    member = NamedSetMember.query.filter_by(set_id=set_id, address=address).first()
    if not member:
        return jsonify({"error": "address not in set"}), 404

    db.session.delete(member)
    task = Task(
        node_id=nset.node_id,
        action="set_remove",
        payload=json.dumps({"name": nset.name, "address": address}),
        created_by=current_user.username,
    )
    db.session.add(task)
    db.session.commit()
    return jsonify({"task_id": task.id, "removed_address": address})


@api_bp.route("/sets/<int:node_id>", methods=["GET"])
@login_required
def list_sets(node_id):
    """List all named sets on a node, including their members."""
    sets = NamedSet.query.filter_by(node_id=node_id).order_by(NamedSet.name).all()
    out = []
    for s in sets:
        out.append({
            "id": s.id,
            "name": s.name,
            "family": s.family,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "members": [
                {"id": m.id, "address": m.address}
                for m in s.members
            ],
        })
    return jsonify({"node_id": node_id, "sets": out})
