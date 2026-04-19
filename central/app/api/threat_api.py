"""Threat Feed API endpoints.

Provides integration points for external systems (e.g. BeakPlatform)
to push IP block/unblock requests. All routes require API Key auth.

Four independent operations:
  - block:            Add IP to nftables drop rules (via task queue)
  - unblock:          Remove IP from nftables drop rules (via task queue)
  - whitelist-add:    Permanently exempt IP from auto-blocking
  - whitelist-remove: Revoke whitelist exemption

Whitelist-first principle: IPs matching a whitelist entry are never blocked.
"""

import ipaddress
import json
from datetime import datetime, timedelta, timezone

from flask import request, jsonify, g

from app.api import api_bp
from app.api.decorators import require_api_key, require_api_key_scope
from app.extensions import db
from app.models.node import Node
from app.models.task import Task
from app.models.threat_block import ThreatBlock
from app.models.threat_whitelist import ThreatWhitelist
from app.services.edl_export import export_blocklist, export_whitelist


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip_str):
    """Return True if ip_str is a valid IPv4/IPv6 address or CIDR block."""
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
    """Check if ip_str falls within any whitelist entry.

    Returns the matching ThreatWhitelist row or None.
    """
    try:
        target = ipaddress.ip_address(ip_str)
    except ValueError:
        try:
            target = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            return None

    entries = ThreatWhitelist.query.all()
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry.ip_cidr, strict=False)
        except ValueError:
            continue

        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if target in network:
                return entry
        else:
            # target is a network -- reject if any overlap
            if target.overlaps(network):
                return entry

    return None


def _broadcast_task(action, payload, created_by):
    """Create a task for every online node. Returns list of created tasks."""
    nodes = Node.query.filter_by(status="online").all()
    tasks = []
    for node in nodes:
        task = Task(
            node_id=node.id,
            action=action,
            payload=json.dumps(payload),
            created_by=created_by,
        )
        db.session.add(task)
        tasks.append(task)
    return tasks


# ---------------------------------------------------------------------------
# 1. Block IP
# ---------------------------------------------------------------------------

@api_bp.route("/threat/block", methods=["POST"])
@require_api_key
def threat_block():
    """Block an IP via threat feed.

    JSON body:
        {
            "source": "beakplatform",
            "ip": "203.0.113.50",
            "reason": "brute_force",
            "detail": "login_fail_10_in_5m",
            "duration": 3600
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    ip_addr = data.get("ip", "").strip()
    if not ip_addr:
        return jsonify({"error": "'ip' is required."}), 400
    if not _validate_ip(ip_addr):
        return jsonify({"error": f"Invalid IP address or CIDR: {ip_addr}"}), 400

    # --- Whitelist-first check ---
    wl_entry = _check_whitelist(ip_addr)
    if wl_entry:
        return jsonify({
            "status": "rejected",
            "reason": "whitelist",
            "ip": ip_addr,
            "whitelist_entry": wl_entry.ip_cidr,
            "description": wl_entry.description,
        }), 409

    source = data.get("source", "external").strip()
    reason = data.get("reason", "")
    detail = data.get("detail", "")
    duration = data.get("duration")

    if duration is not None:
        if not isinstance(duration, int) or duration <= 0:
            return jsonify({"error": "'duration' must be a positive integer (seconds)."}), 400

    # Check if already actively blocked
    existing = ThreatBlock.query.filter_by(
        ip_address=ip_addr, status="active"
    ).first()
    if existing:
        return jsonify({
            "status": "already_blocked",
            "ip": ip_addr,
            "block_id": existing.id,
            "created_at": existing.created_at.isoformat() if existing.created_at else None,
        }), 409

    # Build comment for nftables rule
    source_tag = f"{source}:{reason}" if reason else source
    comment = f"[threat] {source_tag}"
    if detail:
        comment += f" - {detail}"

    api_key_name = g.current_api_key.name
    created_by = f"api:{api_key_name}"

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=duration) if duration else None

    # Create central block record
    block = ThreatBlock(
        ip_address=ip_addr,
        source=source,
        reason=reason,
        detail=detail,
        duration=duration,
        status="active",
        created_by=created_by,
        created_at=now,
        expires_at=expires_at,
    )
    db.session.add(block)

    # Broadcast block task to all online nodes
    payload = {"ip": ip_addr, "comment": comment}
    tasks = _broadcast_task("block_ip", payload, created_by)
    db.session.commit()

    result = {
        "status": "accepted",
        "ip": ip_addr,
        "block_id": block.id,
        "source": source,
        "tasks_created": len(tasks),
        "task_ids": [t.id for t in tasks],
    }
    if expires_at:
        result["expires_at"] = expires_at.isoformat()

    if not tasks:
        result["warning"] = "No online nodes. Block recorded but not yet enforced."

    export_blocklist()
    return jsonify(result), 201


# ---------------------------------------------------------------------------
# 2. Unblock IP
# ---------------------------------------------------------------------------

@api_bp.route("/threat/unblock", methods=["POST"])
@require_api_key
def threat_unblock():
    """Unblock an IP previously blocked via threat feed.

    JSON body:
        {
            "ip": "203.0.113.50"
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    ip_addr = data.get("ip", "").strip()
    if not ip_addr:
        return jsonify({"error": "'ip' is required."}), 400
    if not _validate_ip(ip_addr):
        return jsonify({"error": f"Invalid IP address or CIDR: {ip_addr}"}), 400

    api_key_name = g.current_api_key.name
    created_by = f"api:{api_key_name}"
    now = datetime.now(timezone.utc)

    # Mark active block records as removed
    active_blocks = ThreatBlock.query.filter_by(
        ip_address=ip_addr, status="active"
    ).all()
    for b in active_blocks:
        b.status = "removed"
        b.removed_at = now
        b.removed_by = created_by

    # Broadcast unblock task
    payload = {"ip": ip_addr}
    tasks = _broadcast_task("unblock_ip", payload, created_by)
    db.session.commit()

    export_blocklist()
    return jsonify({
        "status": "accepted",
        "ip": ip_addr,
        "blocks_removed": len(active_blocks),
        "tasks_created": len(tasks),
        "task_ids": [t.id for t in tasks],
    }), 200 if tasks else 202


# ---------------------------------------------------------------------------
# 3. Query active blocks
# ---------------------------------------------------------------------------

@api_bp.route("/threat/blocks", methods=["GET"])
@require_api_key
def threat_block_list():
    """List all active blocks."""
    blocks = ThreatBlock.query.filter_by(status="active").order_by(
        ThreatBlock.created_at.desc()
    ).all()

    return jsonify({
        "blocks": [{
            "id": b.id,
            "ip_address": b.ip_address,
            "source": b.source,
            "reason": b.reason,
            "detail": b.detail,
            "duration": b.duration,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "created_by": b.created_by,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        } for b in blocks],
        "count": len(blocks),
    })


# ---------------------------------------------------------------------------
# 4. Whitelist CRUD
# ---------------------------------------------------------------------------

@api_bp.route("/threat/whitelist", methods=["GET"])
@require_api_key
def whitelist_list():
    """List all whitelist entries. Any API key scope can read."""
    entries = ThreatWhitelist.query.order_by(ThreatWhitelist.id).all()
    return jsonify({
        "entries": [{
            "id": e.id,
            "ip_cidr": e.ip_cidr,
            "description": e.description,
            "created_by": e.created_by,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in entries],
        "count": len(entries),
    })


@api_bp.route("/threat/whitelist", methods=["POST"])
@require_api_key
@require_api_key_scope("full")
def whitelist_create():
    """Add a whitelist entry. Requires scope 'full'.

    JSON body:
        {
            "ip_cidr": "192.168.0.16",
            "description": "Central Server"
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    ip_cidr = data.get("ip_cidr", "").strip()
    if not ip_cidr:
        return jsonify({"error": "'ip_cidr' is required."}), 400
    if not _validate_ip(ip_cidr):
        return jsonify({"error": f"Invalid IP or CIDR: {ip_cidr}"}), 400

    # Normalize CIDR notation
    try:
        net = ipaddress.ip_network(ip_cidr, strict=False)
        ip_cidr = str(net)
    except ValueError:
        pass  # single IP stays as-is

    existing = ThreatWhitelist.query.filter_by(ip_cidr=ip_cidr).first()
    if existing:
        return jsonify({"error": f"'{ip_cidr}' already in whitelist."}), 409

    api_key_name = g.current_api_key.name
    entry = ThreatWhitelist(
        ip_cidr=ip_cidr,
        description=data.get("description", ""),
        created_by=f"api:{api_key_name}",
    )
    db.session.add(entry)
    db.session.commit()

    export_whitelist()
    return jsonify({
        "status": "created",
        "id": entry.id,
        "ip_cidr": entry.ip_cidr,
    }), 201


@api_bp.route("/threat/whitelist/<int:entry_id>", methods=["DELETE"])
@require_api_key
@require_api_key_scope("full")
def whitelist_delete(entry_id):
    """Remove a whitelist entry. Requires scope 'full'."""
    entry = db.session.get(ThreatWhitelist, entry_id)
    if not entry:
        return jsonify({"error": "Whitelist entry not found."}), 404

    ip_cidr = entry.ip_cidr
    db.session.delete(entry)
    db.session.commit()

    export_whitelist()
    return jsonify({
        "status": "deleted",
        "ip_cidr": ip_cidr,
    })
