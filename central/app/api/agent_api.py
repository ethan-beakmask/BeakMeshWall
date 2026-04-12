"""
Agent-facing API endpoints: registration, polling, reporting.
"""

import secrets
from datetime import datetime, timezone

from flask import request, jsonify, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash

from . import api_bp
from .decorators import require_agent_auth
from ..extensions import db
from ..models.node import Node
from ..models.api_key import RegistrationToken
from ..services.task_service import TaskService
from ..services.audit_service import AuditService


@api_bp.route('/agent/register', methods=['POST'])
def agent_register():
    """Register a new agent node using a registration token.

    Expects JSON body:
        {
            "token": "<registration_token>",
            "hostname": "<node hostname>",
            "os_info": "<OS description>",
            "agent_version": "<version string>",
            "ip_address": "<node IP>"
        }

    Returns JSON:
        {
            "agent_id": "<uuid>",
            "agent_secret": "<plaintext secret -- only shown once>",
            "poll_interval": 30
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON.'}), 400

    token_value = data.get('token', '').strip()
    hostname = data.get('hostname', '').strip()

    if not token_value or not hostname:
        return jsonify({'error': 'Fields "token" and "hostname" are required.'}), 400

    # Find and validate the registration token
    prefix = token_value[:8]
    candidates = RegistrationToken.query.filter_by(prefix=prefix).all()

    matched_token = None
    for candidate in candidates:
        if check_password_hash(candidate.token_hash, token_value):
            matched_token = candidate
            break

    if matched_token is None:
        return jsonify({'error': 'Invalid registration token.'}), 401

    if not matched_token.is_valid:
        return jsonify({'error': 'Registration token is expired or exhausted.'}), 401

    # Generate agent credentials
    agent_secret = secrets.token_urlsafe(32)
    agent_secret_hash = generate_password_hash(agent_secret)

    # Create the node record
    node = Node(
        hostname=hostname,
        ip_address=data.get('ip_address', request.remote_addr),
        os_info=data.get('os_info', ''),
        agent_version=data.get('agent_version', ''),
        agent_secret_hash=agent_secret_hash,
        status='approved',
    )

    # Increment usage counter on the registration token
    matched_token.use_count += 1

    db.session.add(node)
    db.session.commit()

    # Audit: node registration
    AuditService.log(
        actor='system',
        action='register_node',
        resource_type='node',
        resource_id=node.id,
        detail={
            'hostname': hostname,
            'ip_address': node.ip_address,
            'agent_version': node.agent_version,
        },
        ip_address=request.remote_addr,
    )

    poll_interval = current_app.config.get('AGENT_POLL_INTERVAL', 30)

    return jsonify({
        'agent_id': node.id,
        'agent_secret': agent_secret,
        'poll_interval': poll_interval,
    }), 201


@api_bp.route('/agent/poll', methods=['GET'])
@require_agent_auth
def agent_poll():
    """Agent polls for pending tasks and updates its heartbeat.

    Returns JSON:
        {
            "tasks": [
                {"id": "uuid", "module": "firewall", "action": "block_ip", "params": {...}}
            ],
            "config": {"poll_interval": 30}
        }
    """
    node = g.current_node
    node.last_heartbeat_at = datetime.now(timezone.utc)
    db.session.commit()

    # Fetch pending tasks and atomically mark them dispatched
    pending_tasks = TaskService.get_pending_tasks_for_node(node.id)

    poll_interval = current_app.config.get('AGENT_POLL_INTERVAL', 30)

    return jsonify({
        'tasks': [t.to_dispatch_dict() for t in pending_tasks],
        'config': {
            'poll_interval': poll_interval,
        },
    })


@api_bp.route('/agent/report', methods=['POST'])
@require_agent_auth
def agent_report():
    """Agent reports task execution results, counters, and table info.

    Expects JSON body:
        {
            "results": [
                {
                    "task_id": "uuid",
                    "status": "completed" or "failed",
                    "message": "optional description",
                    "data": { ... optional result data ... }
                }
            ],
            "counters": {
                "rules": [...],
                "collected_at": "2026-04-12T23:00:00Z"
            },
            "tables": [
                {"name": "beakmeshwall", "family": "inet", "managed": true, "external": ""}
            ]
        }

    Returns JSON:
        {"status": "processed", "processed": <count>}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON.'}), 400

    results = data.get('results', [])
    if not isinstance(results, list):
        return jsonify({'error': '"results" must be an array.'}), 400

    node = g.current_node
    actor = f'agent:{node.id}'

    # Map agent status values to internal status values
    status_map = {
        'success': 'completed',
        'completed': 'completed',
        'error': 'failed',
        'failed': 'failed',
    }

    processed = 0
    for item in results:
        task_id = item.get('task_id')
        raw_status = item.get('status', '')
        status = status_map.get(raw_status)

        if not task_id or not status:
            continue

        result_data = item.get('data')
        error_message = item.get('message') if status == 'failed' else None

        task = TaskService.complete_task(
            task_id=task_id,
            status=status,
            result=result_data,
            error_message=error_message,
        )
        if task is not None:
            processed += 1

            # Audit: task completion or failure
            audit_action = 'task_completed' if status == 'completed' else 'task_failed'
            AuditService.log(
                actor=actor,
                action=audit_action,
                resource_type='task',
                resource_id=task_id,
                detail={
                    'module': task.module,
                    'task_action': task.action,
                    'error_message': error_message,
                },
                ip_address=request.remote_addr,
            )

    # Store counters if present
    counters = data.get('counters')
    if counters is not None:
        node.last_counters = counters

    # Store tables if present
    tables = data.get('tables')
    if tables is not None:
        node.last_tables = tables

    # Always update last_report_at
    node.last_report_at = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({'status': 'processed', 'processed': processed})
