"""
Agent-facing API endpoints: registration, polling, reporting.
"""

import secrets
from datetime import datetime, timezone

from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from . import api_bp
from .decorators import require_agent_auth
from ..extensions import db
from ..models.node import Node
from ..models.api_key import RegistrationToken


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
            "tasks": [],
            "config": {"poll_interval": 30}
        }
    """
    from flask import g

    node = g.current_node
    node.last_heartbeat_at = datetime.now(timezone.utc)
    db.session.commit()

    poll_interval = current_app.config.get('AGENT_POLL_INTERVAL', 30)

    return jsonify({
        'tasks': [],
        'config': {
            'poll_interval': poll_interval,
        },
    })


@api_bp.route('/agent/report', methods=['POST'])
@require_agent_auth
def agent_report():
    """Agent reports task execution results.

    For P1 this endpoint simply acknowledges the report.
    Future phases will process and store task results.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON.'}), 400

    # P1: acknowledge receipt -- task processing comes in P2+
    return jsonify({'status': 'received'})
