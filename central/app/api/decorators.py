"""
Authentication decorators for API endpoints.
"""

from functools import wraps
from datetime import datetime, timezone

from flask import request, jsonify, g
from werkzeug.security import check_password_hash

from ..extensions import db
from ..models.node import Node
from ..models.api_key import APIKey


def require_agent_auth(f):
    """Verify Authorization: Bearer <agent_secret> against Node.agent_secret_hash.

    On success, sets g.current_node to the authenticated Node instance.
    The agent_id is expected in the X-Agent-ID header.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        agent_id = request.headers.get('X-Agent-ID', '')

        if not auth_header.startswith('Bearer ') or not agent_id:
            return jsonify({'error': 'Missing or invalid authentication headers.'}), 401

        token = auth_header[7:]  # Strip 'Bearer '
        if not token:
            return jsonify({'error': 'Empty bearer token.'}), 401

        node = db.session.get(Node, agent_id)
        if node is None:
            return jsonify({'error': 'Unknown agent.'}), 401

        if node.status != 'approved':
            return jsonify({'error': 'Agent is disabled.'}), 403

        if not check_password_hash(node.agent_secret_hash, token):
            return jsonify({'error': 'Invalid agent secret.'}), 401

        g.current_node = node
        return f(*args, **kwargs)

    return decorated


def require_api_key(f):
    """Verify X-API-Key header against the APIKey table.

    On success, sets g.current_api_key to the authenticated APIKey instance.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key_value = request.headers.get('X-API-Key', '')
        if not api_key_value:
            return jsonify({'error': 'Missing X-API-Key header.'}), 401

        # Use the prefix (first 8 chars) to narrow down candidates
        prefix = api_key_value[:8]
        candidates = APIKey.query.filter_by(prefix=prefix, is_active=True).all()

        matched_key = None
        for candidate in candidates:
            if check_password_hash(candidate.key_hash, api_key_value):
                matched_key = candidate
                break

        if matched_key is None:
            return jsonify({'error': 'Invalid API key.'}), 401

        if matched_key.is_expired:
            return jsonify({'error': 'API key has expired.'}), 401

        # Update last_used_at timestamp
        matched_key.last_used_at = datetime.now(timezone.utc)
        db.session.commit()

        g.current_api_key = matched_key
        return f(*args, **kwargs)

    return decorated
