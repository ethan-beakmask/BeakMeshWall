"""
Audit log API endpoints.

Provides read-only access to the audit trail.
Requires session auth or API key.
"""

from flask import request, jsonify

from . import api_bp
from .decorators import require_auth
from ..services.audit_service import AuditService


@api_bp.route('/audit', methods=['GET'])
@require_auth
def list_audit_logs():
    """Query audit log entries with optional filters.

    Query params:
        action        -- filter by action (e.g. 'login', 'create_rule')
        resource_type -- filter by resource type (e.g. 'rule', 'node')
        actor         -- partial match on actor string
        limit         -- max entries to return (default 100, max 500)
        offset        -- entries to skip (default 0)

    Returns JSON:
        {
            "entries": [...],
            "total": N,
            "limit": N,
            "offset": N
        }
    """
    action = request.args.get('action')
    resource_type = request.args.get('resource_type')
    actor = request.args.get('actor')
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    if limit < 1:
        limit = 1
    elif limit > 500:
        limit = 500

    if offset < 0:
        offset = 0

    entries, total = AuditService.query(
        action=action,
        resource_type=resource_type,
        actor=actor,
        limit=limit,
        offset=offset,
    )

    return jsonify({
        'entries': [e.to_dict() for e in entries],
        'total': total,
        'limit': limit,
        'offset': offset,
    })
