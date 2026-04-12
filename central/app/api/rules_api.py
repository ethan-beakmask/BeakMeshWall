"""
Firewall rules CRUD API endpoints.

All routes require session auth (Flask-Login) or API key (X-API-Key).
"""

import ipaddress

from flask import request, jsonify, g

from . import api_bp
from .decorators import require_auth
from ..services.firewall_service import FirewallService
from ..services.audit_service import AuditService


VALID_RULE_TYPES = ('block', 'allow', 'custom')
VALID_DIRECTIONS = ('inbound', 'outbound', 'both')
VALID_ACTIONS = ('drop', 'accept', 'reject')
VALID_STATUS_FILTERS = ('active', 'expired', 'removed')


def _validate_ip(ip_str):
    """Return True if ip_str is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False


@api_bp.route('/rules', methods=['GET'])
@require_auth
def list_rules():
    """List firewall rules with optional filters.

    Query params:
        node_id  -- filter by node UUID
        status   -- filter by status (active, expired, removed)
        type     -- filter by rule type (block, allow, custom)
    """
    node_id = request.args.get('node_id')
    status = request.args.get('status')
    rule_type = request.args.get('type')

    if status and status not in VALID_STATUS_FILTERS:
        return jsonify({'error': f'Invalid status filter. Must be one of: {", ".join(VALID_STATUS_FILTERS)}'}), 400

    if rule_type and rule_type not in VALID_RULE_TYPES:
        return jsonify({'error': f'Invalid type filter. Must be one of: {", ".join(VALID_RULE_TYPES)}'}), 400

    # Default to active if no status filter specified
    if status is None:
        rules = FirewallService.get_active_rules(node_id=node_id, rule_type=rule_type)
    else:
        from ..models.firewall_rule import FirewallRule
        query = FirewallRule.query.filter_by(status=status)
        if node_id:
            query = query.filter_by(node_id=node_id)
        if rule_type:
            query = query.filter_by(rule_type=rule_type)
        rules = query.order_by(FirewallRule.created_at.desc()).all()

    return jsonify({
        'rules': [r.to_dict() for r in rules],
        'count': len(rules),
    })


@api_bp.route('/rules/<int:rule_id>', methods=['GET'])
@require_auth
def get_rule(rule_id):
    """Get a single firewall rule by ID."""
    rule = FirewallService.get_rule_by_id(rule_id)
    if rule is None:
        return jsonify({'error': 'Rule not found.'}), 404

    return jsonify(rule.to_dict())


@api_bp.route('/rules', methods=['POST'])
@require_auth
def create_rule():
    """Create a new firewall rule.

    Expects JSON body:
        {
            "ip_address": "203.0.113.50",
            "node_id": null,
            "rule_type": "block",
            "direction": "inbound",
            "action": "drop",
            "duration": 3600,
            "comment": "manual block"
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON.'}), 400

    ip_address = data.get('ip_address', '').strip()
    if not ip_address:
        return jsonify({'error': '"ip_address" is required.'}), 400

    if not _validate_ip(ip_address):
        return jsonify({'error': f'Invalid IP address: {ip_address}'}), 400

    rule_type = data.get('rule_type', 'block')
    if rule_type not in VALID_RULE_TYPES:
        return jsonify({'error': f'Invalid rule_type. Must be one of: {", ".join(VALID_RULE_TYPES)}'}), 400

    direction = data.get('direction', 'inbound')
    if direction not in VALID_DIRECTIONS:
        return jsonify({'error': f'Invalid direction. Must be one of: {", ".join(VALID_DIRECTIONS)}'}), 400

    action = data.get('action', 'drop')
    if action not in VALID_ACTIONS:
        return jsonify({'error': f'Invalid action. Must be one of: {", ".join(VALID_ACTIONS)}'}), 400

    node_id = data.get('node_id')
    duration = data.get('duration')
    comment = data.get('comment')

    if duration is not None:
        if not isinstance(duration, int) or duration <= 0:
            return jsonify({'error': '"duration" must be a positive integer (seconds).'}), 400

    created_by = g.auth_identity

    rule = FirewallService.create_block_rule(
        ip_address=ip_address,
        node_id=node_id,
        source='manual' if g.auth_type == 'session' else 'api',
        duration=duration,
        comment=comment,
        created_by=created_by,
        direction=direction,
        action=action,
    )

    # Audit: rule creation via rules API
    AuditService.log(
        actor=created_by,
        action='create_rule',
        resource_type='rule',
        resource_id=rule.id,
        detail={
            'ip_address': ip_address,
            'direction': direction,
            'fw_action': action,
            'node_id': node_id,
        },
        ip_address=request.remote_addr,
    )

    return jsonify(rule.to_dict()), 201


@api_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@require_auth
def delete_rule(rule_id):
    """Remove a firewall rule and create unblock task(s).

    This does not delete the record -- it sets status to 'removed'
    and dispatches an unblock task to the relevant agent(s).
    """
    rule = FirewallService.get_rule_by_id(rule_id)
    if rule is None:
        return jsonify({'error': 'Rule not found.'}), 404

    if rule.status != 'active':
        return jsonify({'error': f'Rule is already {rule.status}.'}), 400

    created_by = g.auth_identity

    removed = FirewallService.remove_block_rule(
        rule_id=rule_id,
        created_by=created_by,
    )

    if not removed:
        return jsonify({'error': 'Failed to remove rule.'}), 500

    # Audit: rule deletion via rules API
    AuditService.log(
        actor=created_by,
        action='delete_rule',
        resource_type='rule',
        resource_id=rule_id,
        detail={'ip_address': rule.ip_address},
        ip_address=request.remote_addr,
    )

    return jsonify({
        'status': 'removed',
        'rule_id': rule_id,
    })
