"""
Threat Feed API endpoints.

Provides an integration point for external systems (e.g. BeakPlatform)
to push IP block/unblock requests. All routes require API Key auth.
"""

import ipaddress

from flask import request, jsonify, g

from . import api_bp
from .decorators import require_api_key
from ..services.firewall_service import FirewallService
from ..services.audit_service import AuditService


def _validate_ip(ip_str):
    """Return True if ip_str is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False


@api_bp.route('/threat/block', methods=['POST'])
@require_api_key
def threat_block_create():
    """Create an IP block from a threat feed / external system.

    Expects JSON body:
        {
            "source": "beakplatform",
            "ip": "203.0.113.50",
            "reason": "brute_force",
            "detail": "login_fail_10_in_5m",
            "duration": 3600
        }

    Returns JSON:
        {
            "status": "accepted",
            "rule_id": 123,
            "expires_at": "2026-04-12T20:00:00+00:00"
        }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Request body must be valid JSON.'}), 400

    ip_addr = data.get('ip', '').strip()
    if not ip_addr:
        return jsonify({'error': '"ip" is required.'}), 400

    if not _validate_ip(ip_addr):
        return jsonify({'error': f'Invalid IP address: {ip_addr}'}), 400

    source = data.get('source', 'external').strip()
    reason = data.get('reason', '')
    detail = data.get('detail', '')
    duration = data.get('duration')

    if duration is not None:
        if not isinstance(duration, int) or duration <= 0:
            return jsonify({'error': '"duration" must be a positive integer (seconds).'}), 400

    source_detail = f'{source}:{reason}' if reason else source
    comment = detail if detail else reason

    api_key_name = g.current_api_key.name
    created_by = f'api:{api_key_name}'

    rule = FirewallService.create_block_rule(
        ip_address=ip_addr,
        node_id=None,  # apply to all nodes
        source='threat_feed',
        source_detail=source_detail,
        duration=duration,
        comment=comment,
        created_by=created_by,
    )

    # Audit: threat block
    AuditService.log(
        actor=created_by,
        action='block_threat',
        resource_type='rule',
        resource_id=rule.id,
        detail={
            'ip_address': ip_addr,
            'source': source,
            'reason': reason,
        },
        ip_address=request.remote_addr,
    )

    return jsonify({
        'status': 'accepted',
        'rule_id': rule.id,
        'expires_at': rule.expires_at.isoformat() if rule.expires_at else None,
    }), 201


@api_bp.route('/threat/block/<path:ip_addr>', methods=['DELETE'])
@require_api_key
def threat_block_remove(ip_addr):
    """Remove an IP block created by a threat feed.

    URL parameter:
        ip_addr -- the IP address to unblock
    """
    ip_addr = ip_addr.strip()

    if not _validate_ip(ip_addr):
        return jsonify({'error': f'Invalid IP address: {ip_addr}'}), 400

    api_key_name = g.current_api_key.name
    created_by = f'api:{api_key_name}'

    removed = FirewallService.remove_block_rule(
        ip_address=ip_addr,
        created_by=created_by,
    )

    if not removed:
        return jsonify({'error': 'No active block found for this IP.'}), 404

    # Audit: threat unblock
    AuditService.log(
        actor=created_by,
        action='unblock_threat',
        resource_type='rule',
        resource_id=None,
        detail={
            'ip_address': ip_addr,
            'rules_removed': len(removed),
        },
        ip_address=request.remote_addr,
    )

    return jsonify({
        'status': 'removed',
        'ip': ip_addr,
        'rules_removed': len(removed),
    })


@api_bp.route('/threat/block', methods=['GET'])
@require_api_key
def threat_block_list():
    """List all active threat-feed blocks.

    Returns JSON:
        {
            "rules": [...],
            "count": N
        }
    """
    rules = FirewallService.get_active_rules()

    # Filter to only threat_feed sourced rules
    threat_rules = [r for r in rules if r.source == 'threat_feed']

    return jsonify({
        'rules': [r.to_dict() for r in threat_rules],
        'count': len(threat_rules),
    })
