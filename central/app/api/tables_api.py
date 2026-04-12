"""
Node tables and counters API endpoints.

Provides read access to nftables table listings and rule counters
reported by agents. Requires session auth or API key.
"""

from flask import jsonify

from . import api_bp
from .decorators import require_auth
from ..services.node_service import NodeService


@api_bp.route('/nodes/<node_id>/tables', methods=['GET'])
@require_auth
def get_node_tables(node_id):
    """Return the latest nftables table list for a node.

    The data is populated when the agent sends a report with a 'tables' field.

    Returns JSON:
        {
            "node_id": "<uuid>",
            "tables": [...] or null,
            "last_report_at": "ISO timestamp" or null
        }
    """
    node = NodeService.get_node_by_id(node_id)
    if node is None:
        return jsonify({'error': 'Node not found.'}), 404

    return jsonify({
        'node_id': node.id,
        'tables': node.last_tables,
        'last_report_at': (
            node.last_report_at.isoformat()
            if node.last_report_at else None
        ),
    })


@api_bp.route('/nodes/<node_id>/counters', methods=['GET'])
@require_auth
def get_node_counters(node_id):
    """Return the latest rule counters for a node.

    The data is populated when the agent sends a report with a 'counters' field.

    Returns JSON:
        {
            "node_id": "<uuid>",
            "counters": {...} or null,
            "last_report_at": "ISO timestamp" or null
        }
    """
    node = NodeService.get_node_by_id(node_id)
    if node is None:
        return jsonify({'error': 'Node not found.'}), 404

    return jsonify({
        'node_id': node.id,
        'counters': node.last_counters,
        'last_report_at': (
            node.last_report_at.isoformat()
            if node.last_report_at else None
        ),
    })
