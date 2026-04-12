"""
Dashboard API endpoints for AJAX auto-refresh.
"""

from flask import jsonify
from flask_login import login_required

from . import api_bp
from ..services.node_service import NodeService
from ..models.node import Node


@api_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Return node statistics as JSON for dashboard auto-refresh.

    Returns JSON:
        {"total": int, "online": int, "offline": int}
    """
    stats = NodeService.get_node_stats()
    return jsonify(stats)


@api_bp.route('/dashboard/nodes', methods=['GET'])
@login_required
def dashboard_nodes_list():
    """Return full node list as JSON for the node table auto-refresh.

    Includes counter summary (total packets/bytes) and last_report_at
    for each node.

    Returns JSON:
        {"nodes": [...]}
    """
    nodes = NodeService.get_all_nodes()

    # Enrich each node dict with counter summary
    for node_dict in nodes:
        node_obj = Node.query.get(node_dict['id'])
        counters = node_obj.last_counters if node_obj else None
        total_packets = 0
        total_bytes = 0
        if counters and isinstance(counters, dict):
            rules_data = counters.get('rules', [])
            if isinstance(rules_data, list):
                for r in rules_data:
                    total_packets += r.get('packets', 0) or 0
                    total_bytes += r.get('bytes', 0) or 0
        node_dict['counter_summary'] = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
        }
        node_dict['last_report_at'] = (
            node_obj.last_report_at.isoformat()
            if node_obj and node_obj.last_report_at else None
        )

    return jsonify({'nodes': nodes})
