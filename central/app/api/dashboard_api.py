"""
Dashboard API endpoints for AJAX auto-refresh.
"""

from flask import jsonify
from flask_login import login_required

from . import api_bp
from ..services.node_service import NodeService


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

    Returns JSON:
        {"nodes": [...]}
    """
    nodes = NodeService.get_all_nodes()
    return jsonify({'nodes': nodes})
