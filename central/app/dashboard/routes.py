"""
Dashboard web routes: main dashboard and node inventory.
"""

from flask import render_template
from flask_login import login_required

from . import dashboard_bp
from ..services.node_service import NodeService


@dashboard_bp.route('/')
@login_required
def index():
    """Render the main dashboard with node statistics."""
    stats = NodeService.get_node_stats()
    return render_template('index.html', stats=stats)


@dashboard_bp.route('/nodes')
@login_required
def nodes():
    """Render the node inventory table."""
    node_list = NodeService.get_all_nodes()
    return render_template('nodes.html', nodes=node_list)
