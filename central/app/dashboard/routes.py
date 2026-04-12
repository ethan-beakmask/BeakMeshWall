"""
Dashboard web routes: main dashboard, node inventory, rules, tasks, threat feed.
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


@dashboard_bp.route('/rules')
@login_required
def rules():
    """Render the firewall rules management page."""
    return render_template('rules.html')


@dashboard_bp.route('/tasks')
@login_required
def tasks():
    """Render the task monitoring page."""
    return render_template('tasks.html')


@dashboard_bp.route('/threat')
@login_required
def threat():
    """Render the threat feed block list page."""
    return render_template('threat.html')
