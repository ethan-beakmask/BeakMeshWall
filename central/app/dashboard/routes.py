"""
Dashboard web routes: main dashboard, node inventory, rules, tasks,
threat feed, tables, audit log.
"""

from functools import wraps

from flask import render_template, abort
from flask_login import login_required, current_user

from . import dashboard_bp
from ..services.node_service import NodeService


def admin_required(f):
    """Dashboard decorator: require authenticated admin user."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


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


@dashboard_bp.route('/tables')
@login_required
def tables():
    """Render the nftables external table observation page."""
    node_list = NodeService.get_all_nodes()
    return render_template('tables.html', nodes=node_list)


@dashboard_bp.route('/audit')
@login_required
def audit():
    """Render the audit log page."""
    return render_template('audit.html')


@dashboard_bp.route('/users')
@admin_required
def users():
    """Render the user management page (admin only)."""
    return render_template('users.html')


@dashboard_bp.route('/apikeys')
@admin_required
def apikeys():
    """Render the API key management page (admin only)."""
    return render_template('apikeys.html')
