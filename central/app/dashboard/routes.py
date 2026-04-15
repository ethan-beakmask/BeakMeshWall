import json
from flask import render_template
from flask_login import login_required
from app.dashboard import dashboard_bp
from app.models.node import Node
from app.models.task import Task


@dashboard_bp.route("/")
@login_required
def index():
    nodes = Node.query.order_by(Node.hostname).all()
    online = sum(1 for n in nodes if n.status == "online")
    return render_template(
        "dashboard/index.html",
        nodes=nodes,
        total_nodes=len(nodes),
        online_nodes=online,
    )


@dashboard_bp.route("/nodes")
@login_required
def nodes():
    nodes = Node.query.order_by(Node.hostname).all()
    return render_template("dashboard/nodes.html", nodes=nodes)


@dashboard_bp.route("/nodes/<int:node_id>")
@login_required
def node_detail(node_id):
    node = Node.query.get_or_404(node_id)
    fw_state = None
    if node.config_json:
        fw_state = json.loads(node.config_json)
    tasks = Task.query.filter_by(node_id=node.id).order_by(
        Task.created_at.desc()
    ).limit(20).all()
    return render_template(
        "dashboard/node_detail.html",
        node=node,
        fw_state=fw_state,
        tasks=tasks,
    )
