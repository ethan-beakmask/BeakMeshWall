import json
from flask import render_template, request
from flask_login import login_required
from app.dashboard import dashboard_bp
from app.models.node import Node
from app.models.task import Task
from app.models.threat_block import ThreatBlock
from app.models.threat_whitelist import ThreatWhitelist


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


@dashboard_bp.route("/topology-graph")
@login_required
def topology_graph():
    nodes = Node.query.order_by(Node.hostname).all()
    return render_template("dashboard/topology_graph.html", nodes=nodes)


@dashboard_bp.route("/topology/<int:node_id>")
@login_required
def topology(node_id):
    node = Node.query.get_or_404(node_id)
    state_data = {}
    if node.config_json:
        state_data = json.loads(node.config_json)

    return render_template(
        "dashboard/topology.html",
        node=node,
        state_data=state_data,
    )


@dashboard_bp.route("/help")
@login_required
def help_page():
    lang = request.cookies.get("bmw_lang", "en")
    return render_template("dashboard/help.html", lang=lang)


@dashboard_bp.route("/threat-control")
@login_required
def threat_control():
    active_blocks = ThreatBlock.query.filter_by(status="active").order_by(
        ThreatBlock.created_at.desc()
    ).all()
    whitelist = ThreatWhitelist.query.order_by(ThreatWhitelist.id).all()
    nodes = Node.query.order_by(Node.hostname).all()

    # History: recent threat-related tasks (last 100)
    history = Task.query.filter(
        Task.action.in_(["block_ip", "unblock_ip"]),
        Task.created_by.like("api:%") | Task.created_by.like("web:%"),
    ).order_by(Task.created_at.desc()).limit(100).all()

    # Recent removed/expired blocks
    past_blocks = ThreatBlock.query.filter(
        ThreatBlock.status.in_(["removed", "expired"])
    ).order_by(ThreatBlock.created_at.desc()).limit(50).all()

    return render_template(
        "dashboard/threat_control.html",
        active_blocks=active_blocks,
        whitelist=whitelist,
        nodes=nodes,
        history=history,
        past_blocks=past_blocks,
    )


@dashboard_bp.route("/nodes/<int:node_id>")
@login_required
def node_detail(node_id):
    node = Node.query.get_or_404(node_id)
    fw_state = None
    system_info = None
    if node.config_json:
        state_data = json.loads(node.config_json)
        if "fw_state" in state_data:
            fw_state = state_data["fw_state"]
        elif "managed_table" in state_data or "external_tables" in state_data:
            fw_state = state_data
        if "system_info" in state_data:
            system_info = state_data["system_info"]
    tasks = Task.query.filter_by(node_id=node.id).order_by(
        Task.created_at.desc()
    ).limit(20).all()
    return render_template(
        "dashboard/node_detail.html",
        node=node,
        fw_state=fw_state,
        system_info=system_info,
        tasks=tasks,
    )
