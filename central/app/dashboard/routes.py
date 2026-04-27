import json
from datetime import datetime, timezone
from flask import render_template, request
from flask_login import login_required
from app.dashboard import dashboard_bp
from app.models.managed_rule import DriftEvent, ManagedRule
from app.models.named_set import NamedSet
from app.models.node import Node
from app.models.task import Task
from app.models.threat_block import ThreatBlock
from app.models.threat_whitelist import ThreatWhitelist


# Threshold for considering an agent "stale" / probably offline.
# Aligned with the 60-3600s drift_check_interval range (default 300s);
# any node not seen in 3x default counts as suspect.
AGENT_STALE_SECONDS = 900


def _agent_status(node):
    """Return ('ok'|'stale'|'never', seconds_since_last_seen|None) for a node.

    'ok'    = seen within AGENT_STALE_SECONDS
    'stale' = seen, but longer ago
    'never' = never reported in
    """
    if not node or not node.last_seen_at:
        return "never", None
    delta = (datetime.now(timezone.utc) - node.last_seen_at).total_seconds()
    if delta <= AGENT_STALE_SECONDS:
        return "ok", int(delta)
    return "stale", int(delta)


def _recent_tasks(node_id, actions, limit=15):
    if not node_id:
        return []
    rows = Task.query.filter(
        Task.node_id == node_id,
        Task.action.in_(actions),
    ).order_by(Task.created_at.desc()).limit(limit).all()
    out = []
    for t in rows:
        try:
            payload = json.loads(t.payload)
        except (TypeError, ValueError):
            payload = {}
        out.append({
            "id": t.id,
            "action": t.action,
            "status": t.status,
            "result": t.result or "",
            "created_at": t.created_at.isoformat() if t.created_at else "",
            "completed_at": t.completed_at.isoformat() if t.completed_at else "",
            "created_by": t.created_by or "",
            "payload_summary": _summarize_payload(t.action, payload),
        })
    return out


def _summarize_payload(action, payload):
    """Short one-line summary of a task payload for the Recent Tasks list."""
    if action in ("apply_rule", "remove_rule"):
        r = payload.get("rule") or {}
        bits = [r.get("action", "?"), r.get("direction", "?")]
        if r.get("src") and r["src"] != "any":
            bits.append("src=" + r["src"])
        if r.get("dst") and r["dst"] != "any":
            bits.append("dst=" + r["dst"])
        if r.get("dport") and r["dport"] != "any":
            bits.append("dport=" + r["dport"])
        return " ".join(bits)
    if action == "apply_nginx_access":
        return "regenerate access.conf"
    if action in ("create_set", "delete_set"):
        return "name=" + (payload.get("name") or "")
    if action in ("set_add", "set_remove"):
        return f"{payload.get('name','')} +/- {payload.get('address','')}"
    if action == "block_ip":
        return "ip=" + (payload.get("ip") or "")
    if action == "unblock_ip":
        return "ip=" + (payload.get("ip") or "")
    if action == "cleanup_unmanaged":
        keep = payload.get("keep_ids") or []
        return f"keep {len(keep)} ids"
    return ""


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


@dashboard_bp.route("/firewall-rules")
@login_required
def firewall_rules():
    nodes = Node.query.order_by(Node.hostname).all()
    selected_id = request.args.get("node_id", type=int)
    selected = next((n for n in nodes if n.id == selected_id), None) or (nodes[0] if nodes else None)
    rules = []
    if selected:
        rows = ManagedRule.query.filter_by(
            node_id=selected.id, subsystem="firewall", status="active"
        ).order_by(ManagedRule.applied_at.desc()).all()
        for r in rows:
            try:
                rule_obj = json.loads(r.schema_rule)
            except (TypeError, ValueError):
                rule_obj = {}
            rules.append({
                "fingerprint": r.fingerprint,
                "rule": rule_obj,
                "applied_at": r.applied_at.isoformat() if r.applied_at else "",
            })
    agent_status, agent_age = _agent_status(selected)
    tasks = _recent_tasks(selected.id if selected else None,
                          ["apply_rule", "remove_rule", "cleanup_unmanaged",
                           "block_ip", "unblock_ip", "add_rule", "delete_rule",
                           "flush"])
    return render_template(
        "dashboard/firewall_rules.html",
        nodes=nodes, selected=selected, rules=rules,
        agent_status=agent_status, agent_age=agent_age, tasks=tasks,
    )


@dashboard_bp.route("/nginx-rules")
@login_required
def nginx_rules():
    nodes = Node.query.order_by(Node.hostname).all()
    selected_id = request.args.get("node_id", type=int)
    selected = next((n for n in nodes if n.id == selected_id), None) or (nodes[0] if nodes else None)
    rules = []
    if selected and selected.nginx_managed:
        rows = ManagedRule.query.filter_by(
            node_id=selected.id, subsystem="nginx", status="active"
        ).order_by(ManagedRule.applied_at).all()
        for r in rows:
            try:
                rule_obj = json.loads(r.schema_rule)
            except (TypeError, ValueError):
                rule_obj = {}
            rules.append({
                "fingerprint": r.fingerprint,
                "rule": rule_obj,
                "applied_at": r.applied_at.isoformat() if r.applied_at else "",
            })
    agent_status, agent_age = _agent_status(selected)
    tasks = _recent_tasks(selected.id if selected else None,
                          ["apply_nginx_access"])
    return render_template(
        "dashboard/nginx_rules.html",
        nodes=nodes, selected=selected, rules=rules,
        agent_status=agent_status, agent_age=agent_age, tasks=tasks,
    )


@dashboard_bp.route("/named-sets")
@login_required
def named_sets():
    nodes = Node.query.order_by(Node.hostname).all()
    selected_id = request.args.get("node_id", type=int)
    selected = next((n for n in nodes if n.id == selected_id), None) or (nodes[0] if nodes else None)
    sets_data = []
    if selected:
        sets = NamedSet.query.filter_by(node_id=selected.id).order_by(NamedSet.name).all()
        for s in sets:
            sets_data.append({
                "id": s.id,
                "name": s.name,
                "family": s.family,
                "members": [{"id": m.id, "address": m.address} for m in s.members],
            })
    agent_status, agent_age = _agent_status(selected)
    tasks = _recent_tasks(selected.id if selected else None,
                          ["create_set", "delete_set", "set_add", "set_remove"])
    return render_template(
        "dashboard/named_sets.html",
        nodes=nodes, selected=selected, sets=sets_data,
        agent_status=agent_status, agent_age=agent_age, tasks=tasks,
    )


@dashboard_bp.route("/drift")
@login_required
def drift():
    nodes = Node.query.order_by(Node.hostname).all()
    events = DriftEvent.query.order_by(DriftEvent.detected_at.desc()).limit(100).all()
    rendered = []
    nodes_by_id = {n.id: n for n in nodes}
    for e in events:
        node = nodes_by_id.get(e.node_id)
        try:
            missing = json.loads(e.missing_in_actual or "[]")
        except (TypeError, ValueError):
            missing = []
        try:
            extra = json.loads(e.extra_in_actual or "[]")
        except (TypeError, ValueError):
            extra = []
        rendered.append({
            "id": e.id,
            "hostname": node.hostname if node else f"node-{e.node_id}",
            "node_id": e.node_id,
            "subsystem": e.subsystem,
            "detected_at": e.detected_at.isoformat() if e.detected_at else "",
            "policy": e.policy_applied,
            "notification_sent": e.notification_sent,
            "missing": missing,
            "extra": extra,
            "backup_path": e.backup_path or "",
        })
    # Summarize per-node policy settings for the bottom panel.
    policy_view = []
    for n in nodes:
        try:
            pol = json.loads(n.drift_policies or "{}")
        except (TypeError, ValueError):
            pol = {}
        policy_view.append({
            "id": n.id,
            "hostname": n.hostname,
            "fw_driver": n.fw_driver,
            "nginx_managed": bool(n.nginx_managed),
            "policy_firewall": pol.get("firewall", "notify"),
            "policy_nginx": pol.get("nginx", "notify"),
            "drift_check_interval": n.drift_check_interval,
        })
    return render_template(
        "dashboard/drift.html",
        events=rendered, policies=policy_view,
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
