import json
from flask import jsonify
from flask_login import login_required
from app.api import api_bp
from app.models.node import Node


@api_bp.route("/topology/<int:node_id>")
@login_required
def topology(node_id):
    """Build request path topology by joining firewall, nginx, and service layers."""
    node = Node.query.get_or_404(node_id)

    if not node.config_json:
        return jsonify({
            "node_id": node.id,
            "hostname": node.hostname,
            "paths": [],
            "warnings": [{"type": "no_data", "detail": "No state data reported yet"}],
        })

    state = json.loads(node.config_json)
    fw_state = state.get("fw_state")
    nginx_state = state.get("nginx_state")
    service_state = state.get("service_state")

    # Handle old format where fw_state was stored directly
    if fw_state is None and ("managed_table" in state or "external_tables" in state):
        fw_state = state

    # Build lookup indexes
    fw_ports = _build_fw_port_index(fw_state)
    nginx_by_port = _build_nginx_port_index(nginx_state)
    svc_by_port = _build_service_port_index(service_state)

    # Collect all known ports
    all_ports = sorted(set(fw_ports.keys()) | set(nginx_by_port.keys()) | set(svc_by_port.keys()))

    paths = []
    warnings = []

    for port in all_ports:
        fw_info = fw_ports.get(port)
        ngx_info = nginx_by_port.get(port)
        svc_info = svc_by_port.get(port)

        status = _determine_status(fw_info, ngx_info, svc_info)

        path_entry = {
            "external_port": port,
            "firewall": fw_info,
            "nginx": ngx_info,
            "service": svc_info,
            "status": status,
        }
        paths.append(path_entry)

    # Non-compliant nginx files warning
    if nginx_state and nginx_state.get("non_compliant_files"):
        warnings.append({
            "type": "non_compliant",
            "files": nginx_state["non_compliant_files"],
        })

    return jsonify({
        "node_id": node.id,
        "hostname": node.hostname,
        "paths": paths,
        "warnings": warnings,
    })


def _build_fw_port_index(fw_state):
    """Extract ports with ACCEPT rules from firewall state."""
    index = {}
    if not fw_state:
        return index

    managed = fw_state.get("managed_table")
    if not managed:
        return index

    for chain in managed.get("chains", []):
        if chain.get("hook") != "input":
            continue
        for rule in chain.get("rules", []):
            # Try to extract destination port from rule expression
            expr = rule.get("expr", "")
            port = _extract_port_from_expr(expr)
            if port:
                index[port] = {
                    "action": "accept",
                    "rule_summary": rule.get("comment", expr[:80] if isinstance(expr, str) else ""),
                }

    return index


def _extract_port_from_expr(expr):
    """Try to extract a TCP/UDP destination port number from nft rule expression."""
    if not expr:
        return None

    # expr can be a JSON string of nft expression array
    if isinstance(expr, str):
        try:
            expr_list = json.loads(expr)
        except (json.JSONDecodeError, TypeError):
            return None
    elif isinstance(expr, list):
        expr_list = expr
    else:
        return None

    # Look for dport match in expression objects
    for item in expr_list:
        if not isinstance(item, dict):
            continue
        match = item.get("match")
        if not match:
            continue
        right = match.get("right")
        left = match.get("left", {})
        if isinstance(left, dict):
            payload = left.get("payload", {})
            if payload.get("field") == "dport":
                if isinstance(right, (int, float)):
                    return int(right)
    return None


def _build_nginx_port_index(nginx_state):
    """Index nginx servers by listen port."""
    index = {}
    if not nginx_state:
        return index

    for server in nginx_state.get("servers", []):
        port = server.get("listen_port", 0)
        if port == 0:
            continue

        index[port] = {
            "service_name": server.get("service_name", ""),
            "project": server.get("project", ""),
            "type": server.get("type", ""),
            "listen": "{}:{}".format(
                server.get("listen_addr", ""),
                server.get("listen_port", ""),
            ),
            "server_name": server.get("server_name", "_"),
            "backend": server.get("backend", ""),
            "locations": server.get("locations", []),
        }

    return index


def _build_service_port_index(service_state):
    """Index listening services by port. Prefer 127.0.0.1 bindings."""
    index = {}
    if not service_state:
        return index

    for listener in service_state.get("listeners", []):
        port = listener.get("port", 0)
        if port == 0:
            continue

        bind = listener.get("bind", "")

        # Skip nginx's own listen sockets and IPv6 duplicates
        process = listener.get("process", "")
        if process == "nginx":
            continue

        # Prefer 127.0.0.1 binding over 0.0.0.0 for the same port
        if port in index and index[port]["bind"] == "127.0.0.1":
            continue

        index[port] = {
            "bind": bind,
            "port": port,
            "process": process,
            "pid": listener.get("pid", 0),
        }

    return index


def _determine_status(fw_info, ngx_info, svc_info):
    """Determine the health/compliance status of a path."""
    has_fw = fw_info is not None
    has_ngx = ngx_info is not None
    has_svc = svc_info is not None

    if not has_svc and not has_ngx:
        # Firewall rule for a port with nothing listening
        return "unused"

    if has_svc and not has_ngx:
        bind = svc_info.get("bind", "")
        if bind == "0.0.0.0" or bind == "::":
            return "no_proxy"       # Red: exposed without nginx
        return "no_proxy_local"     # Yellow: bound to local but no nginx

    if has_ngx and has_svc and has_fw:
        return "ok"                 # Green: full three-layer path

    if has_ngx and has_svc and not has_fw:
        return "no_firewall"        # Yellow: nginx + service but no explicit fw rule

    if has_ngx and not has_svc:
        return "service_down"       # Red: nginx configured but no process

    return "unknown"
