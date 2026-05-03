from flask import Blueprint, jsonify

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


@api_bp.route("/health", methods=["GET"])
def health():
    """Liveness probe for installers, monitors, and reverse proxies."""
    return jsonify({"status": "ok", "service": "beakmeshwall-central"}), 200


from app.api import agent_api, rules_api, topology_api, threat_api, nginx_api, sets_api  # noqa: E402, F401
