from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

from app.api import agent_api, rules_api, topology_api, threat_api, nginx_api  # noqa: E402, F401
