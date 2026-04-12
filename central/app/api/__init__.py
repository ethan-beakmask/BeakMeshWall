"""
API blueprint for agent communication and external integrations.

All routes under /api/v1/ -- CSRF is exempted for this blueprint
since authentication is token-based (Bearer / X-API-Key).
"""

from flask import Blueprint

api_bp = Blueprint('api', __name__)

from . import agent_api  # noqa: E402, F401 -- register agent routes
from . import dashboard_api  # noqa: E402, F401 -- register dashboard stats routes
