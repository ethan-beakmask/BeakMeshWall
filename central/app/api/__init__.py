"""
API blueprint for agent communication and external integrations.

All routes under /api/v1/ -- CSRF is exempted for this blueprint
since authentication is token-based (Bearer / X-API-Key).
"""

from flask import Blueprint

api_bp = Blueprint('api', __name__)

from . import agent_api  # noqa: E402, F401 -- register agent routes
from . import dashboard_api  # noqa: E402, F401 -- register dashboard stats routes
from . import rules_api  # noqa: E402, F401 -- register firewall rules CRUD routes
from . import threat_api  # noqa: E402, F401 -- register threat feed routes
from . import tasks_api  # noqa: E402, F401 -- register task query routes
from . import audit_api  # noqa: E402, F401 -- register audit log routes
from . import tables_api  # noqa: E402, F401 -- register tables/counters routes
from . import admin_api  # noqa: E402, F401 -- register admin management routes
from . import health_api  # noqa: E402, F401 -- register health check endpoint
