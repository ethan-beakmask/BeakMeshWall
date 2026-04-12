"""
Dashboard blueprint for the web UI.
"""

from flask import Blueprint

dashboard_bp = Blueprint(
    'dashboard', __name__, template_folder='../templates/dashboard'
)

from . import routes  # noqa: E402, F401 -- register routes
