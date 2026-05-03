from flask import Blueprint

auth_bp = Blueprint("auth", __name__, url_prefix="/beakmeshwall/auth")

from app.auth import routes  # noqa: E402, F401
