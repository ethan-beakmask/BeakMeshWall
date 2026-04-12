"""
Flask application factory for BeakMeshWall Central Server.
"""

from flask import Flask, redirect, url_for

from .config import config_map
from .extensions import db, migrate, login_manager, csrf
from .auth.oidc import init_oidc
from .scheduler import init_scheduler


def create_app(config_name=None):
    """Create and configure the Flask application.

    Args:
        config_name: Configuration name ('development', 'production', 'testing').
                     Defaults to 'development'.

    Returns:
        Configured Flask application instance.
    """
    if config_name is None:
        config_name = 'development'

    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Initialize OIDC (no-op if not configured)
    init_oidc(app)

    # Register blueprints
    from .auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    from .dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')

    # Exempt API blueprint from CSRF protection (token-based auth)
    csrf.exempt(api_bp)

    # Register CLI commands
    from . import cli
    cli.register_commands(app)

    # Start background scheduler (rule expiry, etc.)
    init_scheduler(app)

    # Root route redirects to dashboard
    @app.route('/')
    def index():
        return redirect(url_for('dashboard.index'))

    return app
