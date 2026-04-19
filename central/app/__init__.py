from flask import Flask
from app.config import Config
from app.extensions import db, migrate, login_manager


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return db.session.get(User, int(user_id))

    # Register blueprints
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp
    from app.api import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)

    # CLI commands
    from app.cli import register_cli
    register_cli(app)

    # Template filters
    import json as _json

    @app.template_filter("parse_ip")
    def parse_ip_filter(payload_str):
        """Extract 'ip' from a JSON payload string."""
        try:
            return _json.loads(payload_str).get("ip", "")
        except (ValueError, TypeError):
            return ""

    return app
