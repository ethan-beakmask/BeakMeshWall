"""
Flask extension instances.

Instantiated here, initialized with the app in the factory (create_app).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

# Redirect unauthenticated users to the login page
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login session management."""
    from .models.user import User
    return db.session.get(User, int(user_id))
