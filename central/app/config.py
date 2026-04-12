"""
Configuration classes for BeakMeshWall Central Server.

All sensitive values are loaded from environment variables.
Never hardcode passwords, tokens, or IPs.
"""

import os


class BaseConfig:
    """Base configuration shared across all environments."""

    # SECRET_KEY is required -- abort if not set
    SECRET_KEY = os.environ.get('BMW_SECRET_KEY')

    # Database URI: prefer DATABASE_URL, otherwise construct from individual vars
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://{user}:{password}@{host}:{port}/{dbname}'.format(
            user=os.environ.get('DB_USER', 'beakmeshwall'),
            password=os.environ.get('DB_PASSWORD', ''),
            host=os.environ.get('DB_HOST', 'localhost'),
            port=os.environ.get('DB_PORT', '5432'),
            dbname=os.environ.get('DB_NAME', 'beakmeshwall'),
        )
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session / CSRF
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # OIDC Configuration (optional -- leave unset to use Local Auth only)
    OIDC_ENABLED = os.environ.get('BMW_OIDC_ENABLED', 'false').lower() == 'true'
    OIDC_PROVIDER_NAME = os.environ.get('BMW_OIDC_PROVIDER_NAME', 'SSO')
    OIDC_CLIENT_ID = os.environ.get('BMW_OIDC_CLIENT_ID', '')
    OIDC_CLIENT_SECRET = os.environ.get('BMW_OIDC_CLIENT_SECRET', '')
    OIDC_DISCOVERY_URL = os.environ.get('BMW_OIDC_DISCOVERY_URL', '')
    # e.g. https://accounts.google.com/.well-known/openid-configuration
    OIDC_SCOPES = os.environ.get('BMW_OIDC_SCOPES', 'openid email profile')

    # Agent poll interval in seconds (returned to agents)
    AGENT_POLL_INTERVAL = int(os.environ.get('BMW_POLL_INTERVAL', '30'))

    # Heartbeat timeout: node considered offline after this many seconds
    HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get('BMW_HEARTBEAT_TIMEOUT', '90'))


class DevelopmentConfig(BaseConfig):
    """Development environment configuration."""

    DEBUG = True
    SESSION_COOKIE_SECURE = False

    # Allow running without SECRET_KEY in dev (fallback to a non-empty default)
    SECRET_KEY = os.environ.get('BMW_SECRET_KEY', 'dev-change-me-in-production')


class ProductionConfig(BaseConfig):
    """Production environment configuration."""

    DEBUG = False
    SESSION_COOKIE_SECURE = True

    @classmethod
    def init_app(cls, app):
        """Validate production-critical settings."""
        if not cls.SECRET_KEY:
            raise RuntimeError(
                'BMW_SECRET_KEY environment variable is required in production.'
            )


class TestingConfig(BaseConfig):
    """Testing environment configuration."""

    TESTING = True
    DEBUG = True
    SECRET_KEY = 'testing-secret-key-not-for-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'TEST_DATABASE_URL', 'sqlite:///:memory:'
    )
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False


config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
}
