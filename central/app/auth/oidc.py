"""
OIDC integration for BeakMeshWall.

When OIDC_ENABLED is True, users can log in via an external OIDC provider
(e.g., Keycloak, Azure AD, Google). Local Auth remains available alongside OIDC.

This module provides the OAuth client setup and callback handling.
If OIDC is not configured, all functions are no-ops.
"""

from authlib.integrations.flask_client import OAuth

oauth = OAuth()


def init_oidc(app):
    """Initialize OIDC client if configured. No-op if OIDC_ENABLED is False."""
    if not app.config.get('OIDC_ENABLED'):
        return

    oauth.init_app(app)

    oauth.register(
        name='oidc',
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        server_metadata_url=app.config['OIDC_DISCOVERY_URL'],
        client_kwargs={'scope': app.config['OIDC_SCOPES']},
    )


def get_oidc_client():
    """Return the OIDC client, or None if not configured."""
    try:
        return oauth.oidc
    except AttributeError:
        return None
