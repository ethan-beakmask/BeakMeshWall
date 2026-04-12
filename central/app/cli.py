"""
Flask CLI commands for administrative operations.

Usage:
    flask create-admin --username <name> --password <pass>
    flask create-token --description <desc> [--expires-hours N] [--max-uses N]
"""

import secrets
from datetime import datetime, timezone, timedelta

import click
from werkzeug.security import generate_password_hash

from .extensions import db
from .models.user import User
from .models.api_key import RegistrationToken
from .services.firewall_service import FirewallService


def register_commands(app):
    """Register all CLI commands with the Flask application."""

    @app.cli.command('create-admin')
    @click.option('--username', required=True, help='Admin username.')
    @click.option('--password', required=True, help='Admin password.')
    @click.option('--display-name', default=None, help='Display name (optional).')
    def create_admin(username, password, display_name):
        """Create an admin user account."""
        existing = User.query.filter_by(username=username).first()
        if existing:
            click.echo(f'Error: User "{username}" already exists.')
            raise SystemExit(1)

        user = User(
            username=username,
            display_name=display_name or username,
            role='admin',
            is_active=True,
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        click.echo(f'Admin user "{username}" created successfully.')

    @app.cli.command('create-token')
    @click.option('--description', required=True, help='Token description.')
    @click.option(
        '--expires-hours', default=24, type=int,
        help='Hours until expiration (default: 24).'
    )
    @click.option(
        '--max-uses', default=1, type=int,
        help='Maximum number of registrations (default: 1).'
    )
    def create_token(description, expires_hours, max_uses):
        """Create a registration token for agent enrollment.

        The plaintext token is displayed once and cannot be retrieved later.
        """
        # Generate a secure random token
        token_value = secrets.token_urlsafe(32)
        prefix = token_value[:8]
        token_hash = generate_password_hash(token_value)

        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

        reg_token = RegistrationToken(
            token_hash=token_hash,
            prefix=prefix,
            description=description,
            max_uses=max_uses,
            expires_at=expires_at,
        )

        db.session.add(reg_token)
        db.session.commit()

        click.echo('Registration token created:')
        click.echo(f'  Token:       {token_value}')
        click.echo(f'  Prefix:      {prefix}')
        click.echo(f'  Description: {description}')
        click.echo(f'  Max uses:    {max_uses}')
        click.echo(f'  Expires at:  {expires_at.isoformat()}')
        click.echo('')
        click.echo('Save this token now -- it cannot be retrieved later.')

    @app.cli.command('expire-rules')
    def expire_rules():
        """Manually expire stale firewall rules.

        Finds active rules whose expires_at is in the past,
        marks them as expired, and creates unblock tasks.
        """
        expired = FirewallService.expire_stale_rules()
        if expired:
            click.echo(f'Expired {len(expired)} rule(s).')
            for rule in expired:
                click.echo(f'  Rule #{rule.id}: {rule.ip_address}')
        else:
            click.echo('No expired rules found.')
