"""
Authentication routes: login, logout, OIDC login/callback.
"""

import secrets
from datetime import datetime, timezone

from flask import (
    render_template, redirect, url_for, flash, request,
    current_app, abort,
)
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from ..extensions import db
from ..models.user import User
from ..services.audit_service import AuditService


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login via web form."""
    # Already authenticated -- redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html'), 400

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return render_template('login.html'), 401

        if not user.is_active:
            flash('Account is disabled. Contact an administrator.', 'danger')
            return render_template('login.html'), 403

        # Successful login
        login_user(user, remember=False)
        user.last_login_at = datetime.now(timezone.utc)
        db.session.commit()

        # Audit: successful login
        AuditService.log(
            actor=f'user:{username}',
            action='login',
            resource_type='user',
            resource_id=user.id,
            ip_address=request.remote_addr,
        )

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Log the current user out and redirect to login."""
    username = current_user.username

    # Audit: logout
    AuditService.log(
        actor=f'user:{username}',
        action='logout',
        resource_type='user',
        resource_id=current_user.id,
        ip_address=request.remote_addr,
    )

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# OIDC routes (only active when OIDC_ENABLED is True)
# ---------------------------------------------------------------------------

@auth_bp.route('/oidc/login')
def oidc_login():
    """Redirect to OIDC provider for authentication."""
    if not current_app.config.get('OIDC_ENABLED'):
        abort(404)
    from .oidc import get_oidc_client
    client = get_oidc_client()
    if client is None:
        abort(500, 'OIDC not configured')
    redirect_uri = url_for('auth.oidc_callback', _external=True)
    return client.authorize_redirect(redirect_uri)


@auth_bp.route('/oidc/callback')
def oidc_callback():
    """Handle OIDC provider callback."""
    if not current_app.config.get('OIDC_ENABLED'):
        abort(404)
    from .oidc import get_oidc_client
    client = get_oidc_client()
    if client is None:
        abort(500, 'OIDC not configured')

    token = client.authorize_access_token()
    userinfo = token.get('userinfo')
    if userinfo is None:
        userinfo = client.userinfo()

    email = userinfo.get('email', '')
    name = userinfo.get('name', email)
    sub = userinfo.get('sub', '')

    # Find or create user by email (OIDC users have role 'viewer' by default)
    user = User.query.filter_by(username=email).first()
    if user is None:
        user = User(
            username=email,
            display_name=name,
            role='viewer',
            is_active=True,
        )
        # Set a random password (OIDC users don't use password auth)
        user.set_password(secrets.token_urlsafe(32))
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=False)
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    # Audit log
    AuditService.log(
        actor=f'user:{user.username}',
        action='login_oidc',
        resource_type='user',
        resource_id=str(user.id),
        detail={
            'provider': current_app.config.get('OIDC_PROVIDER_NAME', 'SSO'),
            'sub': sub,
        },
        ip_address=request.remote_addr,
    )

    return redirect(url_for('dashboard.index'))
