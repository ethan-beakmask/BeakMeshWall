"""
Authentication routes: login, logout.
"""

from datetime import datetime, timezone

from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from . import auth_bp
from ..extensions import db
from ..models.user import User


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

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard.index'))

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Log the current user out and redirect to login."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
