"""
Admin API endpoints: user management and API key management.

All endpoints require admin session authentication.
"""

import secrets
from datetime import datetime, timezone, timedelta

from flask import request, jsonify
from flask_login import current_user
from werkzeug.security import generate_password_hash

from . import api_bp
from .decorators import require_admin
from ..extensions import db
from ..models.user import User
from ..models.api_key import APIKey
from ..services.audit_service import AuditService

VALID_ROLES = ('admin', 'operator', 'viewer')
VALID_SCOPES = ('full', 'threat_only')


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------

@api_bp.route('/admin/users', methods=['GET'])
@require_admin
def list_users():
    """Return all user accounts."""
    users = User.query.order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        result.append({
            'id': u.id,
            'username': u.username,
            'display_name': u.display_name,
            'role': u.role,
            'is_active': u.is_active,
            'last_login_at': u.last_login_at.isoformat() if u.last_login_at else None,
            'created_at': u.created_at.isoformat() if u.created_at else None,
        })
    return jsonify({'users': result})


@api_bp.route('/admin/users', methods=['POST'])
@require_admin
def create_user():
    """Create a new user account."""
    data = request.get_json(silent=True) or {}

    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    display_name = (data.get('display_name') or '').strip()
    role = data.get('role', 'viewer')

    if not username:
        return jsonify({'error': 'Username is required.'}), 400
    if len(username) > 80:
        return jsonify({'error': 'Username too long (max 80).'}), 400
    if not password or len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters.'}), 400
    if role not in VALID_ROLES:
        return jsonify({'error': f'Invalid role. Must be one of: {", ".join(VALID_ROLES)}'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': f'Username "{username}" already exists.'}), 409

    user = User(
        username=username,
        display_name=display_name or username,
        role=role,
        is_active=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    AuditService.log(
        actor=current_user.username,
        action='create_user',
        resource_type='user',
        resource_id=user.id,
        detail={'username': username, 'role': role},
        ip_address=request.remote_addr,
    )

    return jsonify({'id': user.id, 'username': user.username}), 201


@api_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@require_admin
def update_user(user_id):
    """Update an existing user account."""
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'User not found.'}), 404

    data = request.get_json(silent=True) or {}
    changes = {}

    # Display name
    if 'display_name' in data:
        new_name = (data['display_name'] or '').strip()
        if new_name:
            user.display_name = new_name
            changes['display_name'] = new_name

    # Role
    if 'role' in data:
        new_role = data['role']
        if new_role not in VALID_ROLES:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(VALID_ROLES)}'}), 400
        # Prevent admin from demoting themselves
        if user.id == current_user.id and new_role != 'admin':
            return jsonify({'error': 'Cannot change your own role.'}), 400
        user.role = new_role
        changes['role'] = new_role

    # Active status
    if 'is_active' in data:
        # Prevent admin from deactivating themselves
        if user.id == current_user.id and not data['is_active']:
            return jsonify({'error': 'Cannot deactivate your own account.'}), 400
        user.is_active = bool(data['is_active'])
        changes['is_active'] = user.is_active

    # Password reset
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters.'}), 400
        user.set_password(data['password'])
        changes['password'] = 'reset'

    if not changes:
        return jsonify({'error': 'No changes provided.'}), 400

    db.session.commit()

    AuditService.log(
        actor=current_user.username,
        action='update_user',
        resource_type='user',
        resource_id=user.id,
        detail={'username': user.username, 'changes': changes},
        ip_address=request.remote_addr,
    )

    return jsonify({'ok': True})


@api_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@require_admin
def delete_user(user_id):
    """Delete a user account (deactivate)."""
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify({'error': 'User not found.'}), 404
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete your own account.'}), 400

    username = user.username
    db.session.delete(user)
    db.session.commit()

    AuditService.log(
        actor=current_user.username,
        action='delete_user',
        resource_type='user',
        resource_id=user_id,
        detail={'username': username},
        ip_address=request.remote_addr,
    )

    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# API Key Management
# ---------------------------------------------------------------------------

@api_bp.route('/admin/apikeys', methods=['GET'])
@require_admin
def list_apikeys():
    """Return all API keys (without the secret)."""
    keys = APIKey.query.order_by(APIKey.created_at.desc()).all()
    result = []
    for k in keys:
        result.append({
            'id': k.id,
            'name': k.name,
            'prefix': k.prefix,
            'scope': k.scope,
            'is_active': k.is_active,
            'is_expired': k.is_expired,
            'created_by': k.created_by.username if k.created_by else None,
            'expires_at': k.expires_at.isoformat() if k.expires_at else None,
            'last_used_at': k.last_used_at.isoformat() if k.last_used_at else None,
            'created_at': k.created_at.isoformat() if k.created_at else None,
        })
    return jsonify({'apikeys': result})


@api_bp.route('/admin/apikeys', methods=['POST'])
@require_admin
def create_apikey():
    """Create a new API key. Returns the plaintext key exactly once."""
    data = request.get_json(silent=True) or {}

    name = (data.get('name') or '').strip()
    scope = data.get('scope', 'full')
    expires_days = data.get('expires_days')  # None = no expiration

    if not name:
        return jsonify({'error': 'Name is required.'}), 400
    if len(name) > 120:
        return jsonify({'error': 'Name too long (max 120).'}), 400
    if scope not in VALID_SCOPES:
        return jsonify({'error': f'Invalid scope. Must be one of: {", ".join(VALID_SCOPES)}'}), 400

    # Generate a secure random key
    key_value = secrets.token_urlsafe(48)
    prefix = key_value[:8]
    key_hash = generate_password_hash(key_value)

    expires_at = None
    if expires_days is not None:
        try:
            days = int(expires_days)
            if days > 0:
                expires_at = datetime.now(timezone.utc) + timedelta(days=days)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid expires_days value.'}), 400

    api_key = APIKey(
        name=name,
        key_hash=key_hash,
        prefix=prefix,
        scope=scope,
        created_by_id=current_user.id,
        is_active=True,
        expires_at=expires_at,
    )
    db.session.add(api_key)
    db.session.commit()

    AuditService.log(
        actor=current_user.username,
        action='create_apikey',
        resource_type='apikey',
        resource_id=api_key.id,
        detail={'name': name, 'scope': scope, 'prefix': prefix},
        ip_address=request.remote_addr,
    )

    return jsonify({
        'id': api_key.id,
        'name': name,
        'prefix': prefix,
        'key': key_value,  # Shown once only
    }), 201


@api_bp.route('/admin/apikeys/<int:key_id>', methods=['DELETE'])
@require_admin
def revoke_apikey(key_id):
    """Revoke (deactivate) an API key."""
    api_key = db.session.get(APIKey, key_id)
    if api_key is None:
        return jsonify({'error': 'API key not found.'}), 404

    api_key.is_active = False
    db.session.commit()

    AuditService.log(
        actor=current_user.username,
        action='revoke_apikey',
        resource_type='apikey',
        resource_id=api_key.id,
        detail={'name': api_key.name, 'prefix': api_key.prefix},
        ip_address=request.remote_addr,
    )

    return jsonify({'ok': True})
