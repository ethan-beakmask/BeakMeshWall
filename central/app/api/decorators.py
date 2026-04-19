"""Authentication decorators for API endpoints."""

from functools import wraps
from datetime import datetime, timezone

from flask import request, jsonify, g
from werkzeug.security import check_password_hash

from app.extensions import db
from app.models.api_key import ApiKey


def require_api_key(f):
    """Verify X-API-Key header against the api_keys table.

    On success, sets g.current_api_key to the matched ApiKey instance.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key_value = request.headers.get("X-API-Key", "")
        if not api_key_value:
            return jsonify({"error": "Missing X-API-Key header."}), 401

        # Use prefix (first 8 chars) to narrow candidates
        prefix = api_key_value[:8]
        candidates = ApiKey.query.filter_by(prefix=prefix, is_active=True).all()

        matched = None
        for candidate in candidates:
            if check_password_hash(candidate.key_hash, api_key_value):
                matched = candidate
                break

        if matched is None:
            return jsonify({"error": "Invalid API key."}), 401

        matched.last_used_at = datetime.now(timezone.utc)
        db.session.commit()

        g.current_api_key = matched
        return f(*args, **kwargs)

    return decorated


def require_api_key_scope(scope):
    """Require a specific API key scope (e.g. 'full', 'threat').

    Must be used AFTER require_api_key so that g.current_api_key is set.
    A 'full' scope key implicitly satisfies any scope requirement.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            key = getattr(g, "current_api_key", None)
            if key is None:
                return jsonify({"error": "Authentication required."}), 401
            if key.scope != "full" and key.scope != scope:
                return jsonify({"error": f"API key scope '{scope}' required."}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
