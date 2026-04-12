"""
Health check endpoint for monitoring and load balancer probes.

GET /api/v1/health -- no authentication required.
"""

from flask import jsonify
from sqlalchemy import text

from . import api_bp
from ..extensions import db
from ..scheduler import _scheduler


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Return system health status.

    Checks:
        - Database connectivity (SELECT 1)
        - Background scheduler running

    Returns 200 if all checks pass, 503 if any critical check fails.
    """
    status = 'ok'
    checks = {}

    # Database connectivity
    try:
        db.session.execute(text('SELECT 1'))
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {e}'
        status = 'degraded'

    # Background scheduler
    if _scheduler is not None and _scheduler.running:
        checks['scheduler'] = 'ok'
    elif _scheduler is None:
        # Scheduler not initialized (testing mode or reloader parent process)
        checks['scheduler'] = 'not_started'
    else:
        checks['scheduler'] = 'stopped'
        status = 'degraded'

    code = 200 if status == 'ok' else 503
    return jsonify({'status': status, 'checks': checks}), code
