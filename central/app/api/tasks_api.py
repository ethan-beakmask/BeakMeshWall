"""
Task query API endpoints.

Provides read access to task status for the web UI and API consumers.
"""

from flask import request, jsonify

from . import api_bp
from .decorators import require_auth
from ..services.task_service import TaskService


VALID_STATUS_FILTERS = ('pending', 'dispatched', 'completed', 'failed')


@api_bp.route('/tasks', methods=['GET'])
@require_auth
def list_tasks():
    """List tasks with optional filters.

    Query params:
        module   -- filter by module (e.g. 'firewall')
        status   -- filter by status (pending, dispatched, completed, failed)
        node_id  -- filter by target node UUID
        limit    -- max results (default 50, max 200)
    """
    module = request.args.get('module')
    status = request.args.get('status')
    node_id = request.args.get('node_id')
    limit = request.args.get('limit', 50, type=int)

    if status and status not in VALID_STATUS_FILTERS:
        return jsonify({'error': f'Invalid status. Must be one of: {", ".join(VALID_STATUS_FILTERS)}'}), 400

    if limit < 1:
        limit = 1
    elif limit > 200:
        limit = 200

    tasks = TaskService.get_tasks(
        module=module,
        status=status,
        node_id=node_id,
        limit=limit,
    )

    return jsonify({
        'tasks': [t.to_dict() for t in tasks],
        'count': len(tasks),
    })


@api_bp.route('/tasks/<task_id>', methods=['GET'])
@require_auth
def get_task(task_id):
    """Get a single task by ID."""
    task = TaskService.get_task_by_id(task_id)
    if task is None:
        return jsonify({'error': 'Task not found.'}), 404

    return jsonify(task.to_dict())
