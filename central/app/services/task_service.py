"""
Task service: business logic for creating, dispatching, and completing tasks.
"""

from uuid import uuid4
from datetime import datetime, timezone

from ..extensions import db
from ..models.task import Task
from ..models.node import Node


class TaskService:
    """Service class for task lifecycle management."""

    @staticmethod
    def create_task(module, action, params, target_node_id=None, created_by=None):
        """Create new task(s).

        If target_node_id is None, one task is created per active (approved) node.
        If target_node_id is specified, a single task is created for that node.

        Args:
            module: Task module (e.g. 'firewall').
            action: Action name (e.g. 'block_ip', 'unblock_ip').
            params: Dict of action parameters.
            target_node_id: UUID of a specific node, or None for all.
            created_by: Identity string of the creator.

        Returns:
            List of created Task instances.
        """
        tasks = []

        if target_node_id is not None:
            task = Task(
                id=str(uuid4()),
                module=module,
                action=action,
                params=params,
                target_node_id=target_node_id,
                status='pending',
                created_by=created_by,
            )
            db.session.add(task)
            tasks.append(task)
        else:
            # Broadcast to all approved nodes
            active_nodes = Node.query.filter_by(status='approved').all()
            for node in active_nodes:
                task = Task(
                    id=str(uuid4()),
                    module=module,
                    action=action,
                    params=params,
                    target_node_id=node.id,
                    status='pending',
                    created_by=created_by,
                )
                db.session.add(task)
                tasks.append(task)

        db.session.commit()
        return tasks

    @staticmethod
    def get_pending_tasks_for_node(node_id):
        """Get all pending tasks for a node and atomically mark them as dispatched.

        This prevents duplicate dispatch if the agent polls again before completing.

        Args:
            node_id: UUID of the node.

        Returns:
            List of Task instances that were marked dispatched.
        """
        now = datetime.now(timezone.utc)
        pending_tasks = Task.query.filter_by(
            target_node_id=node_id,
            status='pending',
        ).order_by(Task.created_at.asc()).all()

        for task in pending_tasks:
            task.status = 'dispatched'
            task.dispatched_at = now

        if pending_tasks:
            db.session.commit()

        return pending_tasks

    @staticmethod
    def complete_task(task_id, status, result=None, error_message=None):
        """Mark a task as completed or failed.

        Args:
            task_id: UUID of the task.
            status: Final status ('completed' or 'failed').
            result: Optional dict of result data from the agent.
            error_message: Optional error description.

        Returns:
            The updated Task instance, or None if not found.
        """
        task = db.session.get(Task, task_id)
        if task is None:
            return None

        task.status = status
        task.result = result
        task.error_message = error_message
        task.completed_at = datetime.now(timezone.utc)
        db.session.commit()
        return task

    @staticmethod
    def get_tasks(module=None, status=None, node_id=None, limit=50):
        """Query tasks with optional filters.

        Args:
            module: Filter by module name.
            status: Filter by status.
            node_id: Filter by target node.
            limit: Max number of results (default 50).

        Returns:
            List of Task instances.
        """
        query = Task.query

        if module is not None:
            query = query.filter_by(module=module)
        if status is not None:
            query = query.filter_by(status=status)
        if node_id is not None:
            query = query.filter_by(target_node_id=node_id)

        return query.order_by(Task.created_at.desc()).limit(limit).all()

    @staticmethod
    def get_task_by_id(task_id):
        """Return a single task by its ID.

        Args:
            task_id: UUID string of the task.

        Returns:
            Task instance or None.
        """
        return db.session.get(Task, task_id)
