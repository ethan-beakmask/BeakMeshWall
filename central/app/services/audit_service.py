"""
Audit service: records security-relevant events to the audit_logs table.

All logging calls are wrapped in try/except to ensure audit failures
never break the calling operation.
"""

import logging

from ..extensions import db
from ..models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """Service class for audit log recording and querying."""

    @staticmethod
    def log(actor, action, resource_type=None, resource_id=None,
            detail=None, ip_address=None):
        """Record an audit event. Commits immediately.

        This method is safe to call in any context -- exceptions are
        caught and logged rather than propagated.

        Args:
            actor: Identity string (e.g. 'user:admin', 'api:key-name',
                   'agent:<uuid>', 'system').
            action: Action name (e.g. 'create_rule', 'login').
            resource_type: Type of affected resource (e.g. 'rule', 'node').
            resource_id: ID of the affected resource.
            detail: Optional dict with additional context.
            ip_address: Source IP of the request.

        Returns:
            The created AuditLog instance, or None on failure.
        """
        try:
            entry = AuditLog(
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id is not None else None,
                detail=detail,
                ip_address=ip_address,
            )
            db.session.add(entry)
            db.session.commit()
            return entry
        except Exception:
            logger.exception('Failed to write audit log entry: %s %s', action, actor)
            try:
                db.session.rollback()
            except Exception:
                pass
            return None

    @staticmethod
    def query(action=None, resource_type=None, actor=None,
              limit=100, offset=0):
        """Query audit log with optional filters.

        Args:
            action: Filter by action name.
            resource_type: Filter by resource type.
            actor: Filter by actor (partial match, case-insensitive).
            limit: Maximum number of entries to return.
            offset: Number of entries to skip.

        Returns:
            Tuple of (list of AuditLog instances, total count).
        """
        q = AuditLog.query.order_by(AuditLog.timestamp.desc())

        if action:
            q = q.filter_by(action=action)
        if resource_type:
            q = q.filter_by(resource_type=resource_type)
        if actor:
            q = q.filter(AuditLog.actor.ilike(f'%{actor}%'))

        total = q.count()
        entries = q.offset(offset).limit(limit).all()
        return entries, total
