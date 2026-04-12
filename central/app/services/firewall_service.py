"""
Firewall service: business logic for managing firewall rules and related tasks.
"""

from datetime import datetime, timezone, timedelta

from flask import request as flask_request

from ..extensions import db
from ..models.firewall_rule import FirewallRule
from ..models.node import Node
from .task_service import TaskService
from .audit_service import AuditService


def _get_request_ip():
    """Safely retrieve the remote IP from the current Flask request context."""
    try:
        return flask_request.remote_addr
    except RuntimeError:
        return None


class FirewallService:
    """Service class for firewall rule CRUD and task orchestration."""

    @staticmethod
    def create_block_rule(ip_address, node_id=None, source='manual',
                          source_detail=None, duration=None, comment=None,
                          created_by=None, direction='inbound', action='drop'):
        """Create a firewall block rule and corresponding dispatch task(s).

        Args:
            ip_address: IPv4 or IPv6 address to block.
            node_id: Target node UUID, or None for all approved nodes.
            source: Origin of the rule (manual, threat_feed, api).
            source_detail: Additional source context.
            duration: Block duration in seconds, or None for permanent.
            comment: Human-readable note.
            created_by: Identity string of the creator.
            direction: Traffic direction (inbound, outbound, both).
            action: Firewall action (drop, accept, reject).

        Returns:
            The created FirewallRule instance.
        """
        now = datetime.now(timezone.utc)
        expires_at = None
        if duration is not None:
            expires_at = now + timedelta(seconds=duration)

        rule = FirewallRule(
            node_id=node_id,
            rule_type='block',
            ip_address=ip_address,
            direction=direction,
            action=action,
            comment=comment,
            source=source,
            source_detail=source_detail,
            duration=duration,
            expires_at=expires_at,
            status='active',
            created_by=created_by,
        )
        db.session.add(rule)
        db.session.commit()

        # Create task(s) to apply the block on target node(s)
        task_params = {
            'ip': ip_address,
            'direction': direction,
            'action': action,
            'rule_id': rule.id,
        }
        if comment:
            task_params['comment'] = comment

        TaskService.create_task(
            module='firewall',
            action='block_ip',
            params=task_params,
            target_node_id=node_id,
            created_by=created_by,
        )

        # Audit: rule creation
        AuditService.log(
            actor=created_by or 'system',
            action='create_rule',
            resource_type='rule',
            resource_id=rule.id,
            detail={
                'ip_address': ip_address,
                'source': source,
                'direction': direction,
                'fw_action': action,
                'node_id': node_id,
            },
            ip_address=_get_request_ip(),
        )

        return rule

    @staticmethod
    def remove_block_rule(rule_id=None, ip_address=None, node_id=None,
                          created_by=None):
        """Remove a block rule and create unblock task(s).

        Either rule_id or ip_address must be provided.

        Args:
            rule_id: Specific rule ID to remove.
            ip_address: IP address to unblock (may match multiple rules).
            node_id: Scope removal to a specific node.
            created_by: Identity string of the actor.

        Returns:
            List of removed FirewallRule instances.
        """
        query = FirewallRule.query.filter_by(status='active')

        if rule_id is not None:
            query = query.filter_by(id=rule_id)
        elif ip_address is not None:
            query = query.filter_by(ip_address=ip_address)
            if node_id is not None:
                query = query.filter_by(node_id=node_id)
        else:
            return []

        rules = query.all()
        removed = []

        for rule in rules:
            rule.status = 'removed'
            removed.append(rule)

            task_params = {
                'ip': rule.ip_address,
                'rule_id': rule.id,
            }

            TaskService.create_task(
                module='firewall',
                action='unblock_ip',
                params=task_params,
                target_node_id=rule.node_id,
                created_by=created_by,
            )

            # Audit: rule deletion
            AuditService.log(
                actor=created_by or 'system',
                action='delete_rule',
                resource_type='rule',
                resource_id=rule.id,
                detail={
                    'ip_address': rule.ip_address,
                    'node_id': rule.node_id,
                },
                ip_address=_get_request_ip(),
            )

        if removed:
            db.session.commit()

        return removed

    @staticmethod
    def get_active_rules(node_id=None, rule_type=None):
        """Get active firewall rules with optional filters.

        Args:
            node_id: Filter by target node.
            rule_type: Filter by rule type (block, allow, custom).

        Returns:
            List of FirewallRule instances.
        """
        query = FirewallRule.query.filter_by(status='active')

        if node_id is not None:
            query = query.filter_by(node_id=node_id)
        if rule_type is not None:
            query = query.filter_by(rule_type=rule_type)

        return query.order_by(FirewallRule.created_at.desc()).all()

    @staticmethod
    def get_rule_by_id(rule_id):
        """Return a single rule by its ID.

        Args:
            rule_id: Integer ID of the rule.

        Returns:
            FirewallRule instance or None.
        """
        return db.session.get(FirewallRule, rule_id)

    @staticmethod
    def expire_stale_rules():
        """Find expired rules and create unblock tasks for them.

        Should be called periodically (e.g. from a scheduled job or
        before returning active rules).

        Returns:
            List of FirewallRule instances that were expired.
        """
        now = datetime.now(timezone.utc)

        # Find active rules that have a non-null expires_at in the past
        expired_rules = FirewallRule.query.filter(
            FirewallRule.status == 'active',
            FirewallRule.expires_at.isnot(None),
            FirewallRule.expires_at <= now,
        ).all()

        for rule in expired_rules:
            rule.status = 'expired'

            task_params = {
                'ip': rule.ip_address,
                'rule_id': rule.id,
            }

            TaskService.create_task(
                module='firewall',
                action='unblock_ip',
                params=task_params,
                target_node_id=rule.node_id,
                created_by='system:expiry',
            )

        if expired_rules:
            db.session.commit()

        return expired_rules
