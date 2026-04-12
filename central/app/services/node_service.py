"""
Node service: business logic for node inventory queries.
"""

from ..models.node import Node


class NodeService:
    """Service class for node-related operations."""

    @staticmethod
    def get_all_nodes():
        """Return all nodes with computed online/offline status.

        Returns:
            List of dicts with node attributes and 'is_online' flag.
        """
        nodes = Node.query.order_by(Node.hostname).all()
        result = []
        for node in nodes:
            result.append({
                'id': node.id,
                'hostname': node.hostname,
                'ip_address': node.ip_address,
                'os_info': node.os_info,
                'agent_version': node.agent_version,
                'status': node.status,
                'is_online': node.is_online,
                'last_heartbeat_at': (
                    node.last_heartbeat_at.isoformat()
                    if node.last_heartbeat_at
                    else None
                ),
                'created_at': (
                    node.created_at.isoformat()
                    if node.created_at
                    else None
                ),
            })
        return result

    @staticmethod
    def get_node_by_id(node_id):
        """Return a single node by its ID.

        Args:
            node_id: UUID string of the node.

        Returns:
            Node instance or None.
        """
        from ..extensions import db
        return db.session.get(Node, node_id)

    @staticmethod
    def get_node_stats():
        """Return aggregate node statistics.

        Returns:
            Dict with keys: total, online, offline.
        """
        nodes = Node.query.all()
        total = len(nodes)
        online = sum(1 for n in nodes if n.is_online)
        return {
            'total': total,
            'online': online,
            'offline': total - online,
        }
