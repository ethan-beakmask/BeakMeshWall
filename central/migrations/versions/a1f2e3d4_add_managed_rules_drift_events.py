"""add managed_rules, drift_events tables; nodes drift policy fields

Revision ID: a1f2e3d4
Revises: c311838bd8a1
Create Date: 2026-04-26 21:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1f2e3d4'
down_revision = 'c311838bd8a1'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('nodes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('drift_policies', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('drift_check_interval', sa.Integer(), nullable=True))

    op.execute(
        "UPDATE nodes SET drift_policies = '{\"firewall\":\"notify\"}' "
        "WHERE drift_policies IS NULL"
    )

    op.create_table(
        'managed_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('subsystem', sa.String(length=32), nullable=False),
        sa.Column('fingerprint', sa.String(length=32), nullable=False),
        sa.Column('schema_rule', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('applied_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('node_id', 'subsystem', 'fingerprint', name='uq_managed_rule_node_fp'),
    )
    with op.batch_alter_table('managed_rules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_managed_rules_node_id'), ['node_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_managed_rules_subsystem'), ['subsystem'], unique=False)
        batch_op.create_index(batch_op.f('ix_managed_rules_fingerprint'), ['fingerprint'], unique=False)
        batch_op.create_index(batch_op.f('ix_managed_rules_status'), ['status'], unique=False)

    op.create_table(
        'drift_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('subsystem', sa.String(length=32), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('missing_in_actual', sa.Text(), nullable=True),
        sa.Column('extra_in_actual', sa.Text(), nullable=True),
        sa.Column('policy_applied', sa.String(length=16), nullable=False),
        sa.Column('notification_sent', sa.Boolean(), nullable=True),
        sa.Column('reconcile_task_ids', sa.Text(), nullable=True),
        sa.Column('backup_path', sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('drift_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_drift_events_node_id'), ['node_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_drift_events_detected_at'), ['detected_at'], unique=False)


def downgrade():
    with op.batch_alter_table('drift_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_drift_events_detected_at'))
        batch_op.drop_index(batch_op.f('ix_drift_events_node_id'))
    op.drop_table('drift_events')

    with op.batch_alter_table('managed_rules', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_managed_rules_status'))
        batch_op.drop_index(batch_op.f('ix_managed_rules_fingerprint'))
        batch_op.drop_index(batch_op.f('ix_managed_rules_subsystem'))
        batch_op.drop_index(batch_op.f('ix_managed_rules_node_id'))
    op.drop_table('managed_rules')

    with op.batch_alter_table('nodes', schema=None) as batch_op:
        batch_op.drop_column('drift_check_interval')
        batch_op.drop_column('drift_policies')
