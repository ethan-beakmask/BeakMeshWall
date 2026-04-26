"""add named_sets and named_set_members tables (Stage C)

Revision ID: c9d8e7f6
Revises: b5c6d7e8
Create Date: 2026-04-26 22:55:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c9d8e7f6'
down_revision = 'b5c6d7e8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'named_sets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=32), nullable=False),
        sa.Column('family', sa.String(length=8), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('node_id', 'name', name='uq_named_set_node_name'),
    )
    with op.batch_alter_table('named_sets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_named_sets_node_id'), ['node_id'], unique=False)

    op.create_table(
        'named_set_members',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('set_id', sa.Integer(), nullable=False),
        sa.Column('address', sa.String(length=45), nullable=False),
        sa.Column('added_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['set_id'], ['named_sets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('set_id', 'address', name='uq_named_set_member'),
    )
    with op.batch_alter_table('named_set_members', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_named_set_members_set_id'), ['set_id'], unique=False)


def downgrade():
    with op.batch_alter_table('named_set_members', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_named_set_members_set_id'))
    op.drop_table('named_set_members')
    with op.batch_alter_table('named_sets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_named_sets_node_id'))
    op.drop_table('named_sets')
