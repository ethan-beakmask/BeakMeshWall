"""add nodes.nginx_managed flag

Revision ID: b5c6d7e8
Revises: a1f2e3d4
Create Date: 2026-04-26 22:25:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b5c6d7e8'
down_revision = 'a1f2e3d4'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('nodes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('nginx_managed', sa.Boolean(), nullable=True))
    op.execute("UPDATE nodes SET nginx_managed = false WHERE nginx_managed IS NULL")
    with op.batch_alter_table('nodes', schema=None) as batch_op:
        batch_op.alter_column('nginx_managed', nullable=False)


def downgrade():
    with op.batch_alter_table('nodes', schema=None) as batch_op:
        batch_op.drop_column('nginx_managed')
