"""message

Revision ID: 264ab8625e29
Revises: 
Create Date: 2025-08-09 13:23:22.463482

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '264ab8625e29'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user',
        sa.Column('id', sa.INTEGER(), nullable=False),
        sa.Column('username', sa.VARCHAR(length=80), nullable=False),
        sa.Column('email', sa.VARCHAR(length=120), nullable=False),
        sa.Column('password', sa.VARCHAR(length=200), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )

def downgrade():
    op.drop_table('user')
