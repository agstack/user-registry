"""Table name updated, blocked user email.

Revision ID: a279d38a7749
Revises: 7a96bc60a027
Create Date: 2023-03-14 01:32:21.549051

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = 'a279d38a7749'
down_revision = '7a96bc60a027'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blocked_user_email',
    sa.Column('id', UUID(), nullable=False, server_default=sa.text('gen_random_uuid()')),
    sa.Column('email', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('blacklist')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('blacklist',
    sa.Column('id', UUID(), autoincrement=True, nullable=False),
    sa.Column('email', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='blacklist_pkey')
    )
    op.drop_table('blocked_user_email')
    # ### end Alembic commands ###
