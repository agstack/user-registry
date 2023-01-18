"""access_token and refresh_token added to the users table

Revision ID: 8d6a665ab523
Revises: 3e16cbf1dc97
Create Date: 2023-01-14 01:30:50.184182

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8d6a665ab523'
down_revision = '3e16cbf1dc97'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('access_token', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('refresh_token', sa.String(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('refresh_token')
        batch_op.drop_column('access_token')

    # ### end Alembic commands ###
