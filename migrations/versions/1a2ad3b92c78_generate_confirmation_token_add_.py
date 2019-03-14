"""generate confirmation token, add confirmed field

Revision ID: 1a2ad3b92c78
Revises: 435e586d8b15
Create Date: 2019-03-11 16:45:58.679322

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a2ad3b92c78'
down_revision = '435e586d8b15'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    # ### end Alembic commands ###