"""add email to User model

Revision ID: 435e586d8b15
Revises: ed245404c7c5
Create Date: 2019-03-11 15:56:19.600674

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '435e586d8b15'
down_revision = 'ed245404c7c5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('email', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_column('users', 'email')
    # ### end Alembic commands ###
