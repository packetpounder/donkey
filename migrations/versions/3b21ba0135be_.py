"""empty message

Revision ID: 3b21ba0135be
Revises: None
Create Date: 2014-11-22 17:02:51.023488

"""

# revision identifiers, used by Alembic.
revision = '3b21ba0135be'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('photos', sa.Column('vote_value', sa.Integer(), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('photos', 'vote_value')
    ### end Alembic commands ###