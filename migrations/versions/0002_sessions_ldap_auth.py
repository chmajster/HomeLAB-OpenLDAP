"""Panel sessions and LDAP panel authentication metadata.

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("panel_users") as batch:
        batch.add_column(sa.Column("auth_source", sa.String(16), nullable=False, server_default="local"))
        batch.add_column(sa.Column("ldap_dn", sa.String(2048), nullable=True))
    op.create_table(
        "panel_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("panel_users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_panel_sessions_user_id", "panel_sessions", ["user_id"])
    op.create_index("ix_panel_sessions_token_hash", "panel_sessions", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_panel_sessions_token_hash", table_name="panel_sessions")
    op.drop_index("ix_panel_sessions_user_id", table_name="panel_sessions")
    op.drop_table("panel_sessions")
    with op.batch_alter_table("panel_users") as batch:
        batch.drop_column("ldap_dn")
        batch.drop_column("auth_source")
