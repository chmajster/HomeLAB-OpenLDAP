"""Initial application database.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("panel_users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("username", sa.String(128), nullable=False), sa.Column("password_hash", sa.String(512), nullable=False), sa.Column("role", sa.String(32), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("theme", sa.String(16), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_login_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("username"))
    op.create_index("ix_panel_users_username", "panel_users", ["username"], unique=True)
    op.create_table("ldap_servers", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(128), nullable=False), sa.Column("url", sa.String(512), nullable=False), sa.Column("base_dn", sa.String(1024), nullable=False), sa.Column("bind_dn", sa.String(1024), nullable=False), sa.Column("encrypted_bind_password", sa.Text(), nullable=False), sa.Column("users_base_dn", sa.String(1024)), sa.Column("groups_base_dn", sa.String(1024)), sa.Column("starttls", sa.Boolean(), nullable=False), sa.Column("verify_tls", sa.Boolean(), nullable=False), sa.Column("ca_cert", sa.Text()), sa.Column("connect_timeout", sa.Integer(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("audit_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("operation_id", sa.String(64), nullable=False), sa.Column("request_id", sa.String(128), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("panel_user", sa.String(128), nullable=False), sa.Column("source_ip", sa.String(64)), sa.Column("operation", sa.String(64), nullable=False), sa.Column("dn", sa.String(2048)), sa.Column("attribute", sa.String(512)), sa.Column("old_value", sa.Text()), sa.Column("new_value", sa.Text()), sa.Column("status", sa.String(32), nullable=False), sa.Column("message", sa.Text()), sa.UniqueConstraint("operation_id"))
    op.create_index("ix_audit_logs_operation_id", "audit_logs", ["operation_id"], unique=True)
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_table("api_tokens", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(128), nullable=False), sa.Column("token_prefix", sa.String(16), nullable=False), sa.Column("token_hash", sa.String(128), nullable=False), sa.Column("permissions", sa.Text(), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_used_at", sa.DateTime(timezone=True)), sa.Column("expires_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("token_hash"))
    op.create_index("ix_api_tokens_token_prefix", "api_tokens", ["token_prefix"])
    op.create_table("app_settings", sa.Column("key", sa.String(128), primary_key=True), sa.Column("value", sa.Text(), nullable=False), sa.Column("encrypted", sa.Boolean(), nullable=False))


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_index("ix_api_tokens_token_prefix", table_name="api_tokens")
    op.drop_table("api_tokens")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_request_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_operation_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("ldap_servers")
    op.drop_index("ix_panel_users_username", table_name="panel_users")
    op.drop_table("panel_users")
