"""Database-backed panel RBAC roles.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


DEFAULT_ROLES = [
    {
        "name": "Administrator",
        "description": "Full access to the panel and LDAP administration features.",
        "permissions": "*",
        "built_in": True,
        "enabled": True,
    },
    {
        "name": "Operator",
        "description": "Operational LDAP management without panel-wide administrator privileges.",
        "permissions": "audit.read,ldap.groups.read,ldap.groups.write,ldap.lifecycle.read,ldap.lifecycle.write,ldap.ou.read,ldap.ou.write,ldap.ppolicy.read,ldap.read,ldap.schema.read,ldap.ssh.read,ldap.ssh.write,ldap.sudo.read,ldap.sudo.write,ldap.users.read,ldap.users.write",
        "built_in": True,
        "enabled": True,
    },
    {
        "name": "Read Only",
        "description": "Read-only directory, security status and audit access.",
        "permissions": "audit.read,ldap.groups.read,ldap.lifecycle.read,ldap.ou.read,ldap.ppolicy.read,ldap.read,ldap.schema.read,ldap.ssh.read,ldap.sudo.read,ldap.users.read",
        "built_in": True,
        "enabled": True,
    },
]


def upgrade() -> None:
    op.create_table(
        "access_roles",
        sa.Column("name", sa.String(128), primary_key=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("permissions", sa.Text(), nullable=False, server_default=""),
        sa.Column("built_in", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    roles = sa.table(
        "access_roles",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("permissions", sa.Text),
        sa.column("built_in", sa.Boolean),
        sa.column("enabled", sa.Boolean),
    )
    op.bulk_insert(roles, DEFAULT_ROLES)
    with op.batch_alter_table("panel_users") as batch:
        batch.alter_column("role", existing_type=sa.String(32), type_=sa.String(128), existing_nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("panel_users") as batch:
        batch.alter_column("role", existing_type=sa.String(128), type_=sa.String(32), existing_nullable=False)
    op.drop_table("access_roles")
