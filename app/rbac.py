from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AccessRole, PanelUser

PERMISSION_CATALOG = {
    "*": "Full application administration",
    "ldap.read": "Read generic LDAP directory data",
    "ldap.users.read": "Read LDAP users",
    "ldap.users.write": "Create and modify LDAP users",
    "ldap.groups.read": "Read LDAP groups",
    "ldap.groups.write": "Create and modify LDAP groups",
    "ldap.ou.read": "Read organizational units",
    "ldap.ou.write": "Create, move and delete organizational units",
    "ldap.schema.read": "Read LDAP schema",
    "ldap.sudo.read": "Read sudoRole entries",
    "ldap.sudo.write": "Manage sudoRole entries",
    "ldap.ssh.read": "Read LDAP SSH keys",
    "ldap.ssh.write": "Manage LDAP SSH keys",
    "ldap.lifecycle.read": "Read account lifecycle state",
    "ldap.lifecycle.write": "Manage account lifecycle state",
    "ldap.ppolicy.read": "Read password policies",
    "ldap.ppolicy.write": "Manage password policies",
    "audit.read": "Read audit log",
    "panel.roles.manage": "Manage custom panel roles",
}

DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "Administrator": {"*"},
    "Operator": {
        "ldap.read",
        "ldap.users.read",
        "ldap.users.write",
        "ldap.groups.read",
        "ldap.groups.write",
        "ldap.ou.read",
        "ldap.ou.write",
        "ldap.schema.read",
        "ldap.sudo.read",
        "ldap.sudo.write",
        "ldap.ssh.read",
        "ldap.ssh.write",
        "ldap.lifecycle.read",
        "ldap.lifecycle.write",
        "ldap.ppolicy.read",
        "audit.read",
    },
    "Read Only": {
        "ldap.read",
        "ldap.users.read",
        "ldap.groups.read",
        "ldap.ou.read",
        "ldap.schema.read",
        "ldap.sudo.read",
        "ldap.ssh.read",
        "ldap.lifecycle.read",
        "ldap.ppolicy.read",
        "audit.read",
    },
}

DEFAULT_ROLE_DESCRIPTIONS = {
    "Administrator": "Full access to the panel and LDAP administration features.",
    "Operator": "Operational LDAP management without panel-wide administrator privileges.",
    "Read Only": "Read-only directory, security status and audit access.",
}


def normalize_permissions(values: Iterable[str]) -> set[str]:
    permissions = {value.strip() for value in values if value and value.strip()}
    unknown = permissions - set(PERMISSION_CATALOG)
    if unknown:
        raise ValueError(f"Unknown permissions: {', '.join(sorted(unknown))}")
    if "*" in permissions:
        return {"*"}
    return permissions


def encode_permissions(values: Iterable[str]) -> str:
    return ",".join(sorted(normalize_permissions(values)))


def decode_permissions(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def ensure_default_roles(db: Session) -> None:
    changed = False
    for name, permissions in DEFAULT_ROLE_PERMISSIONS.items():
        role = db.get(AccessRole, name)
        if role is None:
            db.add(
                AccessRole(
                    name=name,
                    description=DEFAULT_ROLE_DESCRIPTIONS[name],
                    permissions=encode_permissions(permissions),
                    built_in=True,
                    enabled=True,
                )
            )
            changed = True
            continue
        if not role.built_in:
            role.built_in = True
            changed = True
    if changed:
        db.commit()


def get_role(db: Session, name: str) -> AccessRole | None:
    return db.get(AccessRole, name)


def list_roles(db: Session, *, enabled_only: bool = False) -> list[AccessRole]:
    query = select(AccessRole)
    if enabled_only:
        query = query.where(AccessRole.enabled.is_(True))
    return list(db.scalars(query.order_by(AccessRole.name.asc())).all())


def role_permissions(db: Session, role_name: str) -> set[str]:
    role = db.get(AccessRole, role_name)
    if role and role.enabled:
        return decode_permissions(role.permissions)
    return set(DEFAULT_ROLE_PERMISSIONS.get(role_name, set()))


def user_permissions(db: Session, user: PanelUser) -> set[str]:
    return role_permissions(db, user.role)


def allows(permissions: set[str], permission: str) -> bool:
    return "*" in permissions or permission in permissions or (
        permission.startswith("ldap.") and permission.endswith(".read") and "ldap.read" in permissions
    )


def user_allows(db: Session, user: PanelUser, permission: str) -> bool:
    return allows(user_permissions(db, user), permission)


def attach_effective_permissions(db: Session, user: PanelUser) -> PanelUser:
    user.effective_permissions = user_permissions(db, user)
    return user
