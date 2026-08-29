from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import AccessRole, PanelUser
from app.rbac import allows, encode_permissions, ensure_default_roles, role_permissions, user_permissions
from app.rbac_middleware import _required_permission


def make_db() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_default_roles_are_seeded_and_preserve_legacy_permissions():
    with make_db() as db:
        ensure_default_roles(db)
        assert role_permissions(db, "Administrator") == {"*"}
        assert "ldap.users.write" in role_permissions(db, "Operator")
        assert "ldap.users.write" not in role_permissions(db, "Read Only")
        assert "ldap.users.read" in role_permissions(db, "Read Only")


def test_custom_role_permissions_are_resolved_from_database():
    with make_db() as db:
        ensure_default_roles(db)
        db.add(AccessRole(name="Helpdesk", description="Password and user operations", permissions=encode_permissions({"ldap.users.read", "ldap.users.write"}), enabled=True))
        user = PanelUser(username="helpdesk01", password_hash="not-used", role="Helpdesk")
        db.add(user)
        db.commit()
        permissions = user_permissions(db, user)
        assert permissions == {"ldap.users.read", "ldap.users.write"}
        assert allows(permissions, "ldap.users.write")
        assert not allows(permissions, "ldap.groups.write")


def test_disabled_custom_role_has_no_effective_permissions():
    with make_db() as db:
        db.add(AccessRole(name="Disabled Role", permissions="ldap.read", enabled=False))
        user = PanelUser(username="disabled-role-user", password_hash="not-used", role="Disabled Role")
        db.add(user)
        db.commit()
        assert user_permissions(db, user) == set()


def test_legacy_web_mutations_are_mapped_to_granular_permissions():
    assert _required_permission("/users/chris/command-access") == "ldap.sudo.write"
    assert _required_permission("/users/chris/ssh-keys/add") == "ldap.ssh.write"
    assert _required_permission("/users/chris/lifecycle") == "ldap.lifecycle.write"
    assert _required_permission("/locked-accounts/unlock") == "ldap.lifecycle.write"
    assert _required_permission("/ldif/import") == "ldap.users.write"
