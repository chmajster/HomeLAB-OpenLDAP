import os
import uuid

import pytest

from app.advanced import LDAPMembershipService
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPOUService, LDAPUserService
from app.ldap.connection import LDAPSettings

LDAP_URL = os.getenv("LDAP_INTEGRATION_URL")
pytestmark = pytest.mark.skipif(not LDAP_URL, reason="LDAP integration service is not configured")


def test_real_openldap_user_group_ou_and_membership_roundtrip():
    suffix = uuid.uuid4().hex[:8]
    base_dn = os.getenv("LDAP_INTEGRATION_BASE_DN", "dc=example,dc=org")
    bind_dn = os.getenv("LDAP_INTEGRATION_BIND_DN", f"cn=admin,{base_dn}")
    bind_password = os.getenv("LDAP_INTEGRATION_BIND_PASSWORD", "admin")
    manager = LDAPConnectionManager(
        LDAPSettings(
            url=LDAP_URL or "ldap://127.0.0.1:389",
            base_dn=base_dn,
            bind_dn=bind_dn,
            bind_password=bind_password,
            verify_tls=False,
        )
    )
    ou_name = f"integration-{suffix}"
    username = f"user-{suffix}"
    group_name = f"group-{suffix}"
    ou_dn = f"ou={ou_name},{base_dn}"

    try:
        health = manager.test()
        assert all(step["ok"] for step in health if step["name"] != "write_permissions")
        LDAPOUService(manager).create(ou_name)
        manager.settings.users_base_dn = ou_dn
        manager.settings.groups_base_dn = ou_dn

        users = LDAPUserService(manager, 30000, 39999)
        groups = LDAPGroupService(manager, 30000, 39999)
        created_user = users.create(
            {
                "username": username,
                "first_name": "Integration",
                "last_name": "User",
                "password": "Integration-Password-123!",
                "gid_number": 30000,
                "organizational_unit": ou_dn,
            }
        )
        created_group = groups.create({"name": group_name, "group_type": "groupOfNames"})
        LDAPMembershipService(manager).change(created_group["dn"], created_user["dn"], True)

        found_user = users.get(username)
        assert found_user is not None
        assert found_user["dn"] == created_user["dn"]
        memberships = LDAPMembershipService(manager).groups_for_user(created_user["dn"], username)
        assert any(group["dn"] == created_group["dn"] for group in memberships)

        users.disable(username)
        users.enable(username)
        users.reset_password(username, "Integration-Password-Changed-123!")
    finally:
        try:
            LDAPGroupService(manager, 30000, 39999).delete(group_name)
        except Exception:
            pass
        try:
            LDAPUserService(manager, 30000, 39999).delete(username)
        except Exception:
            pass
        try:
            LDAPOUService(manager).delete(ou_dn)
        except Exception:
            pass
        manager.close()
