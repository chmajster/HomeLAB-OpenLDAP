from app.directory_health import LDAPDirectoryHealthService


def test_detects_duplicate_uid_and_missing_posix_attributes():
    users = [
        {"dn": "uid=a,dc=example,dc=org", "uid": ["a"], "uidNumber": ["1001"], "gidNumber": ["100"], "homeDirectory": ["/home/a"], "loginShell": ["/bin/bash"], "objectClass": ["person", "posixAccount"]},
        {"dn": "uid=b,dc=example,dc=org", "uid": ["b"], "uidNumber": ["1001"], "objectClass": ["person", "posixAccount"]},
    ]
    issues = LDAPDirectoryHealthService.analyze_entries(users, [])
    codes = [issue["code"] for issue in issues]
    assert "duplicate_uid_number" in codes
    assert codes.count("missing_posix_user_attribute") == 3


def test_detects_duplicate_group_gid_and_orphan_members():
    users = [{"dn": "uid=a,dc=example,dc=org", "uid": ["a"], "objectClass": ["person"]}]
    groups = [
        {"dn": "cn=g1,dc=example,dc=org", "gidNumber": ["200"], "memberUid": ["missing"], "objectClass": ["posixGroup"]},
        {"dn": "cn=g2,dc=example,dc=org", "gidNumber": ["200"], "member": ["uid=missing,dc=example,dc=org"], "objectClass": ["posixGroup", "groupOfNames"]},
    ]
    issues = LDAPDirectoryHealthService.analyze_entries(users, groups)
    codes = {issue["code"] for issue in issues}
    assert "duplicate_group_gid" in codes
    assert "orphan_group_member_uid" in codes
    assert "orphan_group_member_dn" in codes


def test_clean_entries_have_no_findings():
    users = [{"dn": "uid=a,dc=example,dc=org", "uid": ["a"], "uidNumber": ["1001"], "gidNumber": ["200"], "homeDirectory": ["/home/a"], "loginShell": ["/bin/bash"], "objectClass": ["person", "posixAccount"]}]
    groups = [{"dn": "cn=g1,dc=example,dc=org", "gidNumber": ["200"], "memberUid": ["a"], "objectClass": ["posixGroup"]}]
    assert LDAPDirectoryHealthService.analyze_entries(users, groups) == []
