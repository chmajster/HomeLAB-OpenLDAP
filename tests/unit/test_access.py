import base64

import pytest

from app.ldap.access import LDAPCommandAccessService, LDAPConfigService, LDAPSSHKeyService


def test_command_access_accepts_absolute_commands_and_all():
    result = LDAPCommandAccessService._validate_commands([
        "/usr/bin/systemctl restart nginx",
        "!/usr/bin/systemctl stop nginx",
        "ALL",
    ])
    assert result == ["/usr/bin/systemctl restart nginx", "!/usr/bin/systemctl stop nginx", "ALL"]


def test_command_access_rejects_relative_command():
    with pytest.raises(ValueError):
        LDAPCommandAccessService._validate_commands(["systemctl restart nginx"])


def test_acl_normalization_adds_order_prefixes():
    rules = LDAPConfigService.normalize_acl([
        "to attrs=userPassword by self write by anonymous auth by * none",
        "to * by users read by * none",
    ])
    assert rules[0].startswith("{0}to ")
    assert rules[1].startswith("{1}to ")


def test_acl_normalization_rejects_non_acl_input():
    with pytest.raises(ValueError):
        LDAPConfigService.normalize_acl(["by * manage"])


def test_syncrepl_builder_and_redaction():
    value = LDAPConfigService.build_syncrepl(
        rid="001",
        provider="ldaps://ldap01.example.org:636",
        searchbase="dc=example,dc=org",
        binddn="cn=replicator,dc=example,dc=org",
        bindcredentials="super-secret",
        tls_reqcert="demand",
    )
    assert "rid=001" in value
    assert 'credentials="super-secret"' in value
    redacted = LDAPConfigService.redact_syncrepl(value)
    assert "super-secret" not in redacted
    assert "credentials=***" in redacted


def test_syncrepl_rejects_invalid_rid():
    with pytest.raises(ValueError):
        LDAPConfigService.build_syncrepl(
            rid="1",
            provider="ldap://ldap01.example.org",
            searchbase="dc=example,dc=org",
            binddn="cn=replicator,dc=example,dc=org",
            bindcredentials="secret",
        )


def test_ssh_key_fingerprint():
    payload = base64.b64encode(b"unit-test-public-key").decode()
    key = f"ssh-ed25519 {payload} unit@test"
    fingerprint = LDAPSSHKeyService.fingerprint(key)
    assert fingerprint.startswith("SHA256:")
    assert LDAPSSHKeyService.validate(key) == key
