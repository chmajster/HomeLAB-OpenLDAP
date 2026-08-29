from contextlib import contextmanager
from types import SimpleNamespace

from app.ldap.capabilities import LDAPCapabilityProbeService


class FakeConnection:
    def __init__(self):
        self.bound = True
        self.result = {"result": 0, "description": "success", "message": ""}
        self.server = SimpleNamespace(schema=SimpleNamespace(object_classes={"top": object()}))

    def search(self, *_args, **_kwargs):
        self.result = {"result": 0, "description": "success", "message": ""}
        return True

    def compare(self, *_args, **_kwargs):
        self.result = {"result": 6, "description": "compareTrue", "message": ""}
        return True

    def add(self, *_args, **_kwargs):
        self.result = {"result": 0, "description": "success", "message": ""}
        return True

    def modify(self, *_args, **_kwargs):
        self.result = {"result": 0, "description": "success", "message": ""}
        return True

    def delete(self, *_args, **_kwargs):
        self.result = {"result": 0, "description": "success", "message": ""}
        return True


class FakeManager:
    def __init__(self):
        self.settings = SimpleNamespace(
            bind_dn="cn=admin,dc=example,dc=org",
            base_dn="dc=example,dc=org",
            users_base_dn="ou=People,dc=example,dc=org",
        )
        self.conn = FakeConnection()

    @contextmanager
    def connection(self):
        yield self.conn


def test_inspect_does_not_infer_write_access():
    result = LDAPCapabilityProbeService(FakeManager()).inspect()
    assert result["write_permissions"] == "unknown"
    assert result["write_probe_performed"] is False
    assert all(check["allowed"] for check in result["checks"])


def test_write_probe_verifies_add_modify_delete_and_cleanup():
    result = LDAPCapabilityProbeService(FakeManager()).write_probe()
    assert result["write_permissions"] == "allowed"
    assert result["cleanup_ok"] is True
    assert [step["capability"] for step in result["steps"]] == ["add", "modify", "delete"]
    assert all(step["allowed"] for step in result["steps"])
