from __future__ import annotations

import secrets
from typing import Any

from ldap3 import BASE, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn, parse_dn

from app.ldap.connection import LDAPConnectionManager


class LDAPCapabilityProbeService:
    """Verify LDAP permissions without treating a successful bind as proof of write access."""

    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def _result(conn) -> dict[str, Any]:
        return {
            "code": conn.result.get("result"),
            "description": conn.result.get("description"),
            "message": conn.result.get("message"),
        }

    def inspect(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        with self.manager.connection() as conn:
            checks.append({"capability": "bind", "allowed": bool(conn.bound), "detail": "Service account bind is active"})

            search_ok = conn.search(self.manager.settings.base_dn, "(objectClass=*)", BASE, attributes=["objectClass"], size_limit=1)
            checks.append(
                {
                    "capability": "search_base",
                    "allowed": bool(search_ok and conn.result.get("result") == 0),
                    "result": self._result(conn),
                }
            )

            conn.compare(self.manager.settings.base_dn, "objectClass", "top")
            compare_code = conn.result.get("result")
            checks.append(
                {
                    "capability": "compare",
                    "allowed": compare_code in {5, 6},
                    "result": self._result(conn),
                }
            )

            schema_ok = bool(conn.server.schema and conn.server.schema.object_classes)
            checks.append({"capability": "read_schema", "allowed": schema_ok, "detail": "Schema metadata available" if schema_ok else "Schema metadata unavailable"})

            config_ok = conn.search("cn=config", "(objectClass=*)", BASE, attributes=["1.1"], size_limit=1)
            config_code = conn.result.get("result")
            checks.append(
                {
                    "capability": "read_cn_config",
                    "allowed": bool(config_ok and config_code == 0),
                    "result": self._result(conn),
                }
            )

        return {
            "bind_dn": self.manager.settings.bind_dn,
            "base_dn": self.manager.settings.base_dn,
            "checks": checks,
            "write_probe_performed": False,
            "write_permissions": "unknown",
            "message": "Write access is not inferred from bind. Run the explicit write probe to verify add/modify/delete rights.",
        }

    def write_probe(self, probe_base_dn: str | None = None) -> dict[str, Any]:
        base_dn = probe_base_dn or self.manager.settings.users_base_dn or self.manager.settings.base_dn
        parse_dn(base_dn)
        probe_cn = f"homelab-permission-probe-{secrets.token_hex(8)}"
        probe_dn = f"cn={escape_rdn(probe_cn)},{base_dn}"
        steps: list[dict[str, Any]] = []
        created = False
        cleanup_ok: bool | None = None

        with self.manager.connection() as conn:
            try:
                add_ok = conn.add(
                    probe_dn,
                    object_class=["top", "organizationalRole"],
                    attributes={"cn": probe_cn, "description": "HomeLAB OpenLDAP permission probe"},
                )
                created = bool(add_ok)
                steps.append({"capability": "add", "allowed": bool(add_ok), "result": self._result(conn)})
                if not add_ok:
                    return self._probe_result(base_dn, probe_dn, steps, cleanup_ok)

                modify_ok = conn.modify(probe_dn, {"description": [(MODIFY_REPLACE, ["HomeLAB OpenLDAP permission probe modified"])]})
                steps.append({"capability": "modify", "allowed": bool(modify_ok), "result": self._result(conn)})

                delete_ok = conn.delete(probe_dn)
                cleanup_ok = bool(delete_ok)
                created = not delete_ok
                steps.append({"capability": "delete", "allowed": bool(delete_ok), "result": self._result(conn)})
            finally:
                if created:
                    cleanup_ok = bool(conn.delete(probe_dn))
                    steps.append({"capability": "cleanup", "allowed": cleanup_ok, "result": self._result(conn)})

        return self._probe_result(base_dn, probe_dn, steps, cleanup_ok)

    @staticmethod
    def _probe_result(base_dn: str, probe_dn: str, steps: list[dict[str, Any]], cleanup_ok: bool | None) -> dict[str, Any]:
        permission_steps = [step for step in steps if step["capability"] in {"add", "modify", "delete"}]
        all_allowed = len(permission_steps) == 3 and all(step["allowed"] for step in permission_steps)
        return {
            "probe_base_dn": base_dn,
            "probe_dn": probe_dn,
            "write_probe_performed": True,
            "write_permissions": "allowed" if all_allowed else "partial_or_denied",
            "steps": steps,
            "cleanup_ok": cleanup_ok,
        }
