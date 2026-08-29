from __future__ import annotations

from collections import defaultdict
from typing import Any

from ldap3 import BASE

from app.ldap import LDAPSearchService
from app.ldap.connection import LDAPConnectionManager


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first(value: Any) -> Any:
    values = _values(value)
    return values[0] if values else None


class LDAPDirectoryHealthService:
    WEIGHTS = {"critical": 20, "high": 10, "medium": 5, "low": 2}

    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def _issue(code: str, severity: str, message: str, *, dn: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"code": code, "severity": severity, "message": message, "dn": dn, "details": details or {}}

    @classmethod
    def analyze_entries(cls, users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        uid_numbers: dict[str, list[str]] = defaultdict(list)
        group_gid_numbers: dict[str, list[str]] = defaultdict(list)
        user_dns = {str(user.get("dn", "")).lower() for user in users if user.get("dn")}
        usernames = {str(_first(user.get("uid")) or "").lower() for user in users if _first(user.get("uid"))}

        for user in users:
            dn = str(user.get("dn") or "")
            classes = {str(value).lower() for value in _values(user.get("objectClass"))}
            uid_number = _first(user.get("uidNumber"))
            if uid_number not in {None, ""}:
                uid_numbers[str(uid_number)].append(dn)
            if "posixaccount" in classes:
                for attr in ("uidNumber", "gidNumber", "homeDirectory", "loginShell"):
                    if _first(user.get(attr)) in {None, ""}:
                        issues.append(cls._issue("missing_posix_user_attribute", "high", f"POSIX account is missing {attr}", dn=dn, details={"attribute": attr}))

        for value, dns in uid_numbers.items():
            if len(dns) > 1:
                issues.append(cls._issue("duplicate_uid_number", "critical", f"uidNumber {value} is used by multiple accounts", details={"value": value, "dns": dns}))

        for group in groups:
            dn = str(group.get("dn") or "")
            classes = {str(value).lower() for value in _values(group.get("objectClass"))}
            gid_number = _first(group.get("gidNumber"))
            if "posixgroup" in classes:
                if gid_number in {None, ""}:
                    issues.append(cls._issue("missing_group_gid", "high", "POSIX group is missing gidNumber", dn=dn))
                else:
                    group_gid_numbers[str(gid_number)].append(dn)
            for attr in ("member", "uniqueMember"):
                for member_dn in _values(group.get(attr)):
                    if str(member_dn).lower() not in user_dns:
                        issues.append(cls._issue("orphan_group_member_dn", "medium", f"Group references missing member DN via {attr}", dn=dn, details={"member": str(member_dn), "attribute": attr}))
            for member_uid in _values(group.get("memberUid")):
                if str(member_uid).lower() not in usernames:
                    issues.append(cls._issue("orphan_group_member_uid", "medium", "POSIX group references a missing memberUid", dn=dn, details={"memberUid": str(member_uid)}))

        for value, dns in group_gid_numbers.items():
            if len(dns) > 1:
                issues.append(cls._issue("duplicate_group_gid", "critical", f"gidNumber {value} is used by multiple groups", details={"value": value, "dns": dns}))
        return issues

    def scan(self, *, limit: int = 5000) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        checks: list[dict[str, Any]] = []
        base_dn = self.manager.settings.base_dn
        with self.manager.connection() as conn:
            readable = conn.search(base_dn, "(objectClass=*)", BASE, attributes=["objectClass"], size_limit=1)
            checks.append({"name": "base_dn_readable", "ok": bool(readable and conn.result.get("result") == 0), "detail": conn.result.get("description")})
            schema_ok = bool(conn.server.schema and conn.server.schema.object_classes)
            checks.append({"name": "schema_available", "ok": schema_ok, "detail": "Schema metadata available" if schema_ok else "Schema metadata unavailable"})
        if not checks[0]["ok"]:
            issues.append(self._issue("base_dn_unreadable", "critical", "Configured Base DN cannot be read", dn=base_dn))
        if not checks[1]["ok"]:
            issues.append(self._issue("schema_unavailable", "medium", "LDAP schema metadata is unavailable"))

        mapping = self.manager.settings.attribute_mapping or {}
        username_attr = mapping.get("username", "uid")
        users_base = self.manager.settings.users_base_dn or base_dn
        groups_base = self.manager.settings.groups_base_dn or base_dn
        search = LDAPSearchService(self.manager)
        users = search.search(
            base_dn=users_base,
            ldap_filter=f"(&(objectClass=person)({username_attr}=*))",
            attributes=["uid", username_attr, "uidNumber", "gidNumber", "homeDirectory", "loginShell", "objectClass"],
            size_limit=min(max(limit, 1), 5000),
        )
        for user in users:
            if "uid" not in user and username_attr in user:
                user["uid"] = user[username_attr]
        groups = search.search(
            base_dn=groups_base,
            ldap_filter="(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
            attributes=["cn", "gidNumber", "member", "uniqueMember", "memberUid", "objectClass"],
            size_limit=min(max(limit, 1), 5000),
        )
        issues.extend(self.analyze_entries(users, groups))
        counts = {severity: sum(1 for issue in issues if issue["severity"] == severity) for severity in self.WEIGHTS}
        score = max(0, 100 - sum(self.WEIGHTS[issue["severity"]] for issue in issues))
        status = "healthy" if score >= 90 else "warning" if score >= 70 else "critical"
        return {
            "status": status,
            "score": score,
            "summary": {"users": len(users), "groups": len(groups), "issues": len(issues), **counts},
            "checks": checks,
            "issues": sorted(issues, key=lambda item: (-(self.WEIGHTS[item["severity"]]), item["code"])),
        }
