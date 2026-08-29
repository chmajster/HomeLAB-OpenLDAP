from __future__ import annotations

from typing import Any

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

from app.advanced import encode_dn
from app.ldap import LDAPSearchService
from app.ldap.connection import LDAPConnectionManager


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first(value: Any) -> Any:
    values = _values(value)
    return values[0] if values else None


class LDAPBrowserService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager
        self.search = LDAPSearchService(manager)

    @staticmethod
    def _rdns(dn: str) -> list[str]:
        parsed = parse_dn(dn)
        rdns: list[str] = []
        current = ""
        for attr, value, separator in parsed:
            current += f"{attr}={value}"
            if separator == "+":
                current += "+"
            else:
                rdns.append(current)
                current = ""
        if current:
            rdns.append(current)
        return rdns

    @classmethod
    def breadcrumbs(cls, dn: str, base_dn: str) -> list[dict[str, str]]:
        dn_rdns = cls._rdns(dn)
        base_rdns = cls._rdns(base_dn)
        if len(dn_rdns) < len(base_rdns) or [x.lower() for x in dn_rdns[-len(base_rdns):]] != [x.lower() for x in base_rdns]:
            raise ValueError("DN must be inside configured Base DN")
        crumbs = [{"label": base_rdns[0], "dn": ",".join(base_rdns)}]
        extra = dn_rdns[: len(dn_rdns) - len(base_rdns)]
        suffix = list(base_rdns)
        for rdn in reversed(extra):
            suffix.insert(0, rdn)
            crumbs.append({"label": rdn, "dn": ",".join(suffix)})
        return crumbs

    @staticmethod
    def classify(entry: dict[str, Any]) -> tuple[str, str]:
        classes = {str(value).lower() for value in _values(entry.get("objectClass"))}
        if "organizationalunit" in classes:
            return "ou", str(_first(entry.get("ou")) or entry.get("dn"))
        if "person" in classes or "inetorgperson" in classes:
            return "user", str(_first(entry.get("uid")) or _first(entry.get("cn")) or entry.get("dn"))
        if classes & {"groupofnames", "groupofuniquenames", "posixgroup"}:
            return "group", str(_first(entry.get("cn")) or entry.get("dn"))
        return "entry", str(_first(entry.get("cn")) or _first(entry.get("ou")) or entry.get("dn"))

    def node(self, dn: str | None = None, *, q: str | None = None, limit: int = 500) -> dict[str, Any]:
        base_dn = self.manager.settings.base_dn
        target = dn or base_dn
        crumbs = self.breadcrumbs(target, base_dn)
        entry_rows = self.search.search(base_dn=target, ldap_filter="(objectClass=*)", scope="BASE", attributes=["*", "+"], size_limit=1)
        entry = entry_rows[0] if entry_rows else None
        safe = escape_filter_chars(q.strip()) if q and q.strip() else None
        child_filter = f"(|(cn=*{safe}*)(ou=*{safe}*)(uid=*{safe}*)(mail=*{safe}*))" if safe else "(objectClass=*)"
        children = self.search.search(
            base_dn=target,
            ldap_filter=child_filter,
            scope="LEVEL",
            attributes=["objectClass", "ou", "uid", "cn", "mail"],
            size_limit=min(max(limit, 1), 1000),
        )
        nodes = []
        for child in children:
            kind, label = self.classify(child)
            nodes.append({"dn": child["dn"], "kind": kind, "label": label, "editor_path": f"/directory/entry/{encode_dn(child['dn'])}"})
        nodes.sort(key=lambda item: (item["kind"], item["label"].lower(), item["dn"].lower()))
        parent_dn = crumbs[-2]["dn"] if len(crumbs) > 1 else None
        return {
            "dn": target,
            "base_dn": base_dn,
            "parent_dn": parent_dn,
            "breadcrumbs": crumbs,
            "entry": entry,
            "editor_path": f"/directory/entry/{encode_dn(target)}",
            "children": nodes,
            "child_count": len(nodes),
            "query": q or "",
            "limit": limit,
            "truncated": len(nodes) >= limit,
        }
