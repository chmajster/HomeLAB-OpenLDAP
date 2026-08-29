from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from app.ldap import LDAPSearchService
from app.ldap.connection import LDAPConnectionManager


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


class LDAPLifecycleManagerService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def classify(entry: dict[str, Any], *, today: date | None = None) -> dict[str, Any]:
        today = today or date.today()
        locked = bool(_first(entry.get("pwdAccountLockedTime")))
        reset_required = str(_first(entry.get("pwdReset")) or "FALSE").upper() == "TRUE"
        raw_expire = _first(entry.get("shadowExpire"))
        expires_on: str | None = None
        expired = False
        expires_soon = False
        if raw_expire not in {None, "", "-1"}:
            try:
                expiry = date(1970, 1, 1) + timedelta(days=int(raw_expire))
                expires_on = expiry.isoformat()
                expired = expiry < today
                expires_soon = not expired and expiry <= today + timedelta(days=30)
            except (TypeError, ValueError, OverflowError):
                pass
        state = "locked" if locked else "expired" if expired else "expiring" if expires_soon else "active"
        return {
            **entry,
            "state": state,
            "locked": locked,
            "expired": expired,
            "expires_soon": expires_soon,
            "expires_on": expires_on,
            "password_reset_required": reset_required,
        }

    def report(self, *, state: str | None = None, search: str | None = None, limit: int = 1000) -> dict[str, Any]:
        username_attr = (self.manager.settings.attribute_mapping or {}).get("username", "uid")
        display_attr = (self.manager.settings.attribute_mapping or {}).get("display_name", "displayName")
        email_attr = (self.manager.settings.attribute_mapping or {}).get("email", "mail")
        rows = LDAPSearchService(self.manager).search(
            base_dn=self.manager.settings.users_base_dn or self.manager.settings.base_dn,
            ldap_filter=f"(&(objectClass=person)({username_attr}=*))",
            attributes=[username_attr, display_attr, email_attr, "pwdAccountLockedTime", "shadowExpire", "pwdReset"],
            size_limit=min(max(limit, 1), 5000),
        )
        items = []
        needle = (search or "").strip().lower()
        for row in rows:
            normalized = {
                "dn": row.get("dn"),
                "username": _first(row.get(username_attr)),
                "display_name": _first(row.get(display_attr)),
                "email": _first(row.get(email_attr)),
                "pwdAccountLockedTime": row.get("pwdAccountLockedTime"),
                "shadowExpire": row.get("shadowExpire"),
                "pwdReset": row.get("pwdReset"),
            }
            item = self.classify(normalized)
            if state and state != "all" and item["state"] != state:
                continue
            if needle and needle not in " ".join(str(item.get(key) or "") for key in ("username", "display_name", "email", "dn")).lower():
                continue
            items.append(item)
        summary = {name: sum(1 for item in items if item["state"] == name) for name in ("active", "expiring", "expired", "locked")}
        summary["password_reset_required"] = sum(1 for item in items if item["password_reset_required"])
        summary["total"] = len(items)
        return {"summary": summary, "items": items}
