from __future__ import annotations

import base64
import hashlib
import os
import secrets
import string
from typing import Any

from ldap3 import BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from app.ldap.connection import LDAPConnectionManager, LDAPOperationError


SCOPES = {"BASE": BASE, "LEVEL": LEVEL, "SUBTREE": SUBTREE}


def _entry_to_dict(entry: Any) -> dict[str, Any]:
    result = {"dn": entry.entry_dn}
    result.update(entry.entry_attributes_as_dict)
    return result


def _ensure_success(conn: Any, operation: str) -> None:
    if conn.result.get("result", 0) != 0:
        raise LDAPOperationError(f"LDAP {operation} failed: {conn.result.get('description')}", result=conn.result)


class LDAPPasswordService:
    @staticmethod
    def hash_ssha(password: str) -> str:
        salt = os.urandom(8)
        digest = hashlib.sha1(password.encode() + salt).digest()  # noqa: S324 - OpenLDAP SSHA compatibility
        return "{SSHA}" + base64.b64encode(digest + salt).decode()

    @staticmethod
    def generate(length: int = 24, uppercase: bool = True, lowercase: bool = True,
                 numbers: bool = True, special: bool = True) -> str:
        if not 12 <= length <= 256:
            raise ValueError("Password length must be between 12 and 256")
        pools = []
        if uppercase:
            pools.append(string.ascii_uppercase)
        if lowercase:
            pools.append(string.ascii_lowercase)
        if numbers:
            pools.append(string.digits)
        if special:
            pools.append("!@#$%^&*()-_=+[]{}:,.?")
        if not pools:
            raise ValueError("At least one character class must be enabled")
        password = [secrets.choice(pool) for pool in pools]
        alphabet = "".join(pools)
        password.extend(secrets.choice(alphabet) for _ in range(length - len(password)))
        secrets.SystemRandom().shuffle(password)
        return "".join(password)


class LDAPSearchService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def search(self, *, base_dn: str | None = None, ldap_filter: str = "(objectClass=*)",
               scope: str = "SUBTREE", attributes: list[str] | None = None,
               size_limit: int = 100, time_limit: int = 10) -> list[dict[str, Any]]:
        if scope not in SCOPES:
            raise ValueError("Invalid LDAP search scope")
        target = base_dn or self.manager.settings.base_dn
        with self.manager.connection() as conn:
            conn.search(
                target,
                ldap_filter,
                search_scope=SCOPES[scope],
                attributes=attributes or ["*"],
                size_limit=size_limit,
                time_limit=time_limit,
            )
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(entry) for entry in conn.entries]


class LDAPUserService:
    DEFAULT_ATTRIBUTES = ["uid", "cn", "displayName", "givenName", "sn", "mail", "uidNumber", "gidNumber", "homeDirectory", "loginShell", "pwdAccountLockedTime"]

    def __init__(self, manager: LDAPConnectionManager, uid_min: int = 10000, uid_max: int = 60000):
        self.manager = manager
        self.uid_min = uid_min
        self.uid_max = uid_max

    @property
    def base_dn(self) -> str:
        return self.manager.settings.users_base_dn or self.manager.settings.base_dn

    def list(self, *, search: str | None = None, page_size: int = 50, cookie: bytes | None = None) -> dict[str, Any]:
        safe = escape_filter_chars(search) if search else None
        ldap_filter = f"(&(objectClass=person)(|(uid=*{safe}*)(cn=*{safe}*)(mail=*{safe}*)))" if safe else "(&(objectClass=person)(uid=*))"
        with self.manager.connection() as conn:
            conn.search(self.base_dn, ldap_filter, SUBTREE, attributes=self.DEFAULT_ATTRIBUTES,
                        paged_size=min(max(page_size, 1), 500), paged_cookie=cookie)
            _ensure_success(conn, "SEARCH")
            controls = conn.result.get("controls", {})
            page_control = controls.get("1.2.840.113556.1.4.319", {}).get("value", {})
            next_cookie = page_control.get("cookie") or b""
            return {
                "items": [_entry_to_dict(e) for e in conn.entries],
                "next_cookie": base64.b64encode(next_cookie).decode() if next_cookie else None,
            }

    def get(self, username: str) -> dict[str, Any] | None:
        safe = escape_filter_chars(username)
        with self.manager.connection() as conn:
            conn.search(self.base_dn, f"(&(objectClass=person)(uid={safe}))", SUBTREE, attributes=["*", "+"], size_limit=2)
            _ensure_success(conn, "SEARCH")
            if not conn.entries:
                return None
            return _entry_to_dict(conn.entries[0])

    def _next_uid(self, conn: Any) -> int:
        conn.search(self.base_dn, "(uidNumber=*)", SUBTREE, attributes=["uidNumber"])
        _ensure_success(conn, "SEARCH")
        values = []
        for entry in conn.entries:
            try:
                values.append(int(entry.uidNumber.value))
            except (AttributeError, TypeError, ValueError):
                continue
        candidate = max(values, default=self.uid_min - 1) + 1
        if candidate < self.uid_min:
            candidate = self.uid_min
        if candidate > self.uid_max:
            raise ValueError("Configured UID range is exhausted")
        return candidate

    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        username = data["username"]
        rdn = f"uid={escape_rdn(username)}"
        parent = data.get("organizational_unit") or self.base_dn
        if "," not in parent and parent:
            parent = f"ou={escape_rdn(parent)},{self.base_dn}"
        dn = f"{rdn},{parent}"
        with self.manager.connection() as conn:
            uid_number = data.get("uid_number") or self._next_uid(conn)
            attrs = {
                "uid": username,
                "cn": data.get("display_name") or f"{data['first_name']} {data['last_name']}",
                "givenName": data["first_name"],
                "sn": data["last_name"],
                "displayName": data.get("display_name") or f"{data['first_name']} {data['last_name']}",
                "uidNumber": str(uid_number),
                "gidNumber": str(data["gid_number"]),
                "homeDirectory": data.get("home_directory") or f"/home/{username}",
                "loginShell": data.get("login_shell") or "/bin/bash",
                "userPassword": LDAPPasswordService.hash_ssha(data["password"]),
            }
            if data.get("email"):
                attrs["mail"] = data["email"]
            if not conn.add(dn, object_class=data.get("object_classes") or ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"], attributes=attrs):
                raise LDAPOperationError("LDAP ADD failed", result=conn.result)
            return {"dn": dn, "username": username, "uid_number": uid_number}

    def update(self, username: str, changes: dict[str, Any]) -> dict[str, Any]:
        current = self.get(username)
        if not current:
            raise KeyError(username)
        mapping = {
            "first_name": "givenName", "last_name": "sn", "display_name": "displayName",
            "email": "mail", "gid_number": "gidNumber", "home_directory": "homeDirectory", "login_shell": "loginShell",
        }
        modifications = {}
        for key, attr in mapping.items():
            if changes.get(key) is not None:
                modifications[attr] = [(MODIFY_REPLACE, [str(changes[key])])]
        for attr, value in (changes.get("attributes") or {}).items():
            if attr.lower() == "userpassword":
                raise ValueError("Use password reset endpoint for userPassword")
            modifications[attr] = [(MODIFY_REPLACE, value if isinstance(value, list) else [value])]
        if not modifications:
            return current
        with self.manager.connection() as conn:
            if not conn.modify(current["dn"], modifications):
                raise LDAPOperationError("LDAP MODIFY failed", result=conn.result)
        return self.get(username) or {"dn": current["dn"]}

    def reset_password(self, username: str, password: str) -> None:
        current = self.get(username)
        if not current:
            raise KeyError(username)
        hashed = LDAPPasswordService.hash_ssha(password)
        with self.manager.connection() as conn:
            if not conn.modify(current["dn"], {"userPassword": [(MODIFY_REPLACE, [hashed])]}):
                raise LDAPOperationError("LDAP password MODIFY failed", result=conn.result)

    def disable(self, username: str) -> None:
        current = self.get(username)
        if not current:
            raise KeyError(username)
        with self.manager.connection() as conn:
            # pwdAccountLockedTime=000001010000Z is understood by OpenLDAP ppolicy when available.
            if not conn.modify(current["dn"], {"pwdAccountLockedTime": [(MODIFY_REPLACE, ["000001010000Z"])]}):
                raise LDAPOperationError("LDAP disable failed; ppolicy may be unavailable", result=conn.result)

    def enable(self, username: str) -> None:
        current = self.get(username)
        if not current:
            raise KeyError(username)
        with self.manager.connection() as conn:
            if not conn.modify(current["dn"], {"pwdAccountLockedTime": [(MODIFY_DELETE, [])]}):
                if conn.result.get("result") not in {0, 16}:
                    raise LDAPOperationError("LDAP enable failed", result=conn.result)

    def delete(self, username: str) -> str:
        current = self.get(username)
        if not current:
            raise KeyError(username)
        with self.manager.connection() as conn:
            if not conn.delete(current["dn"]):
                raise LDAPOperationError("LDAP DELETE failed", result=conn.result)
        return current["dn"]


class LDAPGroupService:
    def __init__(self, manager: LDAPConnectionManager, gid_min: int = 10000, gid_max: int = 60000):
        self.manager = manager
        self.gid_min = gid_min
        self.gid_max = gid_max

    @property
    def base_dn(self) -> str:
        return self.manager.settings.groups_base_dn or self.manager.settings.base_dn

    def list(self) -> list[dict[str, Any]]:
        filt = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
        with self.manager.connection() as conn:
            conn.search(self.base_dn, filt, SUBTREE, attributes=["cn", "gidNumber", "member", "uniqueMember", "memberUid", "objectClass"])
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(e) for e in conn.entries]

    def get(self, name: str) -> dict[str, Any] | None:
        safe = escape_filter_chars(name)
        with self.manager.connection() as conn:
            conn.search(self.base_dn, f"(&(cn={safe})(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)))", SUBTREE, attributes=["*", "+"], size_limit=2)
            _ensure_success(conn, "SEARCH")
            return _entry_to_dict(conn.entries[0]) if conn.entries else None

    def _next_gid(self, conn: Any) -> int:
        conn.search(self.base_dn, "(gidNumber=*)", SUBTREE, attributes=["gidNumber"])
        values = []
        for entry in conn.entries:
            try:
                values.append(int(entry.gidNumber.value))
            except (AttributeError, TypeError, ValueError):
                pass
        candidate = max(values, default=self.gid_min - 1) + 1
        if candidate > self.gid_max:
            raise ValueError("Configured GID range is exhausted")
        return max(candidate, self.gid_min)

    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        name = data["name"]
        dn = f"cn={escape_rdn(name)},{self.base_dn}"
        group_type = data.get("group_type", "groupOfNames")
        with self.manager.connection() as conn:
            attrs: dict[str, Any] = {"cn": name}
            members = data.get("members") or []
            if group_type == "posixGroup":
                attrs["gidNumber"] = str(data.get("gid_number") or self._next_gid(conn))
                if members:
                    attrs["memberUid"] = members
            elif group_type == "groupOfUniqueNames":
                attrs["uniqueMember"] = members or [self.manager.settings.bind_dn]
            else:
                attrs["member"] = members or [self.manager.settings.bind_dn]
            if not conn.add(dn, object_class=["top", group_type], attributes=attrs):
                raise LDAPOperationError("LDAP group ADD failed", result=conn.result)
        return {"dn": dn, "name": name, "type": group_type}

    def update(self, name: str, data: dict[str, Any]) -> dict[str, Any]:
        group = self.get(name)
        if not group:
            raise KeyError(name)
        modifications = {}
        for attr, value in (data.get("attributes") or {}).items():
            modifications[attr] = [(MODIFY_REPLACE, value if isinstance(value, list) else [value])]
        if data.get("members") is not None:
            classes = [str(x).lower() for x in group.get("objectClass", [])]
            member_attr = "memberUid" if "posixgroup" in classes else "uniqueMember" if "groupofuniquenames" in classes else "member"
            modifications[member_attr] = [(MODIFY_REPLACE, data["members"])]
        with self.manager.connection() as conn:
            if modifications and not conn.modify(group["dn"], modifications):
                raise LDAPOperationError("LDAP group MODIFY failed", result=conn.result)
        return self.get(name) or group

    def delete(self, name: str) -> str:
        group = self.get(name)
        if not group:
            raise KeyError(name)
        with self.manager.connection() as conn:
            if not conn.delete(group["dn"]):
                raise LDAPOperationError("LDAP group DELETE failed", result=conn.result)
        return group["dn"]


class LDAPOUService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def list(self) -> list[dict[str, Any]]:
        with self.manager.connection() as conn:
            conn.search(self.manager.settings.base_dn, "(objectClass=organizationalUnit)", SUBTREE, attributes=["ou", "description"])
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(e) for e in conn.entries]

    def create(self, name: str, parent_dn: str | None = None) -> dict[str, Any]:
        parent = parent_dn or self.manager.settings.base_dn
        dn = f"ou={escape_rdn(name)},{parent}"
        with self.manager.connection() as conn:
            if not conn.add(dn, object_class=["top", "organizationalUnit"], attributes={"ou": name}):
                raise LDAPOperationError("LDAP OU ADD failed", result=conn.result)
        return {"dn": dn, "name": name}

    def delete(self, dn: str) -> None:
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=*)", LEVEL, attributes=["1.1"], size_limit=1)
            _ensure_success(conn, "SEARCH")
            if conn.entries:
                raise ValueError("OU is not empty")
            if not conn.delete(dn):
                raise LDAPOperationError("LDAP OU DELETE failed", result=conn.result)


class LDAPSchemaService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def get(self) -> dict[str, Any]:
        with self.manager.connection() as conn:
            schema = conn.server.schema
            if not schema:
                return {"objectClasses": [], "attributeTypes": [], "syntaxes": [], "matchingRules": []}
            return {
                "objectClasses": [str(v) for v in schema.object_classes.values()],
                "attributeTypes": [str(v) for v in schema.attribute_types.values()],
                "syntaxes": [str(v) for v in schema.ldap_syntaxes.values()],
                "matchingRules": [str(v) for v in schema.matching_rules.values()],
            }


class LDAPHealthService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def check(self) -> dict[str, Any]:
        steps = self.manager.test()
        return {"ok": all(step["ok"] for step in steps if step["name"] != "write_permissions"), "steps": steps}
