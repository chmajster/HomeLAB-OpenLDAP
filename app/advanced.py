from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from ldap3 import BASE, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn, parse_dn
from passlib.hash import pbkdf2_sha512, sha512_crypt

from app.ldap.connection import LDAPConnectionManager, LDAPOperationError
from app.ldap.services import LDAPPasswordService, _entry_to_dict, _ensure_success


READ_ONLY_ATTRIBUTES = {
    "createtimestamp",
    "modifytimestamp",
    "creatorsname",
    "modifiersname",
    "entryuuid",
    "entrycsn",
    "structuralobjectclass",
    "subschemasubentry",
    "hassubordinates",
    "entrydn",
}


def encode_dn(dn: str) -> str:
    return base64.urlsafe_b64encode(dn.encode()).decode().rstrip("=")


def decode_dn(value: str) -> str:
    padded = value + "=" * (-len(value) % 4)
    dn = base64.urlsafe_b64decode(padded.encode()).decode()
    parse_dn(dn)
    return dn


def normalize_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def safe_entry_attributes(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in entry.items()
        if key != "dn" and key.lower() not in READ_ONLY_ATTRIBUTES and key.lower() != "userpassword"
    }


class LDAPEntryService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def get(self, dn: str) -> dict[str, Any] | None:
        parse_dn(dn)
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=*)", BASE, attributes=["*", "+"], size_limit=1)
            if conn.result.get("result") == 32:
                return None
            _ensure_success(conn, "SEARCH")
            return _entry_to_dict(conn.entries[0]) if conn.entries else None

    def children(self, dn: str, limit: int = 500) -> list[dict[str, Any]]:
        parse_dn(dn)
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=*)", LEVEL, attributes=["objectClass", "ou", "uid", "cn"], size_limit=min(max(limit, 1), 5000))
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(entry) for entry in conn.entries]

    def preview(self, dn: str, attributes: dict[str, Any]) -> dict[str, Any]:
        current = self.get(dn)
        if not current:
            raise KeyError(dn)
        diff: list[dict[str, Any]] = []
        for attr, new_value in attributes.items():
            if attr.lower() in READ_ONLY_ATTRIBUTES or attr.lower() == "dn":
                raise ValueError(f"Attribute is read-only: {attr}")
            old_value = current.get(attr)
            if normalize_values(old_value) != normalize_values(new_value):
                diff.append({"attribute": attr, "old": old_value, "new": new_value})
        return {"dn": dn, "changes": diff, "count": len(diff)}

    def modify(self, dn: str, attributes: dict[str, Any]) -> dict[str, Any]:
        preview = self.preview(dn, attributes)
        if not preview["changes"]:
            return self.get(dn) or {"dn": dn}
        modifications: dict[str, list[tuple[int, list[Any]]]] = {}
        for change in preview["changes"]:
            attr = change["attribute"]
            values = normalize_values(change["new"])
            modifications[attr] = [(MODIFY_REPLACE, values)] if values else [(MODIFY_DELETE, [])]
        with self.manager.connection() as conn:
            if not conn.modify(dn, modifications):
                raise LDAPOperationError("LDAP MODIFY failed", result=conn.result)
        return self.get(dn) or {"dn": dn}

    def add_attribute_value(self, dn: str, attribute: str, values: list[Any]) -> None:
        if attribute.lower() in READ_ONLY_ATTRIBUTES or not values:
            raise ValueError("Invalid attribute/value")
        with self.manager.connection() as conn:
            if not conn.modify(dn, {attribute: [(MODIFY_ADD, values)]}):
                raise LDAPOperationError("LDAP attribute ADD failed", result=conn.result)

    def delete_attribute_value(self, dn: str, attribute: str, values: list[Any] | None = None) -> None:
        if attribute.lower() in READ_ONLY_ATTRIBUTES:
            raise ValueError("Read-only attribute")
        with self.manager.connection() as conn:
            if not conn.modify(dn, {attribute: [(MODIFY_DELETE, values or [])]}):
                raise LDAPOperationError("LDAP attribute DELETE failed", result=conn.result)

    def move(self, dn: str, new_parent_dn: str, new_rdn: str | None = None) -> str:
        parse_dn(dn)
        parse_dn(new_parent_dn)
        current_rdn = dn.split(",", 1)[0]
        target_rdn = new_rdn or current_rdn
        if "," in target_rdn:
            raise ValueError("new_rdn must contain only one RDN")
        with self.manager.connection() as conn:
            if not conn.modify_dn(dn, target_rdn, delete_old_dn=True, new_superior=new_parent_dn):
                raise LDAPOperationError("LDAP MODDN failed", result=conn.result)
        return f"{target_rdn},{new_parent_dn}"

    def rename_rdn(self, dn: str, attribute: str, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", attribute):
            raise ValueError("Invalid RDN attribute")
        new_rdn = f"{attribute}={escape_rdn(value)}"
        parent = dn.split(",", 1)[1]
        return self.move(dn, parent, new_rdn)

    def copy(self, source_dn: str, target_dn: str, replacements: dict[str, Any] | None = None) -> dict[str, Any]:
        parse_dn(target_dn)
        source = self.get(source_dn)
        if not source:
            raise KeyError(source_dn)
        attrs = safe_entry_attributes(source)
        classes = attrs.pop("objectClass", attrs.pop("objectclass", ["top"]))
        for key, value in (replacements or {}).items():
            if key.lower() in READ_ONLY_ATTRIBUTES or key.lower() == "userpassword":
                raise ValueError(f"Attribute cannot be copied/replaced here: {key}")
            attrs[key] = value
        with self.manager.connection() as conn:
            if not conn.add(target_dn, object_class=normalize_values(classes), attributes=attrs):
                raise LDAPOperationError("LDAP COPY/ADD failed", result=conn.result)
        return self.get(target_dn) or {"dn": target_dn}

    def delete(self, dn: str, require_empty: bool = False) -> None:
        parse_dn(dn)
        if require_empty:
            with self.manager.connection() as conn:
                conn.search(dn, "(objectClass=*)", LEVEL, attributes=["1.1"], size_limit=1)
                _ensure_success(conn, "SEARCH")
                if conn.entries:
                    raise ValueError("LDAP entry contains child objects")
                if not conn.delete(dn):
                    raise LDAPOperationError("LDAP DELETE failed", result=conn.result)
            return
        with self.manager.connection() as conn:
            if not conn.delete(dn):
                raise LDAPOperationError("LDAP DELETE failed", result=conn.result)


class LDAPMembershipService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def member_attribute(group: dict[str, Any]) -> str:
        classes = {str(value).lower() for value in normalize_values(group.get("objectClass"))}
        if "groupofuniquenames" in classes:
            return "uniqueMember"
        if "posixgroup" in classes:
            return "memberUid"
        return "member"

    def change(self, group_dn: str, member: str, add: bool) -> None:
        group = LDAPEntryService(self.manager).get(group_dn)
        if not group:
            raise KeyError(group_dn)
        attr = self.member_attribute(group)
        value = member
        if attr == "memberUid" and "," in member:
            rdn = member.split(",", 1)[0]
            value = rdn.split("=", 1)[1] if "=" in rdn else member
        operation = MODIFY_ADD if add else MODIFY_DELETE
        with self.manager.connection() as conn:
            if not conn.modify(group_dn, {attr: [(operation, [value])]}):
                if not add and conn.result.get("result") == 16:
                    return
                raise LDAPOperationError("LDAP membership MODIFY failed", result=conn.result)

    def groups_for_user(self, user_dn: str, username: str) -> list[dict[str, Any]]:
        base = self.manager.settings.groups_base_dn or self.manager.settings.base_dn
        safe_dn = escape_filter_chars(user_dn)
        safe_uid = escape_filter_chars(username)
        ldap_filter = f"(|(member={safe_dn})(uniqueMember={safe_dn})(memberUid={safe_uid}))"
        with self.manager.connection() as conn:
            conn.search(base, ldap_filter, SUBTREE, attributes=["cn", "objectClass", "gidNumber"])
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(entry) for entry in conn.entries]


class LDAPQueryBuilder:
    ALLOWED_ATTRIBUTES = re.compile(r"^[A-Za-z][A-Za-z0-9;-]*$")

    @classmethod
    def condition(cls, attribute: str, operator: str, value: str | None = None) -> str:
        if not cls.ALLOWED_ATTRIBUTES.fullmatch(attribute):
            raise ValueError("Invalid LDAP attribute name")
        escaped = escape_filter_chars(value or "")
        if operator == "equals":
            return f"({attribute}={escaped})"
        if operator == "not_equals":
            return f"(!({attribute}={escaped}))"
        if operator == "contains":
            return f"({attribute}=*{escaped}*)"
        if operator == "starts_with":
            return f"({attribute}={escaped}*)"
        if operator == "ends_with":
            return f"({attribute}=*{escaped})"
        if operator == "present":
            return f"({attribute}=*)"
        raise ValueError("Unsupported LDAP query operator")

    @staticmethod
    def combine(operator: str, filters: list[str]) -> str:
        if not filters:
            raise ValueError("At least one filter is required")
        if operator == "AND":
            return "(&" + "".join(filters) + ")"
        if operator == "OR":
            return "(|" + "".join(filters) + ")"
        if operator == "NOT":
            if len(filters) != 1:
                raise ValueError("NOT accepts exactly one filter")
            return "(!" + filters[0] + ")"
        raise ValueError("Unsupported logical operator")


class LDAPAdvancedPasswordService(LDAPPasswordService):
    @staticmethod
    def hash_sha512(password: str) -> str:
        return "{SHA512}" + base64.b64encode(hashlib.sha512(password.encode()).digest()).decode()

    @staticmethod
    def hash_pbkdf2(password: str, rounds: int = 120_000) -> str:
        return "{PBKDF2-SHA512}" + pbkdf2_sha512.using(rounds=rounds).hash(password)

    @staticmethod
    def hash_crypt(password: str) -> str:
        return "{CRYPT}" + sha512_crypt.hash(password)

    @classmethod
    def hash_password(cls, password: str, scheme: str = "SSHA") -> str:
        normalized = scheme.upper()
        if normalized == "SSHA":
            return cls.hash_ssha(password)
        if normalized == "SHA512":
            return cls.hash_sha512(password)
        if normalized == "PBKDF2":
            return cls.hash_pbkdf2(password)
        if normalized == "CRYPT":
            return cls.hash_crypt(password)
        raise ValueError("Unsupported password hashing scheme")


@dataclass(slots=True)
class AttributeMapping:
    username: str = "uid"
    email: str = "mail"
    first_name: str = "givenName"
    last_name: str = "sn"
    display_name: str = "displayName"
    uid: str = "uidNumber"
    gid: str = "gidNumber"

    @classmethod
    def from_json(cls, value: str | None) -> "AttributeMapping":
        if not value:
            return cls()
        data = json.loads(value)
        allowed = set(cls.__dataclass_fields__)
        clean = {key: val for key, val in data.items() if key in allowed and isinstance(val, str)}
        return cls(**clean)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)
