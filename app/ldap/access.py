from __future__ import annotations

import base64
import hashlib
import re
from datetime import date, datetime, timezone
from typing import Any

from ldap3 import BASE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn, parse_dn

from app.ldap.connection import LDAPConnectionManager, LDAPOperationError
from app.ldap.services import LDAPUserService, _ensure_success, _entry_to_dict


COMMAND_RE = re.compile(r"^[^\x00\r\n]{1,1024}$")
ROLE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
POLICY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
RID_RE = re.compile(r"^\d{3}$")


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _first(value: Any, default: Any = None) -> Any:
    values = _values(value)
    return values[0] if values else default


def _bool_value(value: bool) -> str:
    return "TRUE" if value else "FALSE"


def _safe_config_dn(dn: str) -> str:
    parse_dn(dn)
    if dn.lower() != "cn=config" and not dn.lower().endswith(",cn=config"):
        raise ValueError("DN must be inside cn=config")
    return dn


class LDAPCommandAccessService:
    """Manage sudoRole entries used by sudo LDAP clients."""

    def __init__(self, manager: LDAPConnectionManager, base_dn: str | None = None):
        self.manager = manager
        self.base_dn = base_dn or f"ou=SUDOers,{manager.settings.base_dn}"

    def ensure_base(self) -> None:
        with self.manager.connection() as conn:
            conn.search(self.base_dn, "(objectClass=*)", BASE, attributes=["1.1"], size_limit=1)
            if conn.result.get("result") == 0 and conn.entries:
                return
            if conn.result.get("result") not in {0, 32}:
                _ensure_success(conn, "SEARCH SUDOers")
            if not conn.add(self.base_dn, object_class=["top", "organizationalUnit"], attributes={"ou": "SUDOers"}):
                raise LDAPOperationError("LDAP SUDOers base ADD failed", result=conn.result)

    def list(self, username: str | None = None) -> list[dict[str, Any]]:
        ldap_filter = "(objectClass=sudoRole)"
        if username:
            safe = escape_filter_chars(username)
            ldap_filter = f"(&(objectClass=sudoRole)(sudoUser={safe}))"
        with self.manager.connection() as conn:
            conn.search(
                self.base_dn,
                ldap_filter,
                SUBTREE,
                attributes=["cn", "sudoUser", "sudoHost", "sudoCommand", "sudoRunAsUser", "sudoRunAsGroup", "sudoOption", "sudoOrder"],
            )
            if conn.result.get("result") == 32:
                return []
            _ensure_success(conn, "SEARCH sudoRole")
            return [_entry_to_dict(entry) for entry in conn.entries]

    def get(self, role_name: str) -> dict[str, Any] | None:
        if not ROLE_RE.fullmatch(role_name):
            raise ValueError("Invalid sudo role name")
        dn = f"cn={escape_rdn(role_name)},{self.base_dn}"
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=sudoRole)", BASE, attributes=["*", "+"], size_limit=1)
            if conn.result.get("result") == 32:
                return None
            _ensure_success(conn, "SEARCH sudoRole")
            return _entry_to_dict(conn.entries[0]) if conn.entries else None

    @staticmethod
    def _validate_commands(commands: list[str]) -> list[str]:
        cleaned = list(dict.fromkeys(command.strip() for command in commands if command.strip()))
        if not cleaned or len(cleaned) > 200:
            raise ValueError("Provide between 1 and 200 sudo commands")
        for command in cleaned:
            candidate = command[1:].lstrip() if command.startswith("!") else command
            executable = candidate.split(None, 1)[0]
            if not COMMAND_RE.fullmatch(command) or (executable != "ALL" and not executable.startswith("/")):
                raise ValueError(f"Invalid sudo command: {command}")
        return cleaned

    def upsert_user_role(
        self,
        username: str,
        commands: list[str],
        *,
        role_name: str | None = None,
        hosts: list[str] | None = None,
        run_as_users: list[str] | None = None,
        run_as_groups: list[str] | None = None,
        options: list[str] | None = None,
        order: int | None = None,
    ) -> dict[str, Any]:
        self.ensure_base()
        name = role_name or f"user-{username}"
        if not ROLE_RE.fullmatch(name):
            raise ValueError("Invalid sudo role name")
        commands = self._validate_commands(commands)
        hosts = list(dict.fromkeys(hosts or ["ALL"]))
        run_as_users = list(dict.fromkeys(run_as_users or ["root"]))
        run_as_groups = list(dict.fromkeys(run_as_groups or []))
        options = list(dict.fromkeys(options or []))
        for values in (hosts, run_as_users, run_as_groups, options):
            if len(values) > 100 or any(not value or "\n" in value or "\r" in value or "\x00" in value for value in values):
                raise ValueError("Invalid sudo role value")
        attrs: dict[str, Any] = {
            "cn": name,
            "sudoUser": username,
            "sudoHost": hosts,
            "sudoCommand": commands,
            "sudoRunAsUser": run_as_users,
        }
        if run_as_groups:
            attrs["sudoRunAsGroup"] = run_as_groups
        if options:
            attrs["sudoOption"] = options
        if order is not None:
            if not 0 <= order <= 999999:
                raise ValueError("sudoOrder must be between 0 and 999999")
            attrs["sudoOrder"] = str(order)
        dn = f"cn={escape_rdn(name)},{self.base_dn}"
        current = self.get(name)
        with self.manager.connection() as conn:
            if current:
                mutable = {key: value for key, value in attrs.items() if key != "cn"}
                changes = {key: [(MODIFY_REPLACE, _values(value))] for key, value in mutable.items()}
                for optional in ("sudoRunAsGroup", "sudoOption", "sudoOrder"):
                    if optional not in mutable and current.get(optional):
                        changes[optional] = [(MODIFY_DELETE, [])]
                if not conn.modify(dn, changes):
                    raise LDAPOperationError("LDAP sudoRole MODIFY failed", result=conn.result)
            elif not conn.add(dn, object_class=["top", "sudoRole"], attributes=attrs):
                raise LDAPOperationError("LDAP sudoRole ADD failed; sudo schema may be unavailable", result=conn.result)
        return self.get(name) or {"dn": dn, **attrs}

    def delete(self, role_name: str) -> str:
        role = self.get(role_name)
        if not role:
            raise KeyError(role_name)
        with self.manager.connection() as conn:
            if not conn.delete(role["dn"]):
                raise LDAPOperationError("LDAP sudoRole DELETE failed", result=conn.result)
        return role["dn"]


class LDAPSSHKeyService:
    def __init__(self, manager: LDAPConnectionManager, uid_min: int = 10000, uid_max: int = 60000):
        self.manager = manager
        self.users = LDAPUserService(manager, uid_min, uid_max)

    @staticmethod
    def fingerprint(key: str) -> str:
        parts = key.strip().split()
        if len(parts) < 2:
            raise ValueError("Invalid SSH public key")
        try:
            raw = base64.b64decode(parts[1], validate=True)
        except Exception as exc:
            raise ValueError("Invalid SSH public key payload") from exc
        digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        return f"SHA256:{digest}"

    @staticmethod
    def validate(key: str) -> str:
        key = key.strip()
        allowed = ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-", "sk-ssh-ed25519@openssh.com ", "sk-ecdsa-sha2-nistp256@openssh.com ")
        if len(key) > 16384 or "\n" in key or "\r" in key or "\x00" in key or not key.startswith(allowed):
            raise ValueError("Unsupported or malformed SSH public key")
        LDAPSSHKeyService.fingerprint(key)
        return key

    def list(self, username: str) -> list[dict[str, str]]:
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        result = []
        for key in _values(user.get("sshPublicKey")):
            key_str = str(key)
            parts = key_str.split(maxsplit=2)
            result.append({"key": key_str, "type": parts[0] if parts else "unknown", "comment": parts[2] if len(parts) > 2 else "", "fingerprint": self.fingerprint(key_str)})
        return result

    def add(self, username: str, key: str) -> dict[str, str]:
        key = self.validate(key)
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        classes = {str(value).lower() for value in _values(user.get("objectClass"))}
        with self.manager.connection() as conn:
            changes: dict[str, list[tuple[int, list[str]]]] = {}
            if "ldappublickey" not in classes:
                changes["objectClass"] = [(MODIFY_ADD, ["ldapPublicKey"])]
            changes["sshPublicKey"] = [(MODIFY_ADD, [key])]
            if not conn.modify(user["dn"], changes):
                raise LDAPOperationError("LDAP SSH key ADD failed; ldapPublicKey schema may be unavailable", result=conn.result)
        return {"key": key, "fingerprint": self.fingerprint(key)}

    def delete(self, username: str, key: str) -> None:
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        with self.manager.connection() as conn:
            if not conn.modify(user["dn"], {"sshPublicKey": [(MODIFY_DELETE, [key])]}) and conn.result.get("result") != 16:
                raise LDAPOperationError("LDAP SSH key DELETE failed", result=conn.result)


class LDAPAccountLifecycleService:
    def __init__(self, manager: LDAPConnectionManager, uid_min: int = 10000, uid_max: int = 60000):
        self.manager = manager
        self.users = LDAPUserService(manager, uid_min, uid_max)

    def status(self, username: str) -> dict[str, Any]:
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        locked = bool(_values(user.get("pwdAccountLockedTime")))
        raw_expire = _first(user.get("shadowExpire"))
        expires_on = None
        expired = False
        if raw_expire not in {None, "", "-1"}:
            try:
                expires_on = datetime.fromtimestamp(int(raw_expire) * 86400, tz=timezone.utc).date().isoformat()
                expired = int(raw_expire) < int(datetime.now(timezone.utc).timestamp() // 86400)
            except (TypeError, ValueError, OSError, OverflowError):
                expires_on = None
        state = "Disabled" if locked else "Expired" if expired else "Active"
        return {
            "username": username,
            "dn": user["dn"],
            "state": state,
            "locked": locked,
            "expired": expired,
            "expires_on": expires_on,
            "password_reset_required": str(_first(user.get("pwdReset"), "FALSE")).upper() == "TRUE",
        }

    def set_expiry(self, username: str, expires_on: date | None) -> dict[str, Any]:
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        with self.manager.connection() as conn:
            if expires_on is None:
                changes = {"shadowExpire": [(MODIFY_DELETE, [])]}
            else:
                classes = {str(value).lower() for value in _values(user.get("objectClass"))}
                changes = {}
                if "shadowaccount" not in classes:
                    changes["objectClass"] = [(MODIFY_ADD, ["shadowAccount"])]
                days = (expires_on - date(1970, 1, 1)).days
                changes["shadowExpire"] = [(MODIFY_REPLACE, [str(days)])]
            if not conn.modify(user["dn"], changes) and conn.result.get("result") != 16:
                raise LDAPOperationError("LDAP lifecycle expiry MODIFY failed", result=conn.result)
        return self.status(username)

    def set_enabled(self, username: str, enabled: bool) -> dict[str, Any]:
        if enabled:
            self.users.enable(username)
        else:
            self.users.disable(username)
        return self.status(username)

    def require_password_change(self, username: str, required: bool) -> dict[str, Any]:
        user = self.users.get(username)
        if not user:
            raise KeyError(username)
        change = [(MODIFY_REPLACE, [_bool_value(required)])] if required else [(MODIFY_DELETE, [])]
        with self.manager.connection() as conn:
            if not conn.modify(user["dn"], {"pwdReset": change}) and conn.result.get("result") != 16:
                raise LDAPOperationError("LDAP pwdReset MODIFY failed; ppolicy overlay may be unavailable", result=conn.result)
        return self.status(username)


class LDAPPasswordPolicyService:
    NUMERIC_FIELDS = {
        "pwdMinAge",
        "pwdMaxAge",
        "pwdInHistory",
        "pwdMinLength",
        "pwdExpireWarning",
        "pwdGraceAuthnLimit",
        "pwdMaxFailure",
        "pwdFailureCountInterval",
        "pwdLockoutDuration",
    }
    BOOLEAN_FIELDS = {"pwdLockout", "pwdMustChange", "pwdAllowUserChange", "pwdSafeModify"}

    def __init__(self, manager: LDAPConnectionManager, base_dn: str | None = None):
        self.manager = manager
        self.base_dn = base_dn or f"ou=Policies,{manager.settings.base_dn}"

    def ensure_base(self) -> None:
        with self.manager.connection() as conn:
            conn.search(self.base_dn, "(objectClass=*)", BASE, attributes=["1.1"], size_limit=1)
            if conn.result.get("result") == 0 and conn.entries:
                return
            if conn.result.get("result") not in {0, 32}:
                _ensure_success(conn, "SEARCH Policies")
            if not conn.add(self.base_dn, object_class=["top", "organizationalUnit"], attributes={"ou": "Policies"}):
                raise LDAPOperationError("LDAP Policies base ADD failed", result=conn.result)

    def list(self) -> list[dict[str, Any]]:
        with self.manager.connection() as conn:
            conn.search(self.base_dn, "(objectClass=pwdPolicy)", SUBTREE, attributes=["*", "+"])
            if conn.result.get("result") == 32:
                return []
            _ensure_success(conn, "SEARCH pwdPolicy")
            return [_entry_to_dict(entry) for entry in conn.entries]

    def get(self, name: str) -> dict[str, Any] | None:
        if not POLICY_RE.fullmatch(name):
            raise ValueError("Invalid policy name")
        dn = f"cn={escape_rdn(name)},{self.base_dn}"
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=pwdPolicy)", BASE, attributes=["*", "+"], size_limit=1)
            if conn.result.get("result") == 32:
                return None
            _ensure_success(conn, "SEARCH pwdPolicy")
            return _entry_to_dict(conn.entries[0]) if conn.entries else None

    def upsert(self, name: str, values: dict[str, Any]) -> dict[str, Any]:
        if not POLICY_RE.fullmatch(name):
            raise ValueError("Invalid policy name")
        self.ensure_base()
        attrs: dict[str, Any] = {"cn": name, "pwdAttribute": "userPassword"}
        for key, value in values.items():
            if key in self.NUMERIC_FIELDS and value is not None:
                number = int(value)
                if number < 0:
                    raise ValueError(f"{key} cannot be negative")
                attrs[key] = str(number)
            elif key in self.BOOLEAN_FIELDS and value is not None:
                attrs[key] = _bool_value(bool(value))
        dn = f"cn={escape_rdn(name)},{self.base_dn}"
        current = self.get(name)
        with self.manager.connection() as conn:
            if current:
                changes = {key: [(MODIFY_REPLACE, _values(value))] for key, value in attrs.items() if key != "cn"}
                if not conn.modify(dn, changes):
                    raise LDAPOperationError("LDAP pwdPolicy MODIFY failed", result=conn.result)
            elif not conn.add(dn, object_class=["top", "pwdPolicy"], attributes=attrs):
                raise LDAPOperationError("LDAP pwdPolicy ADD failed; ppolicy schema may be unavailable", result=conn.result)
        return self.get(name) or {"dn": dn, **attrs}

    def delete(self, name: str) -> str:
        policy = self.get(name)
        if not policy:
            raise KeyError(name)
        with self.manager.connection() as conn:
            if not conn.delete(policy["dn"]):
                raise LDAPOperationError("LDAP pwdPolicy DELETE failed", result=conn.result)
        return policy["dn"]

    def assign(self, user_dn: str, policy_dn: str | None) -> None:
        parse_dn(user_dn)
        if policy_dn:
            parse_dn(policy_dn)
            change = [(MODIFY_REPLACE, [policy_dn])]
        else:
            change = [(MODIFY_DELETE, [])]
        with self.manager.connection() as conn:
            if not conn.modify(user_dn, {"pwdPolicySubentry": change}) and conn.result.get("result") != 16:
                raise LDAPOperationError("LDAP pwdPolicySubentry MODIFY failed", result=conn.result)


class LDAPConfigService:
    """Administrative cn=config operations for ACL and syncrepl."""

    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def databases(self) -> list[dict[str, Any]]:
        with self.manager.connection() as conn:
            conn.search(
                "cn=config",
                "(objectClass=olcDatabaseConfig)",
                SUBTREE,
                attributes=["olcDatabase", "olcSuffix", "olcAccess", "olcSyncRepl", "olcMirrorMode"],
            )
            _ensure_success(conn, "SEARCH cn=config databases")
            rows = [_entry_to_dict(entry) for entry in conn.entries]
        for row in rows:
            row["olcSyncRepl"] = [self.redact_syncrepl(str(value)) for value in _values(row.get("olcSyncRepl"))]
        return rows

    def get_database(self, dn: str) -> dict[str, Any] | None:
        dn = _safe_config_dn(dn)
        with self.manager.connection() as conn:
            conn.search(dn, "(objectClass=olcDatabaseConfig)", BASE, attributes=["*", "+"], size_limit=1)
            if conn.result.get("result") == 32:
                return None
            _ensure_success(conn, "SEARCH cn=config database")
            if not conn.entries:
                return None
            result = _entry_to_dict(conn.entries[0])
            result["olcSyncRepl"] = [self.redact_syncrepl(str(value)) for value in _values(result.get("olcSyncRepl"))]
            return result

    @staticmethod
    def normalize_acl(rules: list[str]) -> list[str]:
        cleaned = []
        for raw in rules:
            rule = raw.strip()
            if not rule:
                continue
            if "\n" in rule or "\r" in rule or "\x00" in rule or not re.match(r"^(?:\{\d+\})?to\s+", rule, flags=re.IGNORECASE):
                raise ValueError(f"Invalid olcAccess rule: {raw}")
            if not rule.startswith("{"):
                rule = f"{{{len(cleaned)}}}{rule}"
            cleaned.append(rule)
        if not cleaned:
            raise ValueError("At least one ACL rule is required")
        return cleaned

    def set_acl(self, database_dn: str, rules: list[str]) -> dict[str, Any]:
        database_dn = _safe_config_dn(database_dn)
        normalized = self.normalize_acl(rules)
        with self.manager.connection() as conn:
            if not conn.modify(database_dn, {"olcAccess": [(MODIFY_REPLACE, normalized)]}):
                raise LDAPOperationError("LDAP olcAccess MODIFY failed", result=conn.result)
        return {"database_dn": database_dn, "olcAccess": normalized}

    @staticmethod
    def redact_syncrepl(value: str) -> str:
        return re.sub(r"(?i)((?:bind)?credentials=)(?:\"[^\"]*\"|'[^']*'|\S+)", r"\1***", value)

    @staticmethod
    def build_syncrepl(
        *,
        rid: str,
        provider: str,
        searchbase: str,
        binddn: str,
        bindcredentials: str,
        bindmethod: str = "simple",
        schemachecking: bool = True,
        sync_type: str = "refreshAndPersist",
        retry: str = "5 5 300 +",
        tls_reqcert: str | None = None,
    ) -> str:
        if not RID_RE.fullmatch(rid):
            raise ValueError("syncrepl rid must contain exactly three digits")
        if not provider.startswith(("ldap://", "ldaps://")):
            raise ValueError("syncrepl provider must use ldap:// or ldaps://")
        parse_dn(searchbase)
        parse_dn(binddn)
        if bindmethod not in {"simple", "sasl"}:
            raise ValueError("Unsupported syncrepl bindmethod")
        if sync_type not in {"refreshOnly", "refreshAndPersist"}:
            raise ValueError("Unsupported syncrepl type")
        for value in (provider, bindcredentials, retry):
            if "\n" in value or "\r" in value or "\x00" in value:
                raise ValueError("Invalid syncrepl value")
        if '"' in bindcredentials:
            raise ValueError("syncrepl credential cannot contain a double quote")
        parts = [
            f"rid={rid}",
            f"provider={provider}",
            f"bindmethod={bindmethod}",
            f'binddn="{binddn}"',
            f'credentials="{bindcredentials}"',
            f'searchbase="{searchbase}"',
            f"type={sync_type}",
            f"schemachecking={'on' if schemachecking else 'off'}",
            f'retry="{retry}"',
        ]
        if tls_reqcert:
            if tls_reqcert not in {"never", "allow", "try", "demand", "hard"}:
                raise ValueError("Invalid tls_reqcert")
            parts.append(f"tls_reqcert={tls_reqcert}")
        return " ".join(parts)

    def set_replication(self, database_dn: str, syncrepl: list[str], mirror_mode: bool = False) -> dict[str, Any]:
        database_dn = _safe_config_dn(database_dn)
        if not syncrepl or len(syncrepl) > 10:
            raise ValueError("Provide between 1 and 10 syncrepl definitions")
        with self.manager.connection() as conn:
            changes = {
                "olcSyncRepl": [(MODIFY_REPLACE, syncrepl)],
                "olcMirrorMode": [(MODIFY_REPLACE, [_bool_value(mirror_mode)])],
            }
            if not conn.modify(database_dn, changes):
                raise LDAPOperationError("LDAP syncrepl MODIFY failed", result=conn.result)
        return {"database_dn": database_dn, "olcSyncRepl": [self.redact_syncrepl(value) for value in syncrepl], "olcMirrorMode": mirror_mode}

    def disable_replication(self, database_dn: str) -> None:
        database_dn = _safe_config_dn(database_dn)
        with self.manager.connection() as conn:
            changes = {"olcSyncRepl": [(MODIFY_DELETE, [])], "olcMirrorMode": [(MODIFY_REPLACE, ["FALSE"])]}
            if not conn.modify(database_dn, changes) and conn.result.get("result") != 16:
                raise LDAPOperationError("LDAP syncrepl disable failed", result=conn.result)
