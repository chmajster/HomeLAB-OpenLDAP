from __future__ import annotations

import base64
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.utils.dn import parse_dn

from app.ldap.connection import LDAPConnectionManager, LDAPOperationError
from app.ldap.services import _entry_to_dict, _ensure_success


class LDIFService:
    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def _unfold(text: str) -> list[str]:
        lines: list[str] = []
        for raw in text.replace("\r\n", "\n").split("\n"):
            if raw.startswith(" ") and lines:
                lines[-1] += raw[1:]
            else:
                lines.append(raw)
        return lines

    @staticmethod
    def _decode_value(marker: str, value: str) -> str:
        if marker == "::":
            return base64.b64decode(value.strip()).decode("utf-8")
        return value.lstrip()

    def parse(self, text: str) -> list[dict[str, Any]]:
        records: list[list[str]] = []
        current: list[str] = []
        for line in self._unfold(text):
            if not line.strip():
                if current:
                    records.append(current)
                    current = []
                continue
            if line.startswith("#"):
                continue
            current.append(line)
        if current:
            records.append(current)

        parsed: list[dict[str, Any]] = []
        for lines in records:
            attrs: dict[str, list[str]] = {}
            raw_pairs: list[tuple[str, str]] = []
            for line in lines:
                match = re.match(r"^([^:]+)(::|:<|:)(.*)$", line)
                if not match:
                    raise ValueError(f"Invalid LDIF line: {line}")
                key, marker, value = match.groups()
                if marker == ":<":
                    raise ValueError("External file URLs in LDIF are not supported")
                decoded = self._decode_value(marker, value)
                attrs.setdefault(key, []).append(decoded)
                raw_pairs.append((key, decoded))
            dn = (attrs.get("dn") or [None])[0]
            if not dn:
                raise ValueError("LDIF record is missing DN")
            parse_dn(dn)
            changetype = ((attrs.get("changetype") or ["add"])[0]).lower()
            parsed.append({"dn": dn, "changetype": changetype, "attributes": attrs, "pairs": raw_pairs, "lines": lines})
        return parsed

    def preview(self, text: str) -> dict[str, Any]:
        records = self.parse(text)
        counts = {"add": 0, "modify": 0, "delete": 0, "modrdn": 0}
        for record in records:
            key = "modrdn" if record["changetype"] in {"modrdn", "moddn"} else record["changetype"]
            counts[key] = counts.get(key, 0) + 1
        return {"valid": True, "total": len(records), "create": counts.get("add", 0), "modify": counts.get("modify", 0), "delete": counts.get("delete", 0), "modrdn": counts.get("modrdn", 0), "dns": [r["dn"] for r in records]}

    @staticmethod
    def _modify_sections(record: dict[str, Any]) -> dict[str, list[tuple[int, list[str]]]]:
        modifications: dict[str, list[tuple[int, list[str]]]] = {}
        lines = record["lines"]
        i = 0
        while i < len(lines):
            line = lines[i]
            match = re.match(r"^(add|delete|replace):\s*(.+)$", line, re.I)
            if not match:
                i += 1
                continue
            operation, attr = match.group(1).lower(), match.group(2).strip()
            values: list[str] = []
            i += 1
            while i < len(lines) and lines[i] != "-":
                value_match = re.match(rf"^{re.escape(attr)}(::|:)(.*)$", lines[i], re.I)
                if value_match:
                    values.append(LDIFService._decode_value(value_match.group(1), value_match.group(2)))
                i += 1
            op_code = {"add": MODIFY_ADD, "delete": MODIFY_DELETE, "replace": MODIFY_REPLACE}[operation]
            modifications.setdefault(attr, []).append((op_code, values))
            i += 1
        if not modifications:
            raise ValueError(f"Modify record for {record['dn']} contains no operations")
        return modifications

    def apply(self, text: str) -> dict[str, Any]:
        records = self.parse(text)
        results = []
        with self.manager.connection() as conn:
            for record in records:
                dn = record["dn"]
                changetype = record["changetype"]
                try:
                    if changetype == "add":
                        attrs = {k: v for k, v in record["attributes"].items() if k.lower() not in {"dn", "changetype", "objectclass"}}
                        object_classes = record["attributes"].get("objectClass") or record["attributes"].get("objectclass") or ["top"]
                        ok = conn.add(dn, object_class=object_classes, attributes=attrs)
                    elif changetype == "delete":
                        ok = conn.delete(dn)
                    elif changetype == "modify":
                        ok = conn.modify(dn, self._modify_sections(record))
                    elif changetype in {"modrdn", "moddn"}:
                        attrs = record["attributes"]
                        new_rdn = (attrs.get("newrdn") or [None])[0]
                        if not new_rdn:
                            raise ValueError("modrdn record is missing newrdn")
                        delete_old = (attrs.get("deleteoldrdn") or ["1"])[0] != "0"
                        new_superior = (attrs.get("newsuperior") or [None])[0]
                        ok = conn.modify_dn(dn, new_rdn, delete_old_dn=delete_old, new_superior=new_superior)
                    else:
                        raise ValueError(f"Unsupported LDIF changetype: {changetype}")
                    if not ok:
                        raise LDAPOperationError(f"LDIF {changetype} failed", result=conn.result)
                    results.append({"dn": dn, "operation": changetype, "status": "SUCCESS"})
                except Exception as exc:
                    results.append({"dn": dn, "operation": changetype, "status": "FAILED", "error": str(exc)})
        success = sum(1 for r in results if r["status"] == "SUCCESS")
        failed = len(results) - success
        return {"status": "SUCCESS" if failed == 0 else "PARTIAL", "success": success, "failed": failed, "results": results}

    def export(self, base_dn: str | None = None, ldap_filter: str = "(objectClass=*)") -> str:
        target = base_dn or self.manager.settings.base_dn
        with self.manager.connection() as conn:
            conn.search(target, ldap_filter, SUBTREE, attributes=["*"])
            _ensure_success(conn, "SEARCH")
            records = []
            for entry in conn.entries:
                lines = [f"dn: {entry.entry_dn}"]
                for attr, values in entry.entry_attributes_as_dict.items():
                    for value in values if isinstance(values, list) else [values]:
                        text_value = str(value)
                        try:
                            text_value.encode("ascii")
                            encoded = text_value.startswith((" ", ":", "<")) or text_value.endswith(" ")
                        except UnicodeEncodeError:
                            encoded = True
                        if encoded:
                            lines.append(f"{attr}:: {base64.b64encode(text_value.encode()).decode()}")
                        else:
                            lines.append(f"{attr}: {text_value}")
                records.append("\n".join(lines))
            return "\n\n".join(records) + ("\n" if records else "")


class PasswordPolicyService:
    POLICY_ATTRS = ["pwdMinLength", "pwdInHistory", "pwdMaxAge", "pwdExpireWarning", "pwdMaxFailure", "pwdLockoutDuration", "pwdLockout"]

    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    def detect(self) -> dict[str, Any]:
        with self.manager.connection() as conn:
            schema = conn.server.schema
            detected = bool(schema and any(str(name).lower() == "pwdpolicy" for name in schema.object_classes.keys()))
            if not detected:
                return {"detected": False, "message": "Password Policy overlay not detected.", "policies": []}
            conn.search(self.manager.settings.base_dn, "(objectClass=pwdPolicy)", SUBTREE, attributes=self.POLICY_ATTRS)
            if conn.result.get("result") not in {0, 32}:
                raise LDAPOperationError("Password policy search failed", result=conn.result)
            return {"detected": True, "policies": [_entry_to_dict(e) for e in conn.entries]}

    def locked_accounts(self) -> list[dict[str, Any]]:
        base = self.manager.settings.users_base_dn or self.manager.settings.base_dn
        with self.manager.connection() as conn:
            conn.search(base, "(pwdAccountLockedTime=*)", SUBTREE, attributes=["uid", "cn", "pwdAccountLockedTime", "pwdFailureTime"])
            if conn.result.get("result") == 16:
                return []
            _ensure_success(conn, "SEARCH")
            return [_entry_to_dict(e) for e in conn.entries]

    def unlock(self, dn: str) -> None:
        with self.manager.connection() as conn:
            ok = conn.modify(dn, {"pwdAccountLockedTime": [(MODIFY_DELETE, [])], "pwdFailureTime": [(MODIFY_DELETE, [])]})
            if not ok and conn.result.get("result") not in {0, 16}:
                raise LDAPOperationError("LDAP unlock failed", result=conn.result)


class SystemService:
    def __init__(self, version: str, database_url: str):
        self.version = version
        self.database_url = database_url
        self.started = psutil.Process(os.getpid()).create_time()

    def status(self) -> dict[str, Any]:
        root = Path("/")
        disk = psutil.disk_usage(root)
        memory = psutil.virtual_memory()
        return {
            "application_version": self.version,
            "python_version": platform.python_version(),
            "os": platform.platform(),
            "database": self.database_url.split(":", 1)[0],
            "uptime_seconds": max(0, int(time.time() - self.started)),
            "memory": {"total": memory.total, "available": memory.available, "percent": memory.percent},
            "disk": {"total": disk.total, "free": disk.free, "percent": disk.percent},
            "time_utc": datetime.now(timezone.utc).isoformat(),
        }


class JournalService:
    ALLOWED = {"application": "homelab-openldap-manager.service", "ldap": "slapd.service"}

    def read(self, kind: str, lines: int = 200) -> str:
        if kind not in self.ALLOWED:
            raise ValueError("Unsupported log source")
        lines = min(max(lines, 1), 1000)
        completed = subprocess.run(["journalctl", "-u", self.ALLOWED[kind], "-n", str(lines), "--no-pager", "--output=short-iso"], capture_output=True, text=True, timeout=15, check=False, shell=False)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "journalctl failed")
        return completed.stdout
