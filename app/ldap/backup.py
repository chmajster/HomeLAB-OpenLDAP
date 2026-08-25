from __future__ import annotations

import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class LDAPBackupService:
    NAME_RE = re.compile(r"^ldap-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.ldif$")

    def __init__(self, backup_dir: str = "/var/backups/homelab-openldap-manager", helper: str = "/usr/local/libexec/homelab-openldap-backup"):
        self.backup_dir = Path(backup_dir)
        self.helper = helper

    def _validate_name(self, name: str) -> str:
        if not self.NAME_RE.fullmatch(name):
            raise ValueError("Invalid backup filename")
        return name

    def _run(self, action: str, name: str) -> None:
        if action not in {"create", "validate", "restore"}:
            raise ValueError("Unsupported backup action")
        name = self._validate_name(name)
        completed = subprocess.run(["sudo", self.helper, action, name], capture_output=True, text=True, timeout=600, check=False, shell=False)
        if completed.returncode != 0:
            raise RuntimeError(f"Backup helper failed ({completed.returncode}): {completed.stderr.strip()}")

    def create(self) -> dict:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"ldap-{stamp}-{secrets.token_hex(4)}.ldif"
        self._run("create", name)
        path = self.backup_dir / name
        return {"filename": name, "size": path.stat().st_size if path.exists() else None, "status": "created"}

    def list(self) -> list[dict]:
        if not self.backup_dir.exists():
            return []
        rows = []
        for path in sorted(self.backup_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if path.is_file() and self.NAME_RE.fullmatch(path.name):
                rows.append({"filename": path.name, "size": path.stat().st_size, "modified": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()})
        return rows

    def validate(self, name: str) -> None:
        self._run("validate", name)

    def restore(self, name: str) -> None:
        self._run("restore", name)

    def delete(self, name: str) -> None:
        name = self._validate_name(name)
        path = self.backup_dir / name
        if path.is_file():
            path.unlink()
