from __future__ import annotations

import re
import shlex
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ldap3 import BASE, SUBTREE, Connection, Server, Tls

from app.ldap.connection import LDAPConnectionManager
from app.ldap.services import _ensure_success, _entry_to_dict

_CSN_RE = re.compile(r"^(\d{14})(?:\.\d+)?Z#")
_SECRET_RE = re.compile(r"(?i)((?:bind)?credentials=)(?:\"[^\"]*\"|'[^']*'|\S+)")


class LDAPReplicationMonitorService:
    """Inspect syncrepl configuration and compare local/provider contextCSN state."""

    def __init__(self, manager: LDAPConnectionManager):
        self.manager = manager

    @staticmethod
    def redact(value: str) -> str:
        return _SECRET_RE.sub(r"\1***", value)

    @staticmethod
    def parse_syncrepl(value: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for token in shlex.split(value):
            if "=" not in token:
                continue
            key, raw = token.split("=", 1)
            result[key.lower()] = raw
        return result

    @staticmethod
    def _csn_timestamp(value: str) -> datetime | None:
        match = _CSN_RE.match(value)
        if not match:
            return None
        try:
            return datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @classmethod
    def newest_csn_timestamp(cls, values: list[str]) -> datetime | None:
        parsed = [stamp for value in values if (stamp := cls._csn_timestamp(str(value))) is not None]
        return max(parsed) if parsed else None

    @staticmethod
    def classify(*, connected: bool, lag_seconds: float | None, configured: bool = True) -> str:
        if not configured:
            return "not_configured"
        if not connected:
            return "disconnected"
        if lag_seconds is None:
            return "unknown"
        if lag_seconds <= 30:
            return "healthy"
        if lag_seconds <= 300:
            return "lagging"
        return "critical"

    def _context_csn(self, conn: Connection, base_dn: str) -> list[str]:
        ok = conn.search(base_dn, "(objectClass=*)", BASE, attributes=["contextCSN"], size_limit=1)
        if not ok and conn.result.get("result") != 0:
            _ensure_success(conn, "SEARCH contextCSN")
        if not conn.entries:
            return []
        entry = _entry_to_dict(conn.entries[0])
        raw = entry.get("contextCSN") or entry.get("contextcsn") or []
        if isinstance(raw, list):
            return [str(item) for item in raw]
        return [str(raw)] if raw else []

    def local_context_csn(self, base_dn: str) -> list[str]:
        with self.manager.connection() as conn:
            return self._context_csn(conn, base_dn)

    def provider_context_csn(self, definition: dict[str, str]) -> tuple[list[str], float]:
        provider = definition.get("provider", "")
        parsed = urlparse(provider)
        if parsed.scheme not in {"ldap", "ldaps"} or not parsed.hostname:
            raise ValueError("Invalid syncrepl provider URL")
        use_ssl = parsed.scheme == "ldaps"
        port = parsed.port or (636 if use_ssl else 389)
        reqcert = definition.get("tls_reqcert", "demand").lower()
        validate = ssl.CERT_NONE if reqcert in {"never", "allow", "try"} else ssl.CERT_REQUIRED
        tls = Tls(validate=validate)
        server = Server(parsed.hostname, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=self.manager.settings.connect_timeout)
        conn = Connection(
            server,
            user=definition.get("binddn"),
            password=definition.get("credentials") or definition.get("bindcredentials"),
            auto_bind=False,
            receive_timeout=self.manager.settings.connect_timeout,
            raise_exceptions=False,
        )
        started = time.perf_counter()
        try:
            conn.open()
            if conn.closed:
                raise RuntimeError(str(conn.last_error or "Unable to open provider socket"))
            if definition.get("starttls", "").lower() in {"yes", "true", "critical"} and not use_ssl:
                if not conn.start_tls():
                    raise RuntimeError(str(conn.result))
            if not conn.bind():
                raise RuntimeError(str(conn.result))
            values = self._context_csn(conn, definition.get("searchbase") or self.manager.settings.base_dn)
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            return values, latency_ms
        finally:
            if conn.bound:
                conn.unbind()

    def status(self) -> list[dict[str, Any]]:
        with self.manager.connection() as conn:
            conn.search(
                "cn=config",
                "(objectClass=olcDatabaseConfig)",
                SUBTREE,
                attributes=["olcDatabase", "olcSuffix", "olcSyncRepl", "olcMirrorMode"],
            )
            _ensure_success(conn, "SEARCH replication configuration")
            databases = [_entry_to_dict(entry) for entry in conn.entries]

        results: list[dict[str, Any]] = []
        for database in databases:
            raw_definitions = database.get("olcSyncRepl") or []
            if not isinstance(raw_definitions, list):
                raw_definitions = [raw_definitions]
            for raw in raw_definitions:
                raw_value = str(raw)
                definition = self.parse_syncrepl(raw_value)
                searchbase = definition.get("searchbase") or str(database.get("olcSuffix") or self.manager.settings.base_dn)
                item: dict[str, Any] = {
                    "database_dn": database.get("dn"),
                    "database": database.get("olcDatabase"),
                    "suffix": database.get("olcSuffix"),
                    "mirror_mode": database.get("olcMirrorMode"),
                    "rid": definition.get("rid"),
                    "provider": definition.get("provider"),
                    "searchbase": searchbase,
                    "definition": self.redact(raw_value),
                    "connected": False,
                    "status": "unknown",
                    "lag_seconds": None,
                    "provider_latency_ms": None,
                    "local_context_csn": [],
                    "provider_context_csn": [],
                    "error": None,
                }
                try:
                    local_values = self.local_context_csn(searchbase)
                    provider_values, latency_ms = self.provider_context_csn(definition)
                    local_stamp = self.newest_csn_timestamp(local_values)
                    provider_stamp = self.newest_csn_timestamp(provider_values)
                    lag = None
                    if local_stamp and provider_stamp:
                        lag = max(0.0, (provider_stamp - local_stamp).total_seconds())
                    item.update(
                        connected=True,
                        lag_seconds=lag,
                        provider_latency_ms=latency_ms,
                        local_context_csn=local_values,
                        provider_context_csn=provider_values,
                        status=self.classify(connected=True, lag_seconds=lag),
                    )
                except Exception as exc:
                    item["status"] = self.classify(connected=False, lag_seconds=None)
                    item["error"] = str(exc)
                results.append(item)
        return results
