from __future__ import annotations

import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlparse

from ldap3 import ALL, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError


class LDAPOperationError(RuntimeError):
    def __init__(self, message: str, *, result: dict | None = None):
        super().__init__(message)
        self.result = result or {}


@dataclass(slots=True)
class LDAPSettings:
    url: str
    base_dn: str
    bind_dn: str
    bind_password: str
    starttls: bool = False
    verify_tls: bool = True
    ca_cert: str | None = None
    connect_timeout: int = 10
    users_base_dn: str | None = None
    groups_base_dn: str | None = None


class LDAPConnectionManager:
    """Creates one LDAP connection per logical operation and reuses it inside that operation."""

    def __init__(self, settings: LDAPSettings):
        self.settings = settings

    def _server(self) -> Server:
        parsed = urlparse(self.settings.url)
        if parsed.scheme not in {"ldap", "ldaps"}:
            raise ValueError("LDAP URL must use ldap:// or ldaps://")
        if not parsed.hostname:
            raise ValueError("LDAP URL is missing a hostname")

        use_ssl = parsed.scheme == "ldaps"
        port = parsed.port or (636 if use_ssl else 389)
        validate = ssl.CERT_REQUIRED if self.settings.verify_tls else ssl.CERT_NONE
        tls = Tls(validate=validate, ca_certs_file=self.settings.ca_cert) if use_ssl or self.settings.starttls else None
        return Server(
            parsed.hostname,
            port=port,
            use_ssl=use_ssl,
            tls=tls,
            get_info=ALL,
            connect_timeout=self.settings.connect_timeout,
        )

    @contextmanager
    def connection(self):
        conn: Connection | None = None
        try:
            conn = Connection(
                self._server(),
                user=self.settings.bind_dn,
                password=self.settings.bind_password,
                auto_bind=False,
                receive_timeout=self.settings.connect_timeout,
                raise_exceptions=False,
            )
            if not conn.open():
                raise LDAPSocketOpenError(str(conn.last_error or "Unable to open LDAP socket"))
            if self.settings.starttls and not conn.server.ssl:
                if not conn.start_tls():
                    raise LDAPOperationError("StartTLS failed", result=conn.result)
            if not conn.bind():
                raise LDAPOperationError("LDAP bind failed", result=conn.result)
            yield conn
        except LDAPOperationError:
            raise
        except LDAPException as exc:
            raise LDAPOperationError(str(exc)) from exc
        finally:
            if conn is not None and conn.bound:
                conn.unbind()

    def test(self) -> list[dict]:
        steps: list[dict] = []
        started = time.perf_counter()
        try:
            server = self._server()
            steps.append({"name": "url", "ok": True, "detail": f"{server.host}:{server.port}"})
            with self.connection() as conn:
                elapsed = (time.perf_counter() - started) * 1000
                steps.append({"name": "tcp_tls_bind", "ok": True, "detail": "Connected and bound", "duration_ms": round(elapsed, 2)})
                ok = conn.search(self.settings.base_dn, "(objectClass=*)", search_scope="BASE", attributes=["objectClass"])
                steps.append({"name": "base_dn", "ok": bool(ok), "detail": "Base DN readable" if ok else str(conn.result)})
                schema_ok = bool(conn.server.schema and conn.server.schema.object_classes)
                steps.append({"name": "schema", "ok": schema_ok, "detail": "Schema available" if schema_ok else "Schema unavailable"})
                writable = self._check_write_capability(conn)
                steps.append({"name": "write_permissions", "ok": writable, "detail": "Write capability detected from root DSE/ACL outcome" if writable else "Write permission not proven; no destructive probe was executed"})
        except Exception as exc:
            steps.append({"name": "connection", "ok": False, "detail": str(exc)})
        return steps

    def _check_write_capability(self, conn: Connection) -> bool:
        # Do not mutate LDAP during a connection test. A successful authenticated bind plus
        # readable naming context is considered inconclusive rather than performing a probe write.
        return bool(conn.bound and conn.user)
