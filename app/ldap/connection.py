from __future__ import annotations

import ssl
import time
from contextlib import contextmanager
from dataclasses import dataclass
from queue import Empty, Full, LifoQueue
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
    attribute_mapping: dict[str, str] | None = None


class LDAPConnectionManager:
    """Bounded pool of service-account LDAP connections with exclusive checkout per operation."""

    def __init__(self, settings: LDAPSettings, pool_size: int = 5):
        self.settings = settings
        self.pool_size = min(max(pool_size, 1), 32)
        self._server_instance = self._build_server()
        self._pool: LifoQueue[Connection] = LifoQueue(maxsize=self.pool_size)

    def _build_server(self) -> Server:
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

    def _server(self) -> Server:
        return self._server_instance

    def _create_bound_connection(self, user: str, password: str) -> Connection:
        conn = Connection(
            self._server(),
            user=user,
            password=password,
            auto_bind=False,
            receive_timeout=self.settings.connect_timeout,
            raise_exceptions=False,
        )
        conn.open()
        if conn.closed:
            raise LDAPSocketOpenError(str(conn.last_error or "Unable to open LDAP socket"))
        if self.settings.starttls and not conn.server.ssl:
            if not conn.start_tls():
                result = dict(conn.result)
                conn.unbind()
                raise LDAPOperationError("StartTLS failed", result=result)
        if not conn.bind():
            result = dict(conn.result)
            conn.unbind()
            raise LDAPOperationError("LDAP bind failed", result=result)
        return conn

    def _acquire(self) -> Connection:
        try:
            conn = self._pool.get_nowait()
        except Empty:
            return self._create_bound_connection(self.settings.bind_dn, self.settings.bind_password)
        if not conn.bound:
            conn.unbind()
            return self._create_bound_connection(self.settings.bind_dn, self.settings.bind_password)
        return conn

    def _release(self, conn: Connection, reusable: bool) -> None:
        if not reusable or not conn.bound:
            conn.unbind()
            return
        try:
            self._pool.put_nowait(conn)
        except Full:
            conn.unbind()

    @contextmanager
    def connection(self):
        conn: Connection | None = None
        reusable = True
        try:
            conn = self._acquire()
            yield conn
        except LDAPOperationError:
            reusable = False
            raise
        except (LDAPException, OSError) as exc:
            reusable = False
            raise LDAPOperationError(str(exc)) from exc
        finally:
            if conn is not None:
                self._release(conn, reusable)

    def authenticate(self, user_dn: str, password: str) -> bool:
        """Verify end-user credentials without adding that connection to the service-account pool."""
        if not user_dn or not password:
            return False
        conn: Connection | None = None
        try:
            conn = self._create_bound_connection(user_dn, password)
            return bool(conn.bound)
        except (LDAPException, LDAPOperationError, OSError):
            return False
        finally:
            if conn is not None and conn.bound:
                conn.unbind()

    def close(self) -> None:
        while True:
            try:
                conn = self._pool.get_nowait()
            except Empty:
                break
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
                steps.append(
                    {
                        "name": "write_permissions",
                        "ok": None,
                        "detail": "Not inferred from bind. Use the explicit capability write probe to verify add/modify/delete rights.",
                    }
                )
        except Exception as exc:
            steps.append({"name": "connection", "ok": False, "detail": str(exc)})
        return steps
