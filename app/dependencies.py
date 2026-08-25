from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.ldap.connection import LDAPConnectionManager, LDAPSettings
from app.models import APIToken, LDAPServer, PanelUser
from app.security import decrypt_secret, hash_api_token
from app.session_store import active_session

bearer = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS = {
    "Administrator": {"*"},
    "Operator": {"ldap.read", "ldap.users.read", "ldap.users.write", "ldap.groups.read", "ldap.groups.write", "ldap.ou.read", "ldap.ou.write", "ldap.schema.read", "audit.read"},
    "Read Only": {"ldap.read", "ldap.users.read", "ldap.groups.read", "ldap.ou.read", "ldap.schema.read", "audit.read"},
}

_MANAGER_CACHE_TTL = 300.0
_MANAGER_CACHE: dict[tuple, tuple[float, LDAPConnectionManager]] = {}
_MANAGER_CACHE_LOCK = Lock()


@dataclass(slots=True)
class AuthContext:
    username: str
    permissions: set[str]
    role: str = "token"

    def allows(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions or (permission.startswith("ldap.") and "ldap.read" in self.permissions and permission.endswith(".read"))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def get_auth_context(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials:
        token_hash = hash_api_token(credentials.credentials)
        token = db.scalar(select(APIToken).where(APIToken.token_hash == token_hash, APIToken.enabled.is_(True)))
        now = datetime.now(timezone.utc)
        if not token or (token.expires_at and _aware(token.expires_at) < now):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API token")
        token.last_used_at = now
        db.commit()
        return AuthContext(username=f"token:{token.name}", permissions={p.strip() for p in token.permissions.split(",") if p.strip()})

    session_row = active_session(request, db) if hasattr(request, "session") else None
    if session_row:
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            expected = request.session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(supplied, expected):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing or invalid X-CSRF-Token")
        user = db.get(PanelUser, session_row.user_id)
        if user and user.enabled:
            return AuthContext(username=user.username, permissions=ROLE_PERMISSIONS.get(user.role, set()), role=user.role)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_permission(permission: str):
    def dependency(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not auth.allows(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return auth

    return dependency


def _secret_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _cached_manager(key: tuple, ldap_settings: LDAPSettings) -> LDAPConnectionManager:
    now = time.monotonic()
    with _MANAGER_CACHE_LOCK:
        cached = _MANAGER_CACHE.get(key)
        if cached and now - cached[0] < _MANAGER_CACHE_TTL:
            return cached[1]
        expired = [cache_key for cache_key, (created, _) in _MANAGER_CACHE.items() if now - created >= _MANAGER_CACHE_TTL]
        for cache_key in expired:
            _, manager = _MANAGER_CACHE.pop(cache_key)
            manager.close()
        manager = LDAPConnectionManager(ldap_settings)
        _MANAGER_CACHE[key] = (now, manager)
        return manager


def get_ldap_manager(db: Session = Depends(get_db)) -> LDAPConnectionManager:
    settings = get_settings()
    server = db.scalar(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.id.asc()))
    if server:
        bind_password = decrypt_secret(server.encrypted_bind_password)
        ldap_settings = LDAPSettings(
            url=server.url,
            base_dn=server.base_dn,
            bind_dn=server.bind_dn,
            bind_password=bind_password,
            starttls=server.starttls,
            verify_tls=server.verify_tls,
            ca_cert=server.ca_cert,
            connect_timeout=server.connect_timeout,
            users_base_dn=server.users_base_dn,
            groups_base_dn=server.groups_base_dn,
        )
        key = (
            "db",
            server.id,
            server.url,
            server.base_dn,
            server.bind_dn,
            _secret_fingerprint(server.encrypted_bind_password),
            server.starttls,
            server.verify_tls,
            server.ca_cert,
            server.connect_timeout,
            server.users_base_dn,
            server.groups_base_dn,
        )
        return _cached_manager(key, ldap_settings)
    if settings.ldap_url and settings.ldap_base_dn and settings.ldap_bind_dn and settings.ldap_bind_password:
        ldap_settings = LDAPSettings(
            url=settings.ldap_url,
            base_dn=settings.ldap_base_dn,
            bind_dn=settings.ldap_bind_dn,
            bind_password=settings.ldap_bind_password,
            starttls=settings.ldap_starttls,
            verify_tls=settings.ldap_verify_tls,
            ca_cert=settings.ldap_ca_cert,
            connect_timeout=settings.ldap_connect_timeout,
            users_base_dn=settings.users_base_dn,
            groups_base_dn=settings.groups_base_dn,
        )
        key = (
            "env",
            settings.ldap_url,
            settings.ldap_base_dn,
            settings.ldap_bind_dn,
            _secret_fingerprint(settings.ldap_bind_password),
            settings.ldap_starttls,
            settings.ldap_verify_tls,
            settings.ldap_ca_cert,
            settings.ldap_connect_timeout,
            settings.users_base_dn,
            settings.groups_base_dn,
        )
        return _cached_manager(key, ldap_settings)
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP server is not configured")
