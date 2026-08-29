from __future__ import annotations

import hashlib
import json
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
from app.models import APIToken, AppSetting, LDAPServer, PanelUser
from app.security import decrypt_secret, hash_api_token
from app.session_store import active_session

bearer = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS = {
    "Administrator": {"*"},
    "Operator": {
        "ldap.read",
        "ldap.users.read",
        "ldap.users.write",
        "ldap.groups.read",
        "ldap.groups.write",
        "ldap.ou.read",
        "ldap.ou.write",
        "ldap.schema.read",
        "ldap.sudo.read",
        "ldap.sudo.write",
        "ldap.ssh.read",
        "ldap.ssh.write",
        "ldap.lifecycle.read",
        "ldap.lifecycle.write",
        "ldap.ppolicy.read",
        "audit.read",
    },
    "Read Only": {
        "ldap.read",
        "ldap.users.read",
        "ldap.groups.read",
        "ldap.ou.read",
        "ldap.schema.read",
        "ldap.sudo.read",
        "ldap.ssh.read",
        "ldap.lifecycle.read",
        "ldap.ppolicy.read",
        "audit.read",
    },
}

DEFAULT_ATTRIBUTE_MAPPING = {
    "username": "uid",
    "email": "mail",
    "first_name": "givenName",
    "last_name": "sn",
    "display_name": "displayName",
    "uid": "uidNumber",
    "gid": "gidNumber",
}
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


def _attribute_mapping(db: Session) -> dict[str, str]:
    row = db.get(AppSetting, "ldap.attribute_mapping")
    if not row:
        return dict(DEFAULT_ATTRIBUTE_MAPPING)
    try:
        data = json.loads(row.value)
    except json.JSONDecodeError:
        return dict(DEFAULT_ATTRIBUTE_MAPPING)
    if not isinstance(data, dict):
        return dict(DEFAULT_ATTRIBUTE_MAPPING)
    result = dict(DEFAULT_ATTRIBUTE_MAPPING)
    for key in result:
        value = data.get(key)
        if isinstance(value, str) and value:
            result[key] = value
    return result


def _cached_manager(key: tuple, ldap_settings: LDAPSettings, ttl: int) -> LDAPConnectionManager:
    now = time.monotonic()
    with _MANAGER_CACHE_LOCK:
        cached = _MANAGER_CACHE.get(key)
        if cached and now - cached[0] < ttl:
            return cached[1]
        expired = [cache_key for cache_key, (created, _) in _MANAGER_CACHE.items() if now - created >= ttl]
        for cache_key in expired:
            _, manager = _MANAGER_CACHE.pop(cache_key)
            manager.close()
        manager = LDAPConnectionManager(ldap_settings)
        _MANAGER_CACHE[key] = (now, manager)
        return manager


def _requested_server_id(request: Request) -> tuple[int | None, str | None]:
    header_value = request.headers.get("X-LDAP-Server-ID")
    if header_value:
        try:
            server_id = int(header_value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="X-LDAP-Server-ID must be a positive integer") from exc
        if server_id <= 0:
            raise HTTPException(status_code=422, detail="X-LDAP-Server-ID must be a positive integer")
        return server_id, "header"

    if hasattr(request, "session"):
        session_value = request.session.get("ldap_server_id")
        if session_value is not None:
            try:
                server_id = int(session_value)
            except (TypeError, ValueError):
                request.session.pop("ldap_server_id", None)
            else:
                if server_id > 0:
                    return server_id, "session"
                request.session.pop("ldap_server_id", None)
    return None, None


def _selected_db_server(request: Request, db: Session) -> LDAPServer | None:
    requested_id, source = _requested_server_id(request)
    base_query = select(LDAPServer).where(LDAPServer.enabled.is_(True))
    if requested_id is not None:
        server = db.scalar(base_query.where(LDAPServer.id == requested_id))
        if server:
            return server
        if source == "header":
            raise HTTPException(status_code=404, detail="Requested LDAP server does not exist or is disabled")
        if hasattr(request, "session"):
            request.session.pop("ldap_server_id", None)
    return db.scalar(base_query.order_by(LDAPServer.id.asc()))


def get_ldap_manager(request: Request, db: Session = Depends(get_db)) -> LDAPConnectionManager:
    settings = get_settings()
    mapping = _attribute_mapping(db)
    mapping_key = tuple(sorted(mapping.items()))
    server = _selected_db_server(request, db)
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
            attribute_mapping=mapping,
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
            mapping_key,
        )
        return _cached_manager(key, ldap_settings, settings.ldap_cache_ttl)
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
            attribute_mapping=mapping,
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
            mapping_key,
        )
        return _cached_manager(key, ldap_settings, settings.ldap_cache_ttl)
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP server is not configured")
