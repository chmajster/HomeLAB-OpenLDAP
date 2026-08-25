from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.ldap.connection import LDAPConnectionManager, LDAPSettings
from app.models import APIToken, LDAPServer, PanelUser
from app.security import decrypt_secret, hash_api_token

bearer = HTTPBearer(auto_error=False)

ROLE_PERMISSIONS = {
    "Administrator": {"*"},
    "Operator": {"ldap.read", "ldap.users.read", "ldap.users.write", "ldap.groups.read", "ldap.groups.write", "ldap.ou.read", "ldap.ou.write", "ldap.schema.read", "audit.read"},
    "Read Only": {"ldap.read", "ldap.users.read", "ldap.groups.read", "ldap.ou.read", "ldap.schema.read", "audit.read"},
}


@dataclass(slots=True)
class AuthContext:
    username: str
    permissions: set[str]
    role: str = "token"

    def allows(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions or (permission.startswith("ldap.") and "ldap.read" in self.permissions and permission.endswith(".read"))


def get_auth_context(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials:
        token_hash = hash_api_token(credentials.credentials)
        token = db.scalar(select(APIToken).where(APIToken.token_hash == token_hash, APIToken.enabled.is_(True)))
        now = datetime.now(timezone.utc)
        if not token or (token.expires_at and token.expires_at < now):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired API token")
        token.last_used_at = now
        db.commit()
        return AuthContext(username=f"token:{token.name}", permissions={p.strip() for p in token.permissions.split(",") if p.strip()})

    user_id = request.session.get("user_id") if hasattr(request, "session") else None
    if user_id:
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            expected = request.session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(supplied, expected):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing or invalid X-CSRF-Token")
        user = db.get(PanelUser, user_id)
        if user and user.enabled:
            return AuthContext(username=user.username, permissions=ROLE_PERMISSIONS.get(user.role, set()), role=user.role)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def require_permission(permission: str):
    def dependency(auth: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not auth.allows(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return auth
    return dependency


def get_ldap_manager(db: Session = Depends(get_db)) -> LDAPConnectionManager:
    settings = get_settings()
    server = db.scalar(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.id.asc()))
    if server:
        ldap_settings = LDAPSettings(
            url=server.url,
            base_dn=server.base_dn,
            bind_dn=server.bind_dn,
            bind_password=decrypt_secret(server.encrypted_bind_password),
            starttls=server.starttls,
            verify_tls=server.verify_tls,
            ca_cert=server.ca_cert,
            connect_timeout=server.connect_timeout,
            users_base_dn=server.users_base_dn,
            groups_base_dn=server.groups_base_dn,
        )
        return LDAPConnectionManager(ldap_settings)
    if settings.ldap_url and settings.ldap_base_dn and settings.ldap_bind_dn and settings.ldap_bind_password:
        return LDAPConnectionManager(LDAPSettings(
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
        ))
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="LDAP server is not configured")
