from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import AuthContext, require_permission
from app.ldap.connection import LDAPConnectionManager, LDAPSettings
from app.models import LDAPServer
from app.security import decrypt_secret, encrypt_secret

router = APIRouter(prefix="/api/v1/ldap-servers", tags=["LDAP servers"])


class LDAPServerCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=512)
    base_dn: str = Field(min_length=1, max_length=1024)
    bind_dn: str = Field(min_length=1, max_length=1024)
    bind_password: str = Field(min_length=1, max_length=4096)
    users_base_dn: str | None = Field(default=None, max_length=1024)
    groups_base_dn: str | None = Field(default=None, max_length=1024)
    starttls: bool = False
    verify_tls: bool = True
    ca_cert: str | None = None
    connect_timeout: int = Field(default=10, ge=1, le=120)
    enabled: bool = True


class LDAPServerUpdatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=512)
    base_dn: str = Field(min_length=1, max_length=1024)
    bind_dn: str = Field(min_length=1, max_length=1024)
    bind_password: str | None = Field(default=None, max_length=4096)
    users_base_dn: str | None = Field(default=None, max_length=1024)
    groups_base_dn: str | None = Field(default=None, max_length=1024)
    starttls: bool = False
    verify_tls: bool = True
    ca_cert: str | None = None
    connect_timeout: int = Field(default=10, ge=1, le=120)
    enabled: bool = True


def serialize_server(server: LDAPServer) -> dict[str, Any]:
    return {
        "id": server.id,
        "name": server.name,
        "url": server.url,
        "base_dn": server.base_dn,
        "bind_dn": server.bind_dn,
        "users_base_dn": server.users_base_dn,
        "groups_base_dn": server.groups_base_dn,
        "starttls": server.starttls,
        "verify_tls": server.verify_tls,
        "ca_cert_configured": bool(server.ca_cert),
        "connect_timeout": server.connect_timeout,
        "enabled": server.enabled,
        "created_at": server.created_at,
    }


def manager_for_server(server: LDAPServer) -> LDAPConnectionManager:
    return LDAPConnectionManager(
        LDAPSettings(
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
    )


@router.get("/available")
def available_servers(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("ldap.read")),
) -> list[dict[str, Any]]:
    servers = db.scalars(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.name.asc(), LDAPServer.id.asc())).all()
    return [{"id": row.id, "name": row.name, "url": row.url, "base_dn": row.base_dn} for row in servers]


@router.get("")
def list_servers(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> list[dict[str, Any]]:
    servers = db.scalars(select(LDAPServer).order_by(LDAPServer.name.asc(), LDAPServer.id.asc())).all()
    return [serialize_server(row) for row in servers]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_server(
    payload: LDAPServerCreatePayload,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    server = LDAPServer(
        name=payload.name.strip(),
        url=payload.url.strip(),
        base_dn=payload.base_dn.strip(),
        bind_dn=payload.bind_dn.strip(),
        encrypted_bind_password=encrypt_secret(payload.bind_password),
        users_base_dn=(payload.users_base_dn or "").strip() or None,
        groups_base_dn=(payload.groups_base_dn or "").strip() or None,
        starttls=payload.starttls,
        verify_tls=payload.verify_tls,
        ca_cert=(payload.ca_cert or "").strip() or None,
        connect_timeout=payload.connect_timeout,
        enabled=payload.enabled,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return serialize_server(server)


@router.put("/{server_id}")
def update_server(
    server_id: int,
    payload: LDAPServerUpdatePayload,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    server.name = payload.name.strip()
    server.url = payload.url.strip()
    server.base_dn = payload.base_dn.strip()
    server.bind_dn = payload.bind_dn.strip()
    if payload.bind_password:
        server.encrypted_bind_password = encrypt_secret(payload.bind_password)
    server.users_base_dn = (payload.users_base_dn or "").strip() or None
    server.groups_base_dn = (payload.groups_base_dn or "").strip() or None
    server.starttls = payload.starttls
    server.verify_tls = payload.verify_tls
    server.ca_cert = (payload.ca_cert or "").strip() or None
    server.connect_timeout = payload.connect_timeout
    server.enabled = payload.enabled
    db.commit()
    db.refresh(server)
    return serialize_server(server)


@router.post("/{server_id}/test")
def test_server(
    server_id: int,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    manager = manager_for_server(server)
    try:
        steps = manager.test()
    finally:
        manager.close()
    return {"server": serialize_server(server), "ok": all(step.get("ok") for step in steps if step.get("name") != "write_permissions"), "steps": steps}


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(
    server_id: int,
    confirm: bool = Query(False),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> None:
    if not confirm:
        raise HTTPException(status_code=409, detail="Deleting an LDAP server requires confirm=true")
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    db.delete(server)
    db.commit()
