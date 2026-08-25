from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap.backup import LDAPBackupService
from app.ldap.connection import LDAPConnectionManager
from app.models import LDAPServer, PanelUser
from app.security import encrypt_secret, hash_password
from app.tools import JournalService, LDIFService, PasswordPolicyService, SystemService

router = APIRouter(prefix="/api/v1")
settings = get_settings()
system_service = SystemService(settings.version, settings.database_url)


class LDIFPayload(BaseModel):
    content: str = Field(min_length=1, max_length=16_000_000)
    confirm: bool = False


class RestorePayload(BaseModel):
    filename: str
    confirm: str


class AdminCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=1024)
    role: str = "Read Only"


class AdminUpdate(BaseModel):
    role: str | None = None
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class LDAPSettingsUpdate(BaseModel):
    name: str = "Default"
    url: str
    base_dn: str
    bind_dn: str
    bind_password: str | None = None
    users_base_dn: str | None = None
    groups_base_dn: str | None = None
    starttls: bool = False
    verify_tls: bool = True
    ca_cert: str | None = None
    connect_timeout: int = Field(default=10, ge=1, le=120)


def meta(request: Request, auth: AuthContext) -> dict[str, str | None]:
    return {"request_id": getattr(request.state, "request_id", "unknown"), "panel_user": auth.username, "source_ip": request.client.host if request.client else None}


@router.post("/ldif/preview")
def ldif_preview(payload: LDIFPayload, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> dict[str, Any]:
    return LDIFService(manager).preview(payload.content)


@router.post("/ldif/import")
def ldif_import(payload: LDIFPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, Any]:
    preview = LDIFService(manager).preview(payload.content)
    if not payload.confirm:
        raise HTTPException(status_code=409, detail={"message": "LDIF import requires confirmation", "preview": preview})
    result = LDIFService(manager).apply(payload.content)
    AuditService(db).record(**meta(request, auth), operation="LDIF_IMPORT", status=result["status"], new_value={"create": preview["create"], "modify": preview["modify"], "delete": preview["delete"], "modrdn": preview["modrdn"]})
    return result


@router.get("/ldif/export", response_class=Response)
def ldif_export(base_dn: str | None = None, ldap_filter: str = "(objectClass=*)", manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> Response:
    content = LDIFService(manager).export(base_dn, ldap_filter)
    return Response(content=content, media_type="text/plain", headers={"Content-Disposition": "attachment; filename=ldap-export.ldif"})


@router.get("/backups")
def backups(_: AuthContext = Depends(require_permission("*"))) -> list[dict]:
    return LDAPBackupService().list()


@router.post("/backups", status_code=201)
def create_backup(request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("*"))) -> dict:
    result = LDAPBackupService().create()
    AuditService(db).record(**meta(request, auth), operation="BACKUP_CREATE", status="SUCCESS", new_value=result)
    return result


@router.post("/backups/{filename}/validate", status_code=204)
def validate_backup(filename: str, _: AuthContext = Depends(require_permission("*"))) -> Response:
    LDAPBackupService().validate(filename)
    return Response(status_code=204)


@router.post("/backups/restore")
def restore_backup(payload: RestorePayload, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("*"))) -> dict[str, str]:
    if payload.confirm != f"RESTORE {payload.filename}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal: RESTORE {payload.filename}")
    LDAPBackupService().restore(payload.filename)
    op = AuditService(db).record(**meta(request, auth), operation="BACKUP_RESTORE", status="SUCCESS", new_value={"filename": payload.filename})
    return {"status": "restored", "operation_id": op}


@router.delete("/backups/{filename}", status_code=204)
def delete_backup(filename: str, request: Request, db: Session = Depends(get_db), auth: AuthContext = Depends(require_permission("*"))) -> Response:
    LDAPBackupService().delete(filename)
    AuditService(db).record(**meta(request, auth), operation="BACKUP_DELETE", status="SUCCESS", new_value={"filename": filename})
    return Response(status_code=204)


@router.get("/password-policy")
def password_policy(manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> dict[str, Any]:
    return PasswordPolicyService(manager).detect()


@router.get("/locked-accounts")
def locked_accounts(manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.users.read"))) -> list[dict[str, Any]]:
    return PasswordPolicyService(manager).locked_accounts()


@router.post("/locked-accounts/unlock", status_code=204)
def unlock_account(payload: dict[str, str], request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    dn = payload.get("dn", "")
    if not dn:
        raise HTTPException(status_code=422, detail="dn is required")
    PasswordPolicyService(manager).unlock(dn)
    AuditService(db).record(**meta(request, auth), operation="UNLOCK", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.get("/system")
def system_status(_: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    return system_service.status()


@router.get("/logs/{kind}")
def logs(kind: str, lines: int = 200, _: AuthContext = Depends(require_permission("*"))) -> dict[str, str]:
    return {"source": kind, "content": JournalService().read(kind, lines)}


@router.get("/administrators")
def administrators(db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> list[dict[str, Any]]:
    rows = db.scalars(select(PanelUser).order_by(PanelUser.username)).all()
    return [{"id": row.id, "username": row.username, "role": row.role, "enabled": row.enabled, "theme": row.theme, "created_at": row.created_at, "last_login_at": row.last_login_at} for row in rows]


@router.post("/administrators", status_code=201)
def create_administrator(payload: AdminCreate, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    if payload.role not in {"Administrator", "Operator", "Read Only"}:
        raise HTTPException(status_code=422, detail="Invalid role")
    if db.scalar(select(PanelUser).where(PanelUser.username == payload.username)):
        raise HTTPException(status_code=409, detail="Administrator already exists")
    row = PanelUser(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "username": row.username, "role": row.role, "enabled": row.enabled}


@router.put("/administrators/{user_id}")
def update_administrator(user_id: int, payload: AdminUpdate, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    row = db.get(PanelUser, user_id)
    if not row:
        raise HTTPException(status_code=404, detail="Administrator not found")
    if payload.role is not None:
        if payload.role not in {"Administrator", "Operator", "Read Only"}:
            raise HTTPException(status_code=422, detail="Invalid role")
        row.role = payload.role
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.password:
        row.password_hash = hash_password(payload.password)
    db.commit()
    return {"id": row.id, "username": row.username, "role": row.role, "enabled": row.enabled}


@router.get("/settings/ldap")
def ldap_settings(db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    row = db.scalar(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.id))
    if not row:
        raise HTTPException(status_code=404, detail="LDAP configuration not found")
    return {"id": row.id, "name": row.name, "url": row.url, "base_dn": row.base_dn, "bind_dn": row.bind_dn, "users_base_dn": row.users_base_dn, "groups_base_dn": row.groups_base_dn, "starttls": row.starttls, "verify_tls": row.verify_tls, "ca_cert": row.ca_cert, "connect_timeout": row.connect_timeout, "enabled": row.enabled}


@router.put("/settings/ldap")
def update_ldap_settings(payload: LDAPSettingsUpdate, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    row = db.scalar(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.id))
    if not row:
        raise HTTPException(status_code=404, detail="LDAP configuration not found")
    row.name = payload.name
    row.url = payload.url
    row.base_dn = payload.base_dn
    row.bind_dn = payload.bind_dn
    row.users_base_dn = payload.users_base_dn
    row.groups_base_dn = payload.groups_base_dn
    row.starttls = payload.starttls
    row.verify_tls = payload.verify_tls
    row.ca_cert = payload.ca_cert
    row.connect_timeout = payload.connect_timeout
    if payload.bind_password:
        row.encrypted_bind_password = encrypt_secret(payload.bind_password)
    db.commit()
    return {"id": row.id, "name": row.name, "url": row.url, "base_dn": row.base_dn, "bind_dn": row.bind_dn, "starttls": row.starttls, "verify_tls": row.verify_tls}
