from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager
from app.ldap.backup import LDAPBackupService
from app.models import APIToken, LDAPServer, PanelUser
from app.security import generate_api_token, hash_api_token, hash_password
from app.tools import JournalService, LDIFService, PasswordPolicyService, SystemService
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()
system_service = SystemService(settings.version, settings.database_url)


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def audit_meta(request: Request, user: PanelUser) -> dict[str, str | None]:
    return {"request_id": getattr(request.state, "request_id", "unknown"), "panel_user": user.username, "source_ip": request.client.host if request.client else None}


@router.get("/password-policy", response_class=HTMLResponse)
def password_policy_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    result = PasswordPolicyService(manager).detect()
    return templates.TemplateResponse("password_policy.html", page_context(request, user, result=result))


@router.get("/locked-accounts", response_class=HTMLResponse)
def locked_accounts_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    rows = PasswordPolicyService(manager).locked_accounts()
    return templates.TemplateResponse("locked_accounts.html", page_context(request, user, rows=rows))


@router.post("/locked-accounts/unlock")
def locked_account_unlock(request: Request, dn: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    if user.role == "Read Only":
        raise HTTPException(status_code=403, detail="Read Only role cannot unlock accounts")
    verify_csrf(request, csrf_token)
    PasswordPolicyService(manager).unlock(dn)
    AuditService(db).record(**audit_meta(request, user), operation="UNLOCK", status="SUCCESS", dn=dn)
    return RedirectResponse("/locked-accounts", status_code=303)


@router.get("/ldap-test", response_class=HTMLResponse)
def ldap_test_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    return templates.TemplateResponse("ldap_test.html", page_context(request, user, steps=manager.test(), ldap=manager.settings))


@router.get("/ldif", response_class=HTMLResponse)
def ldif_page(request: Request, db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    return templates.TemplateResponse("ldif.html", page_context(request, user))


@router.post("/ldif/preview", response_class=HTMLResponse)
async def ldif_preview_page(request: Request, csrf_token: str = Form(...), file: UploadFile = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    verify_csrf(request, csrf_token)
    content = (await file.read(16_000_001)).decode("utf-8")
    if len(content) > 16_000_000:
        raise HTTPException(status_code=413, detail="LDIF file too large")
    preview = LDIFService(manager).preview(content)
    return templates.TemplateResponse("ldif.html", page_context(request, user, preview=preview, ldif_content=content))


@router.post("/ldif/import", response_class=HTMLResponse)
def ldif_import_page(request: Request, csrf_token: str = Form(...), ldif_content: str = Form(...), confirm: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    if user.role == "Read Only":
        raise HTTPException(status_code=403, detail="Read Only role cannot import LDIF")
    verify_csrf(request, csrf_token)
    preview = LDIFService(manager).preview(ldif_content)
    if confirm != "IMPORT":
        return templates.TemplateResponse("ldif.html", page_context(request, user, preview=preview, ldif_content=ldif_content, error="Wpisz IMPORT, aby potwierdzić."), status_code=409)
    result = LDIFService(manager).apply(ldif_content)
    AuditService(db).record(**audit_meta(request, user), operation="LDIF_IMPORT", status=result["status"], new_value={"create": preview["create"], "modify": preview["modify"], "delete": preview["delete"], "modrdn": preview["modrdn"]})
    return templates.TemplateResponse("ldif.html", page_context(request, user, result=result))


@router.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    return templates.TemplateResponse("backups.html", page_context(request, user, backups=LDAPBackupService().list()))


@router.post("/backups/create")
def backup_create_page(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    result = LDAPBackupService().create()
    AuditService(db).record(**audit_meta(request, user), operation="BACKUP_CREATE", status="SUCCESS", new_value=result)
    return RedirectResponse("/backups", status_code=303)


@router.post("/backups/delete")
def backup_delete_page(request: Request, filename: str = Form(...), confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    if confirmation != f"DELETE {filename}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE {filename}")
    LDAPBackupService().delete(filename)
    AuditService(db).record(**audit_meta(request, user), operation="BACKUP_DELETE", status="SUCCESS", new_value={"filename": filename})
    return RedirectResponse("/backups", status_code=303)


@router.post("/backups/restore")
def backup_restore_page(request: Request, filename: str = Form(...), confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    if confirmation != f"RESTORE {filename}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal RESTORE {filename}")
    LDAPBackupService().restore(filename)
    AuditService(db).record(**audit_meta(request, user), operation="BACKUP_RESTORE", status="SUCCESS", new_value={"filename": filename})
    return RedirectResponse("/backups", status_code=303)


@router.get("/api-tokens", response_class=HTMLResponse)
def api_tokens_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    rows = db.scalars(select(APIToken).order_by(desc(APIToken.created_at))).all()
    return templates.TemplateResponse("api_tokens.html", page_context(request, user, rows=rows))


@router.post("/api-tokens", response_class=HTMLResponse)
def api_token_create_page(request: Request, name: str = Form(...), permissions: str = Form("ldap.read"), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    token = generate_api_token()
    row = APIToken(name=name, token_prefix=token[:14], token_hash=hash_api_token(token), permissions=permissions)
    db.add(row)
    db.commit()
    rows = db.scalars(select(APIToken).order_by(desc(APIToken.created_at))).all()
    return templates.TemplateResponse("api_tokens.html", page_context(request, user, rows=rows, new_token=token))


@router.post("/api-tokens/revoke")
def api_token_revoke_page(request: Request, token_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    verify_csrf(request, csrf_token)
    row = db.get(APIToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    row.enabled = False
    db.commit()
    return RedirectResponse("/api-tokens", status_code=303)


@router.get("/administrators", response_class=HTMLResponse)
def administrators_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    rows = db.scalars(select(PanelUser).order_by(PanelUser.username)).all()
    return templates.TemplateResponse("administrators.html", page_context(request, user, rows=rows))


@router.post("/administrators")
def administrator_create_page(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    verify_csrf(request, csrf_token)
    if role not in {"Administrator", "Operator", "Read Only"}:
        raise HTTPException(status_code=422, detail="Invalid role")
    if len(password) < 12:
        raise HTTPException(status_code=422, detail="Password must contain at least 12 characters")
    if db.scalar(select(PanelUser).where(PanelUser.username == username)):
        raise HTTPException(status_code=409, detail="Administrator already exists")
    db.add(PanelUser(username=username, password_hash=hash_password(password), role=role))
    db.commit()
    return RedirectResponse("/administrators", status_code=303)


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, source: str = "application", lines: int = 200, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    content = JournalService().read(source, lines)
    return templates.TemplateResponse("logs.html", page_context(request, user, source=source, lines=lines, content=content))


@router.get("/system", response_class=HTMLResponse)
def system_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_admin(request, db)
    system = system_service.status()
    ldap = manager.test()
    return templates.TemplateResponse("system.html", page_context(request, user, system=system, ldap=ldap, ldap_settings=manager.settings))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    ldap = db.scalar(select(LDAPServer).where(LDAPServer.enabled.is_(True)).order_by(LDAPServer.id))
    return templates.TemplateResponse("settings.html", page_context(request, user, ldap=ldap, app_settings=settings))
