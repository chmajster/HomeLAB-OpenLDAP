from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.advanced import LDAPEntryService, LDAPMembershipService
from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPUserService
from app.ldap.backup import LDAPBackupService
from app.models import APIToken, AppSetting, PanelSession, PanelUser
from app.security import hash_password
from app.session_store import establish_session
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()
ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9;-]*$")


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def get_setting(db: Session, key: str, default: str) -> str:
    row = db.get(AppSetting, key)
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value, encrypted=False))


def audit_meta(request: Request, user: PanelUser) -> dict[str, str | None]:
    return {"request_id": getattr(request.state, "request_id", "unknown"), "panel_user": user.username, "source_ip": request.client.host if request.client else None}


@router.get("/sessions", response_class=HTMLResponse)
def sessions_page(request: Request, db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    query = select(PanelSession, PanelUser).join(PanelUser, PanelUser.id == PanelSession.user_id).order_by(desc(PanelSession.created_at))
    if user.role != "Administrator":
        query = query.where(PanelSession.user_id == user.id)
    rows = db.execute(query.limit(500)).all()
    current_hash = None
    raw = request.session.get("session_token")
    if raw:
        import hashlib

        current_hash = hashlib.sha256(raw.encode()).hexdigest()
    return templates.TemplateResponse("sessions.html", page_context(request, user, rows=rows, current_hash=current_hash))


@router.post("/sessions/revoke")
def session_revoke(request: Request, session_id: int = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    verify_csrf(request, csrf_token)
    row = db.get(PanelSession, session_id)
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    if user.role != "Administrator" and row.user_id != user.id:
        raise HTTPException(status_code=403, detail="Cannot revoke another user's session")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return RedirectResponse("/sessions", status_code=303)


@router.get("/ldap-login", response_class=HTMLResponse)
def ldap_login_page(request: Request, db: Session = Depends(get_db)):
    if get_setting(db, "auth.ldap_enabled", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="LDAP panel login is disabled")
    return templates.TemplateResponse("ldap_login.html", page_context(request))


@router.post("/ldap-login", response_class=HTMLResponse)
def ldap_login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    verify_csrf(request, csrf_token)
    if get_setting(db, "auth.ldap_enabled", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="LDAP panel login is disabled")
    entry = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not entry or not manager.authenticate(entry["dn"], password):
        return templates.TemplateResponse("ldap_login.html", page_context(request, error="Nieprawidłowy login lub hasło LDAP."), status_code=401)
    existing = db.scalar(select(PanelUser).where(PanelUser.username == username))
    if existing and existing.auth_source != "ldap":
        return templates.TemplateResponse("ldap_login.html", page_context(request, error="Ta nazwa jest zarezerwowana przez lokalne konto panelu."), status_code=409)
    role = get_setting(db, "auth.ldap_default_role", "Read Only")
    if role not in {"Administrator", "Operator", "Read Only"}:
        role = "Read Only"
    user = existing or PanelUser(username=username, password_hash=hash_password(secrets_token()), role=role, auth_source="ldap", ldap_dn=entry["dn"])
    if not existing:
        db.add(user)
        db.commit()
        db.refresh(user)
    user.ldap_dn = entry["dn"]
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    establish_session(request, db, user, settings.session_max_age)
    AuditService(db).record(**audit_meta(request, user), operation="LDAP_PANEL_LOGIN", status="SUCCESS", dn=entry["dn"])
    return RedirectResponse("/dashboard", status_code=303)


def secrets_token() -> str:
    import secrets

    return secrets.token_urlsafe(48)


@router.get("/users/{username}/memberships", response_class=HTMLResponse)
def memberships_page(request: Request, username: str, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    panel_user = require_web_user(request, db)
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    memberships = LDAPMembershipService(manager).groups_for_user(user["dn"], username)
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()
    return templates.TemplateResponse("memberships.html", page_context(request, panel_user, username=username, ldap_user=user, memberships=memberships, groups=groups))


@router.post("/users/{username}/memberships")
def memberships_change(
    request: Request,
    username: str,
    group_dn: str = Form(...),
    operation: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_web_user(request, db)
    if panel_user.role == "Read Only":
        raise HTTPException(status_code=403, detail="Read Only role cannot modify memberships")
    verify_csrf(request, csrf_token)
    if confirmation != "APPLY":
        raise HTTPException(status_code=409, detail="Confirmation must equal APPLY")
    ldap_user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not ldap_user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()
    if group_dn not in {group["dn"] for group in groups}:
        raise HTTPException(status_code=422, detail="Unknown group DN")
    if operation not in {"add", "remove"}:
        raise HTTPException(status_code=422, detail="Invalid membership operation")
    LDAPMembershipService(manager).change(group_dn, ldap_user["dn"], operation == "add")
    AuditService(db).record(**audit_meta(request, panel_user), operation="ADD_TO_GROUP" if operation == "add" else "REMOVE_FROM_GROUP", status="SUCCESS", dn=ldap_user["dn"], new_value={"group_dn": group_dn})
    return RedirectResponse(f"/users/{username}/memberships", status_code=303)


@router.get("/bulk", response_class=HTMLResponse)
def bulk_page(request: Request, db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    return templates.TemplateResponse("bulk.html", page_context(request, user))


@router.post("/bulk", response_class=HTMLResponse)
def bulk_submit(
    request: Request,
    entity_type: str = Form(...),
    items: str = Form(...),
    operation: str = Form(...),
    target_dn: str = Form(""),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_web_user(request, db)
    if user.role == "Read Only":
        raise HTTPException(status_code=403, detail="Read Only role cannot perform bulk operations")
    verify_csrf(request, csrf_token)
    parsed = [item.strip() for item in re.split(r"[\n,]+", items) if item.strip()]
    if not parsed or len(parsed) > 500:
        raise HTTPException(status_code=422, detail="Provide between 1 and 500 items")
    destructive = operation == "delete"
    expected = "BULK DELETE" if destructive else "APPLY"
    if confirmation != expected:
        raise HTTPException(status_code=409, detail=f"Confirmation must equal {expected}")
    results: list[dict[str, str]] = []
    users = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max)
    entries = LDAPEntryService(manager)
    memberships = LDAPMembershipService(manager)
    for item in parsed:
        try:
            if entity_type == "users":
                ldap_user = users.get(item)
                if not ldap_user:
                    raise KeyError(item)
                if operation == "enable":
                    users.enable(item)
                elif operation == "disable":
                    users.disable(item)
                elif operation == "delete":
                    users.delete(item)
                elif operation == "move":
                    if not target_dn:
                        raise ValueError("Target DN is required")
                    entries.move(ldap_user["dn"], target_dn)
                elif operation in {"add_to_group", "remove_from_group"}:
                    if not target_dn:
                        raise ValueError("Group DN is required")
                    memberships.change(target_dn, ldap_user["dn"], operation == "add_to_group")
                else:
                    raise ValueError("Unsupported user operation")
            elif entity_type == "groups":
                group = groups.get(item)
                if not group:
                    raise KeyError(item)
                if operation == "delete":
                    groups.delete(item)
                elif operation == "move":
                    if not target_dn:
                        raise ValueError("Target DN is required")
                    entries.move(group["dn"], target_dn)
                else:
                    raise ValueError("Unsupported group operation")
            else:
                raise ValueError("Unsupported entity type")
            results.append({"item": item, "status": "SUCCESS"})
        except Exception as exc:
            results.append({"item": item, "status": "FAILED", "error": str(exc)})
    failed = sum(1 for result in results if result["status"] == "FAILED")
    AuditService(db).record(**audit_meta(request, user), operation=f"BULK_{entity_type.upper()}_{operation.upper()}", status="PARTIAL" if failed else "SUCCESS", new_value={"count": len(results), "failed": failed})
    return templates.TemplateResponse("bulk.html", page_context(request, user, results=results, entity_type=entity_type, items=items, operation=operation, target_dn=target_dn))


@router.get("/backups/{filename}/download")
def backup_download(request: Request, filename: str, db: Session = Depends(get_db)):
    require_admin(request, db)
    service = LDAPBackupService()
    safe_name = service._validate_name(filename)
    path = service.backup_dir / safe_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path, media_type="text/plain", filename=safe_name)


@router.post("/api-tokens/delete")
def api_token_delete(request: Request, token_id: int = Form(...), confirmation: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    if confirmation != f"DELETE TOKEN {token_id}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE TOKEN {token_id}")
    row = db.get(APIToken, token_id)
    if not row:
        raise HTTPException(status_code=404, detail="Token not found")
    db.delete(row)
    db.commit()
    AuditService(db).record(**audit_meta(request, user), operation="API_TOKEN_DELETE", status="SUCCESS", new_value={"token_id": token_id, "name": row.name})
    return RedirectResponse("/api-tokens", status_code=303)


@router.get("/settings/advanced", response_class=HTMLResponse)
def advanced_settings_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    mapping_default = {"username": "uid", "email": "mail", "first_name": "givenName", "last_name": "sn", "display_name": "displayName", "uid": "uidNumber", "gid": "gidNumber"}
    templates_default = [
        {"name": "Basic User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {}},
        {"name": "Linux User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount"], "defaults": {"loginShell": "/bin/bash"}},
        {"name": "Service Account", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {}},
    ]
    return templates.TemplateResponse(
        "advanced_settings.html",
        page_context(
            request,
            user,
            mapping_json=json.dumps(json.loads(get_setting(db, "ldap.attribute_mapping", json.dumps(mapping_default))), indent=2, ensure_ascii=False),
            templates_json=json.dumps(json.loads(get_setting(db, "ldap.objectclass_templates", json.dumps(templates_default))), indent=2, ensure_ascii=False),
            ldap_login_enabled=get_setting(db, "auth.ldap_enabled", "false").lower() == "true",
            ldap_default_role=get_setting(db, "auth.ldap_default_role", "Read Only"),
        ),
    )


@router.post("/settings/advanced")
def advanced_settings_submit(
    request: Request,
    mapping_json: str = Form(...),
    templates_json: str = Form(...),
    ldap_login_enabled: bool = Form(False),
    ldap_default_role: str = Form("Read Only"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    try:
        mapping = json.loads(mapping_json)
        object_templates = json.loads(templates_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}") from exc
    required = {"username", "email", "first_name", "last_name", "display_name", "uid", "gid"}
    if not isinstance(mapping, dict) or set(mapping) != required or not all(isinstance(value, str) and ATTRIBUTE_RE.fullmatch(value) for value in mapping.values()):
        raise HTTPException(status_code=422, detail="Invalid attribute mapping")
    if not isinstance(object_templates, list) or len(object_templates) > 100:
        raise HTTPException(status_code=422, detail="Invalid ObjectClass templates")
    for item in object_templates:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("object_classes"), list) or not item["object_classes"]:
            raise HTTPException(status_code=422, detail="Invalid ObjectClass template entry")
        if not all(isinstance(value, str) and ATTRIBUTE_RE.fullmatch(value) for value in item["object_classes"]):
            raise HTTPException(status_code=422, detail="Invalid ObjectClass name")
        if not isinstance(item.get("defaults", {}), dict):
            raise HTTPException(status_code=422, detail="Template defaults must be an object")
    if ldap_default_role not in {"Administrator", "Operator", "Read Only"}:
        raise HTTPException(status_code=422, detail="Invalid LDAP default role")
    set_setting(db, "ldap.attribute_mapping", json.dumps(mapping, ensure_ascii=False))
    set_setting(db, "ldap.objectclass_templates", json.dumps(object_templates, ensure_ascii=False))
    set_setting(db, "auth.ldap_enabled", "true" if ldap_login_enabled else "false")
    set_setting(db, "auth.ldap_default_role", ldap_default_role)
    db.commit()
    AuditService(db).record(**audit_meta(request, user), operation="ADVANCED_SETTINGS_UPDATE", status="SUCCESS")
    return RedirectResponse("/settings/advanced", status_code=303)
