from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.database import get_db
from app.models import AccessRole, PanelUser
from app.rbac import PERMISSION_CATALOG, decode_permissions, encode_permissions, list_roles, normalize_permissions
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,127}$")


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def audit_meta(request: Request, user: PanelUser) -> dict[str, str | None]:
    return {"request_id": getattr(request.state, "request_id", "unknown"), "panel_user": user.username, "source_ip": request.client.host if request.client else None}


def render(request: Request, db: Session, user: PanelUser, **extra):
    roles = list_roles(db)
    users = db.scalars(select(PanelUser).order_by(PanelUser.username.asc())).all()
    assigned = dict(db.execute(select(PanelUser.role, func.count(PanelUser.id)).group_by(PanelUser.role)).all())
    return templates.TemplateResponse(
        "roles.html",
        page_context(request, user, roles=roles, users=users, assigned=assigned, permission_catalog=PERMISSION_CATALOG, decode_permissions=decode_permissions, **extra),
    )


def validate_custom_role(name: str, permissions: list[str]) -> tuple[str, set[str]]:
    clean_name = name.strip()
    if not ROLE_NAME_RE.fullmatch(clean_name):
        raise HTTPException(status_code=422, detail="Invalid role name")
    try:
        clean_permissions = normalize_permissions(permissions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "*" in clean_permissions:
        raise HTTPException(status_code=422, detail="Wildcard permission is reserved for Administrator")
    return clean_name, clean_permissions


@router.get("/roles", response_class=HTMLResponse)
def roles_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    return render(request, db, user)


@router.post("/roles/create", response_class=HTMLResponse)
def role_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    permissions: list[str] = Form(default=[]),
    enabled: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    clean_name, clean_permissions = validate_custom_role(name, permissions)
    if db.get(AccessRole, clean_name):
        return render(request, db, user, error="Role already exists." )
    role = AccessRole(name=clean_name, description=description.strip() or None, permissions=encode_permissions(clean_permissions), built_in=False, enabled=enabled)
    db.add(role)
    db.commit()
    AuditService(db).record(**audit_meta(request, user), operation="RBAC_ROLE_CREATE", status="SUCCESS", new_value={"name": role.name, "permissions": sorted(clean_permissions), "enabled": role.enabled})
    return RedirectResponse("/roles", status_code=303)


@router.post("/roles/update", response_class=HTMLResponse)
def role_update(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    permissions: list[str] = Form(default=[]),
    enabled: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    role = db.get(AccessRole, name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.built_in:
        raise HTTPException(status_code=409, detail="Built-in roles are immutable")
    _, clean_permissions = validate_custom_role(role.name, permissions)
    old = {"description": role.description, "permissions": sorted(decode_permissions(role.permissions)), "enabled": role.enabled}
    role.description = description.strip() or None
    role.permissions = encode_permissions(clean_permissions)
    role.enabled = enabled
    db.commit()
    AuditService(db).record(**audit_meta(request, user), operation="RBAC_ROLE_UPDATE", status="SUCCESS", old_value=old, new_value={"description": role.description, "permissions": sorted(clean_permissions), "enabled": role.enabled})
    return RedirectResponse("/roles", status_code=303)


@router.post("/roles/delete")
def role_delete(
    request: Request,
    name: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    if confirmation != f"DELETE ROLE {name}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE ROLE {name}")
    role = db.get(AccessRole, name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.built_in:
        raise HTTPException(status_code=409, detail="Built-in roles cannot be deleted")
    assigned = db.scalar(select(func.count(PanelUser.id)).where(PanelUser.role == name)) or 0
    if assigned:
        raise HTTPException(status_code=409, detail="Role is assigned to panel users")
    snapshot = {"name": role.name, "permissions": sorted(decode_permissions(role.permissions))}
    db.delete(role)
    db.commit()
    AuditService(db).record(**audit_meta(request, user), operation="RBAC_ROLE_DELETE", status="SUCCESS", old_value=snapshot)
    return RedirectResponse("/roles", status_code=303)


@router.post("/roles/assign")
def role_assign(
    request: Request,
    user_id: int = Form(...),
    role_name: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = require_admin(request, db)
    verify_csrf(request, csrf_token)
    panel_user = db.get(PanelUser, user_id)
    role = db.get(AccessRole, role_name)
    if not panel_user:
        raise HTTPException(status_code=404, detail="Panel user not found")
    if not role or not role.enabled:
        raise HTTPException(status_code=422, detail="Role does not exist or is disabled")
    if panel_user.id == admin.id and role.name != "Administrator":
        raise HTTPException(status_code=409, detail="Administrator cannot remove their own Administrator role")
    old_role = panel_user.role
    panel_user.role = role.name
    db.commit()
    AuditService(db).record(**audit_meta(request, admin), operation="RBAC_ROLE_ASSIGN", status="SUCCESS", dn=f"panel-user:{panel_user.id}", old_value={"role": old_role}, new_value={"role": role.name})
    return RedirectResponse("/roles", status_code=303)
