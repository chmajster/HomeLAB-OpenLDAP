from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.advanced import LDAPEntryService, LDAPQueryBuilder, encode_dn
from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPOUService, LDAPUserService
from app.models import AppSetting
from app.rbac import user_allows
from app.schemas import GroupCreate, UserCreate
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()

DEFAULT_OBJECTCLASS_TEMPLATES = [
    {"name": "Basic User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {}},
    {"name": "Linux User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount"], "defaults": {"loginShell": "/bin/bash"}},
    {"name": "Service Account", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {"description": "Service account"}},
]


def require_write(request: Request, db: Session, permission: str):
    user = require_web_user(request, db)
    if not user_allows(db, user, permission):
        raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
    return user


def audit_meta(request: Request, user) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": user.username,
        "source_ip": request.client.host if request.client else None,
    }


def objectclass_templates(db: Session) -> list[dict]:
    row = db.get(AppSetting, "ldap.objectclass_templates")
    if not row:
        return DEFAULT_OBJECTCLASS_TEMPLATES
    try:
        data = json.loads(row.value)
    except json.JSONDecodeError:
        return DEFAULT_OBJECTCLASS_TEMPLATES
    return data if isinstance(data, list) and data else DEFAULT_OBJECTCLASS_TEMPLATES


def selected_template(db: Session, name: str) -> dict:
    for item in objectclass_templates(db):
        if item.get("name") == name:
            return item
    raise HTTPException(status_code=422, detail="Unknown ObjectClass template")


@router.get("/directory/users/create", response_class=HTMLResponse)
def create_user_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.users.write")
    ous = LDAPOUService(manager).list()
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()
    return templates.TemplateResponse(
        "user_create.html",
        page_context(
            request,
            user,
            ous=ous,
            groups=groups,
            objectclass_templates=objectclass_templates(db),
            uid_min=settings.uid_min,
            uid_max=settings.uid_max,
        ),
    )


@router.post("/directory/users/create", response_class=HTMLResponse)
def create_user_submit(
    request: Request,
    csrf_token: str = Form(...),
    username: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(...),
    gid_number: int = Form(...),
    home_directory: str = Form(""),
    login_shell: str = Form(""),
    organizational_unit: str = Form(""),
    template_name: str = Form("Linux User"),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db, "ldap.users.write")
    verify_csrf(request, csrf_token)
    template = selected_template(db, template_name)
    defaults = dict(template.get("defaults") or {})
    configured_home = home_directory or str(defaults.pop("homeDirectory", "") or "")
    if configured_home:
        configured_home = configured_home.replace("{username}", username)
    configured_shell = login_shell or str(defaults.pop("loginShell", "") or "/bin/bash")
    payload = UserCreate(
        username=username,
        first_name=first_name,
        last_name=last_name,
        display_name=display_name or None,
        email=email or None,
        password=password,
        gid_number=gid_number,
        home_directory=configured_home or None,
        login_shell=configured_shell,
        organizational_unit=organizational_unit or None,
        object_classes=list(template.get("object_classes") or []),
        attributes=defaults,
    )
    result = LDAPUserService(manager, settings.uid_min, settings.uid_max).create(payload.model_dump())
    audit_value = {key: value for key, value in payload.model_dump().items() if key != "password"}
    audit_value["template"] = template_name
    AuditService(db).record(**audit_meta(request, panel_user), operation="ADD_SERVICE_ACCOUNT" if template_name == "Service Account" else "ADD", status="SUCCESS", dn=result["dn"], new_value=audit_value)
    return RedirectResponse(f"/users/{username}", status_code=303)


@router.post("/users/{username}/action")
def user_action(
    username: str,
    request: Request,
    csrf_token: str = Form(...),
    action: str = Form(...),
    password: str = Form(""),
    confirmation: str = Form(""),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db, "ldap.users.write")
    verify_csrf(request, csrf_token)
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    entry = service.get(username)
    if not entry:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    if action == "disable":
        service.disable(username)
        operation = "DISABLE"
    elif action == "enable":
        service.enable(username)
        operation = "ENABLE"
    elif action == "reset_password":
        if len(password) < 8:
            raise HTTPException(status_code=422, detail="Password must contain at least 8 characters")
        service.reset_password(username, password)
        operation = "PASSWORD_RESET"
    elif action == "delete":
        if confirmation != f"DELETE {username}":
            raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE {username}")
        service.delete(username)
        operation = "PERMANENT_DELETE"
    else:
        raise HTTPException(status_code=422, detail="Unsupported action")
    AuditService(db).record(**audit_meta(request, panel_user), operation=operation, status="SUCCESS", dn=entry["dn"], attribute="userPassword" if action == "reset_password" else None, new_value="[REDACTED]" if action == "reset_password" else None)
    return RedirectResponse("/users" if action == "delete" else f"/users/{username}", status_code=303)


@router.get("/directory/groups/create", response_class=HTMLResponse)
def create_group_page(request: Request, db: Session = Depends(get_db)):
    user = require_write(request, db, "ldap.groups.write")
    return templates.TemplateResponse("group_create.html", page_context(request, user))


@router.post("/directory/groups/create")
def create_group_submit(
    request: Request,
    csrf_token: str = Form(...),
    name: str = Form(...),
    group_type: str = Form("groupOfNames"),
    gid_number: int | None = Form(None),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_write(request, db, "ldap.groups.write")
    verify_csrf(request, csrf_token)
    payload = GroupCreate(name=name, group_type=group_type, gid_number=gid_number)
    result = LDAPGroupService(manager, settings.gid_min, settings.gid_max).create(payload.model_dump())
    AuditService(db).record(**audit_meta(request, user), operation="ADD_GROUP", status="SUCCESS", dn=result["dn"], new_value=payload.model_dump())
    return RedirectResponse(f"/groups/{name}", status_code=303)


@router.post("/groups/{name}/delete")
def delete_group_submit(name: str, request: Request, csrf_token: str = Form(...), confirmation: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.groups.write")
    verify_csrf(request, csrf_token)
    if confirmation != f"DELETE {name}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE {name}")
    dn = LDAPGroupService(manager, settings.gid_min, settings.gid_max).delete(name)
    AuditService(db).record(**audit_meta(request, user), operation="DELETE_GROUP", status="SUCCESS", dn=dn)
    return RedirectResponse("/groups", status_code=303)


@router.get("/ous", response_class=HTMLResponse)
def ous_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    rows = LDAPOUService(manager).list()
    return templates.TemplateResponse("ous.html", page_context(request, user, rows=rows, base_dn=manager.settings.base_dn))


@router.post("/ous/create")
def create_ou_submit(request: Request, csrf_token: str = Form(...), name: str = Form(...), parent_dn: str = Form(""), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.ou.write")
    verify_csrf(request, csrf_token)
    result = LDAPOUService(manager).create(name, parent_dn or None)
    AuditService(db).record(**audit_meta(request, user), operation="ADD_OU", status="SUCCESS", dn=result["dn"])
    return RedirectResponse("/ous", status_code=303)


@router.post("/ous/delete")
def delete_ou_submit(request: Request, csrf_token: str = Form(...), dn: str = Form(...), confirmation: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.ou.write")
    verify_csrf(request, csrf_token)
    if confirmation != f"DELETE {dn}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE {dn}")
    LDAPOUService(manager).delete(dn)
    AuditService(db).record(**audit_meta(request, user), operation="DELETE_OU", status="SUCCESS", dn=dn)
    return RedirectResponse("/ous", status_code=303)


@router.post("/ous/move")
def move_ou_submit(request: Request, csrf_token: str = Form(...), dn: str = Form(...), new_parent_dn: str = Form(...), new_name: str = Form(""), confirmation: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.ou.write")
    verify_csrf(request, csrf_token)
    if confirmation != "MOVE":
        raise HTTPException(status_code=409, detail="Confirmation must equal MOVE")
    new_rdn = f"ou={new_name}" if new_name else None
    new_dn = LDAPEntryService(manager).move(dn, new_parent_dn, new_rdn)
    AuditService(db).record(**audit_meta(request, user), operation="MOVE_OU", status="SUCCESS", dn=dn, old_value=dn, new_value=new_dn)
    return RedirectResponse("/ous", status_code=303)


@router.get("/directory/entry/{encoded_dn}", response_class=HTMLResponse)
def advanced_entry_page(encoded_dn: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    service = LDAPEntryService(manager)
    from app.advanced import decode_dn

    dn = decode_dn(encoded_dn)
    entry = service.get(dn)
    if not entry:
        raise HTTPException(status_code=404, detail="LDAP entry not found")
    children = service.children(dn)
    editable = {key: value for key, value in entry.items() if key not in {"dn", "userPassword"}}
    return templates.TemplateResponse("advanced_entry.html", page_context(request, user, entry=entry, editable_json=json.dumps(editable, indent=2, ensure_ascii=False, default=str), encoded_dn=encoded_dn, children=children, encode_dn=encode_dn))


@router.post("/directory/entry/{encoded_dn}/modify")
def advanced_entry_modify(encoded_dn: str, request: Request, csrf_token: str = Form(...), attributes_json: str = Form(...), confirmation: str = Form(...), db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_write(request, db, "ldap.users.write")
    verify_csrf(request, csrf_token)
    if confirmation != "MODIFY":
        raise HTTPException(status_code=409, detail="Confirmation must equal MODIFY")
    from app.advanced import decode_dn

    dn = decode_dn(encoded_dn)
    try:
        attributes = json.loads(attributes_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON: {exc}") from exc
    if not isinstance(attributes, dict):
        raise HTTPException(status_code=422, detail="Attributes must be a JSON object")
    service = LDAPEntryService(manager)
    before = service.get(dn)
    diff = service.preview(dn, attributes)
    result = service.modify(dn, attributes)
    AuditService(db).record(**audit_meta(request, user), operation="MODIFY_ENTRY", status="SUCCESS", dn=dn, old_value=before, new_value=result)
    return templates.TemplateResponse("advanced_entry_result.html", page_context(request, user, entry=result, diff=diff, encoded_dn=encoded_dn))


@router.get("/query-builder", response_class=HTMLResponse)
def query_builder_page(request: Request, db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    return templates.TemplateResponse("query_builder.html", page_context(request, user))


@router.post("/query-builder", response_class=HTMLResponse)
def query_builder_submit(request: Request, csrf_token: str = Form(...), attribute: str = Form(...), operator: str = Form(...), value: str = Form(""), logical: str = Form("AND"), db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    verify_csrf(request, csrf_token)
    condition = LDAPQueryBuilder.condition(attribute, operator, value)
    ldap_filter = LDAPQueryBuilder.combine(logical, [condition]) if logical == "NOT" else condition
    return templates.TemplateResponse("query_builder.html", page_context(request, user, ldap_filter=ldap_filter, attribute=attribute, operator=operator, value=value, logical=logical))


@router.post("/appearance")
def appearance(request: Request, csrf_token: str = Form(...), theme: str = Form(...), db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    verify_csrf(request, csrf_token)
    if theme not in {"light", "dark", "system"}:
        raise HTTPException(status_code=422, detail="Invalid theme")
    user.theme = theme
    db.commit()
    target = request.headers.get("Referer", "/dashboard")
    return RedirectResponse(target, status_code=303)
