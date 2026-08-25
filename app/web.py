from __future__ import annotations

import secrets
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPHealthService, LDAPOUService, LDAPSchemaService, LDAPSearchService, LDAPUserService
from app.ldap.connection import LDAPSettings
from app.models import AuditLog, LDAPServer, PanelUser
from app.security import encrypt_secret, generate_csrf_token, hash_password, verify_password

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()


def csrf(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = generate_csrf_token()
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, supplied: str) -> None:
    expected = request.session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def current_user(request: Request, db: Session) -> PanelUser | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    user = db.get(PanelUser, user_id)
    return user if user and user.enabled else None


def require_web_user(request: Request, db: Session) -> PanelUser:
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def page_context(request: Request, user: PanelUser | None = None, **extra):
    return {"request": request, "user": user, "csrf_token": csrf(request), "app_name": settings.app_name, "version": settings.version, **extra}


@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if db.scalar(select(func.count(PanelUser.id))) == 0:
        return RedirectResponse("/setup", status_code=303)
    if not current_user(request, db):
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)):
    if db.scalar(select(func.count(PanelUser.id))) > 0:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("setup.html", page_context(request, step=1))


@router.post("/setup", response_class=HTMLResponse)
def setup_submit(
    request: Request,
    csrf_token: str = Form(...),
    ldap_url: str = Form(...),
    base_dn: str = Form(...),
    bind_dn: str = Form(...),
    bind_password: str = Form(...),
    starttls: bool = Form(False),
    verify_tls: bool = Form(False),
    users_base_dn: str = Form(""),
    groups_base_dn: str = Form(""),
    admin_user: str = Form(...),
    admin_password: str = Form(...),
    db: Session = Depends(get_db),
):
    if db.scalar(select(func.count(PanelUser.id))) > 0:
        raise HTTPException(status_code=409, detail="Setup already completed")
    verify_csrf(request, csrf_token)
    if len(admin_password) < 12:
        return templates.TemplateResponse("setup.html", page_context(request, error="Hasło administratora musi mieć co najmniej 12 znaków."), status_code=422)
    manager = LDAPConnectionManager(LDAPSettings(url=ldap_url, base_dn=base_dn, bind_dn=bind_dn, bind_password=bind_password, starttls=starttls, verify_tls=verify_tls))
    test = manager.test()
    connection_ok = all(s["ok"] for s in test if s["name"] != "write_permissions")
    if not connection_ok:
        return templates.TemplateResponse("setup.html", page_context(request, error="Test LDAP nie powiódł się.", test_steps=test), status_code=422)
    server = LDAPServer(name="Default", url=ldap_url, base_dn=base_dn, bind_dn=bind_dn, encrypted_bind_password=encrypt_secret(bind_password), users_base_dn=users_base_dn or None, groups_base_dn=groups_base_dn or None, starttls=starttls, verify_tls=verify_tls)
    admin = PanelUser(username=admin_user, password_hash=hash_password(admin_password), role="Administrator")
    db.add_all([server, admin])
    db.commit()
    db.refresh(admin)
    request.session["user_id"] = admin.id
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if current_user(request, db):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse("login.html", page_context(request))


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    user = db.scalar(select(PanelUser).where(PanelUser.username == username))
    if not user or not user.enabled or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", page_context(request, error="Nieprawidłowy login lub hasło."), status_code=401)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["csrf_token"] = generate_csrf_token()
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    health = LDAPHealthService(manager).check()
    users = LDAPUserService(manager, settings.uid_min, settings.uid_max).list(page_size=1)
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()
    ous = LDAPOUService(manager).list()
    audit = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(10)).all()
    return templates.TemplateResponse("dashboard.html", page_context(request, user, health=health, user_count_hint=len(users["items"]), group_count=len(groups), ou_count=len(ous), audit=audit, ldap=manager.settings))


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, q: str | None = None, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    result = LDAPUserService(manager, settings.uid_min, settings.uid_max).list(search=q, page_size=100)
    return templates.TemplateResponse("users.html", page_context(request, user, users=result["items"], q=q or ""))


@router.get("/users/{username}", response_class=HTMLResponse)
def user_details(username: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    panel_user = require_web_user(request, db)
    entry = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not entry:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    audit = db.scalars(select(AuditLog).where(AuditLog.dn == entry["dn"]).order_by(desc(AuditLog.created_at)).limit(50)).all()
    return templates.TemplateResponse("entry.html", page_context(request, panel_user, title=username, entry=entry, audit=audit, kind="User"))


@router.get("/groups", response_class=HTMLResponse)
def groups_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()
    return templates.TemplateResponse("groups.html", page_context(request, user, groups=groups))


@router.get("/groups/{name}", response_class=HTMLResponse)
def group_details(name: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    panel_user = require_web_user(request, db)
    entry = LDAPGroupService(manager, settings.gid_min, settings.gid_max).get(name)
    if not entry:
        raise HTTPException(status_code=404, detail="LDAP group not found")
    audit = db.scalars(select(AuditLog).where(AuditLog.dn == entry["dn"]).order_by(desc(AuditLog.created_at)).limit(50)).all()
    return templates.TemplateResponse("entry.html", page_context(request, panel_user, title=name, entry=entry, audit=audit, kind="Group"))


@router.get("/directory", response_class=HTMLResponse)
def directory(request: Request, dn: str | None = None, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    base = dn or manager.settings.base_dn
    children = LDAPSearchService(manager).search(base_dn=base, ldap_filter="(objectClass=*)", scope="LEVEL", attributes=["objectClass", "ou", "uid", "cn"], size_limit=500)
    entry = LDAPSearchService(manager).search(base_dn=base, ldap_filter="(objectClass=*)", scope="BASE", attributes=["*", "+"], size_limit=1)
    return templates.TemplateResponse("directory.html", page_context(request, user, dn=base, entry=entry[0] if entry else None, children=children, quote=quote))


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, ldap_filter: str = "(objectClass=*)", base_dn: str | None = None, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    results = LDAPSearchService(manager).search(base_dn=base_dn, ldap_filter=ldap_filter, attributes=["*"], size_limit=200) if ldap_filter else []
    return templates.TemplateResponse("search.html", page_context(request, user, results=results, ldap_filter=ldap_filter, base_dn=base_dn or manager.settings.base_dn))


@router.get("/schema", response_class=HTMLResponse)
def schema_page(request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager)):
    user = require_web_user(request, db)
    schema = LDAPSchemaService(manager).get()
    return templates.TemplateResponse("schema.html", page_context(request, user, schema=schema))


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db)):
    user = require_web_user(request, db)
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(500)).all()
    return templates.TemplateResponse("audit.html", page_context(request, user, rows=rows))
