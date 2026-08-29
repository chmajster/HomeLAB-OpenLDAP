from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.ldap.connection import LDAPConnectionManager, LDAPSettings
from app.models import LDAPServer, PanelUser
from app.security import decrypt_secret, encrypt_secret
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def _safe_next(value: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        return "/dashboard"
    return value


def _manager(server: LDAPServer) -> LDAPConnectionManager:
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


def _render_servers(request: Request, db: Session, user: PanelUser, **extra):
    servers = db.scalars(select(LDAPServer).order_by(LDAPServer.name.asc(), LDAPServer.id.asc())).all()
    return templates.TemplateResponse("ldap_servers.html", page_context(request, user, servers=servers, **extra))


@router.post("/ldap-servers/select")
def select_ldap_server(
    request: Request,
    server_id: int = Form(...),
    next_url: str = Form("/dashboard"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_web_user(request, db)
    verify_csrf(request, csrf_token)
    server = db.scalar(select(LDAPServer).where(LDAPServer.id == server_id, LDAPServer.enabled.is_(True)))
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found or disabled")
    request.session["ldap_server_id"] = server.id
    return RedirectResponse(_safe_next(next_url), status_code=303)


@router.get("/ldap-servers", response_class=HTMLResponse)
def ldap_servers_page(request: Request, db: Session = Depends(get_db)):
    user = require_admin(request, db)
    return _render_servers(request, db, user)


@router.post("/ldap-servers/create")
def create_ldap_server(
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    base_dn: str = Form(...),
    bind_dn: str = Form(...),
    bind_password: str = Form(...),
    users_base_dn: str = Form(""),
    groups_base_dn: str = Form(""),
    starttls: bool = Form(False),
    verify_tls: bool = Form(False),
    ca_cert: str = Form(""),
    connect_timeout: int = Form(10),
    enabled: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request, db)
    verify_csrf(request, csrf_token)
    if not name.strip() or not url.strip() or not base_dn.strip() or not bind_dn.strip() or not bind_password:
        raise HTTPException(status_code=422, detail="Name, URL, Base DN, Bind DN and bind password are required")
    if connect_timeout < 1 or connect_timeout > 120:
        raise HTTPException(status_code=422, detail="Connect timeout must be between 1 and 120 seconds")
    server = LDAPServer(
        name=name.strip(),
        url=url.strip(),
        base_dn=base_dn.strip(),
        bind_dn=bind_dn.strip(),
        encrypted_bind_password=encrypt_secret(bind_password),
        users_base_dn=users_base_dn.strip() or None,
        groups_base_dn=groups_base_dn.strip() or None,
        starttls=starttls,
        verify_tls=verify_tls,
        ca_cert=ca_cert.strip() or None,
        connect_timeout=connect_timeout,
        enabled=enabled,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return RedirectResponse("/ldap-servers", status_code=303)


@router.post("/ldap-servers/{server_id}/update")
def update_ldap_server(
    server_id: int,
    request: Request,
    name: str = Form(...),
    url: str = Form(...),
    base_dn: str = Form(...),
    bind_dn: str = Form(...),
    bind_password: str = Form(""),
    users_base_dn: str = Form(""),
    groups_base_dn: str = Form(""),
    starttls: bool = Form(False),
    verify_tls: bool = Form(False),
    ca_cert: str = Form(""),
    connect_timeout: int = Form(10),
    enabled: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request, db)
    verify_csrf(request, csrf_token)
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    if not name.strip() or not url.strip() or not base_dn.strip() or not bind_dn.strip():
        raise HTTPException(status_code=422, detail="Name, URL, Base DN and Bind DN are required")
    if connect_timeout < 1 or connect_timeout > 120:
        raise HTTPException(status_code=422, detail="Connect timeout must be between 1 and 120 seconds")
    server.name = name.strip()
    server.url = url.strip()
    server.base_dn = base_dn.strip()
    server.bind_dn = bind_dn.strip()
    if bind_password:
        server.encrypted_bind_password = encrypt_secret(bind_password)
    server.users_base_dn = users_base_dn.strip() or None
    server.groups_base_dn = groups_base_dn.strip() or None
    server.starttls = starttls
    server.verify_tls = verify_tls
    server.ca_cert = ca_cert.strip() or None
    server.connect_timeout = connect_timeout
    server.enabled = enabled
    db.commit()
    if not enabled and request.session.get("ldap_server_id") == server_id:
        request.session.pop("ldap_server_id", None)
    return RedirectResponse("/ldap-servers", status_code=303)


@router.post("/ldap-servers/{server_id}/test", response_class=HTMLResponse)
def test_ldap_server(
    server_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    manager = _manager(server)
    try:
        steps = manager.test()
    finally:
        manager.close()
    return _render_servers(request, db, user, test_server_id=server_id, test_steps=steps)


@router.post("/ldap-servers/{server_id}/delete")
def delete_ldap_server(
    server_id: int,
    request: Request,
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request, db)
    verify_csrf(request, csrf_token)
    server = db.get(LDAPServer, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="LDAP server not found")
    if confirmation != f"DELETE {server_id}":
        raise HTTPException(status_code=409, detail=f"Confirmation must equal DELETE {server_id}")
    db.delete(server)
    db.commit()
    if request.session.get("ldap_server_id") == server_id:
        request.session.pop("ldap_server_id", None)
    return RedirectResponse("/ldap-servers", status_code=303)
