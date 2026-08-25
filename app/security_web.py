from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_ldap_manager
from app.ldap import LDAPConnectionManager, LDAPUserService
from app.ldap.access import (
    LDAPAccountLifecycleService,
    LDAPCommandAccessService,
    LDAPConfigService,
    LDAPPasswordPolicyService,
    LDAPSSHKeyService,
)
from app.models import PanelUser
from app.web import page_context, require_web_user, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="templates")
settings = get_settings()


def require_write(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role == "Read Only":
        raise HTTPException(status_code=403, detail="Read Only role cannot modify LDAP")
    return user


def require_admin(request: Request, db: Session) -> PanelUser:
    user = require_web_user(request, db)
    if user.role != "Administrator":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def audit_meta(request: Request, user: PanelUser) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": user.username,
        "source_ip": request.client.host if request.client else None,
    }


def parse_lines(value: str) -> list[str]:
    return [line.strip() for line in value.replace(",", "\n").splitlines() if line.strip()]


def require_apply(value: str, expected: str = "APPLY") -> None:
    if value != expected:
        raise HTTPException(status_code=409, detail=f"Confirmation must equal {expected}")


@router.get("/users/{username}/access", response_class=HTMLResponse)
def user_access_page(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_web_user(request, db)
    ldap_user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not ldap_user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    sudo_roles = LDAPCommandAccessService(manager).list(username)
    ssh_keys = LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max).list(username)
    lifecycle = LDAPAccountLifecycleService(manager, settings.uid_min, settings.uid_max).status(username)
    policies = LDAPPasswordPolicyService(manager).list() if panel_user.role == "Administrator" else []
    return templates.TemplateResponse(
        "user_access.html",
        page_context(
            request,
            panel_user,
            username=username,
            ldap_user=ldap_user,
            sudo_roles=sudo_roles,
            ssh_keys=ssh_keys,
            lifecycle=lifecycle,
            policies=policies,
        ),
    )


@router.post("/users/{username}/command-access")
def command_access_save(
    request: Request,
    username: str,
    role_name: str = Form(""),
    commands: str = Form(...),
    hosts: str = Form("ALL"),
    run_as_users: str = Form("root"),
    run_as_groups: str = Form(""),
    options: str = Form(""),
    order: int | None = Form(None),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    ldap_user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not ldap_user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service = LDAPCommandAccessService(manager)
    result = service.upsert_user_role(
        username,
        parse_lines(commands),
        role_name=role_name.strip() or None,
        hosts=parse_lines(hosts) or ["ALL"],
        run_as_users=parse_lines(run_as_users) or ["root"],
        run_as_groups=parse_lines(run_as_groups),
        options=parse_lines(options),
        order=order,
    )
    AuditService(db).record(
        **audit_meta(request, panel_user),
        operation="SUDO_ROLE_UPSERT",
        status="SUCCESS",
        dn=result["dn"],
        new_value={
            "username": username,
            "commands": parse_lines(commands),
            "hosts": parse_lines(hosts) or ["ALL"],
            "run_as_users": parse_lines(run_as_users) or ["root"],
            "run_as_groups": parse_lines(run_as_groups),
            "options": parse_lines(options),
            "order": order,
        },
    )
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.post("/users/{username}/command-access/delete")
def command_access_delete(
    request: Request,
    username: str,
    role_name: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation, f"DELETE {role_name}")
    dn = LDAPCommandAccessService(manager).delete(role_name)
    AuditService(db).record(**audit_meta(request, panel_user), operation="SUDO_ROLE_DELETE", status="SUCCESS", dn=dn)
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.post("/users/{username}/ssh-keys/add")
def ssh_key_add(
    request: Request,
    username: str,
    public_key: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    result = LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max).add(username, public_key)
    AuditService(db).record(
        **audit_meta(request, panel_user),
        operation="SSH_KEY_ADD",
        status="SUCCESS",
        dn=username,
        new_value={"fingerprint": result["fingerprint"]},
    )
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.post("/users/{username}/ssh-keys/delete")
def ssh_key_delete(
    request: Request,
    username: str,
    public_key: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    service = LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max)
    fingerprint = service.fingerprint(public_key)
    service.delete(username, public_key)
    AuditService(db).record(
        **audit_meta(request, panel_user), operation="SSH_KEY_DELETE", status="SUCCESS", dn=username, old_value={"fingerprint": fingerprint}
    )
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.post("/users/{username}/lifecycle")
def lifecycle_update(
    request: Request,
    username: str,
    action: str = Form(...),
    expires_on: str = Form(""),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_write(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    service = LDAPAccountLifecycleService(manager, settings.uid_min, settings.uid_max)
    if action == "enable":
        result = service.set_enabled(username, True)
    elif action == "disable":
        result = service.set_enabled(username, False)
    elif action == "set_expiry":
        if not expires_on:
            raise HTTPException(status_code=422, detail="Expiry date is required")
        try:
            parsed = date.fromisoformat(expires_on)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Expiry date must use YYYY-MM-DD") from exc
        result = service.set_expiry(username, parsed)
    elif action == "clear_expiry":
        result = service.set_expiry(username, None)
    elif action == "require_password_change":
        result = service.require_password_change(username, True)
    elif action == "clear_password_change":
        result = service.require_password_change(username, False)
    else:
        raise HTTPException(status_code=422, detail="Unsupported lifecycle action")
    AuditService(db).record(
        **audit_meta(request, panel_user), operation="ACCOUNT_LIFECYCLE_UPDATE", status="SUCCESS", dn=result["dn"], new_value={"action": action, "expires_on": expires_on or None}
    )
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.post("/users/{username}/password-policy")
def password_policy_assign(
    request: Request,
    username: str,
    policy_name: str = Form(""),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    panel_user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    ldap_user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not ldap_user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service = LDAPPasswordPolicyService(manager)
    policy_dn = None
    if policy_name:
        policy = service.get(policy_name)
        if not policy:
            raise HTTPException(status_code=404, detail="Password policy not found")
        policy_dn = policy["dn"]
    service.assign(ldap_user["dn"], policy_dn)
    AuditService(db).record(
        **audit_meta(request, panel_user), operation="PASSWORD_POLICY_ASSIGN", status="SUCCESS", dn=ldap_user["dn"], new_value={"policy_dn": policy_dn}
    )
    return RedirectResponse(f"/users/{username}/access", status_code=303)


@router.get("/acl-manager", response_class=HTMLResponse)
def acl_manager_page(
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    rows = LDAPConfigService(manager).databases()
    return templates.TemplateResponse("acl_manager.html", page_context(request, user, rows=rows))


@router.post("/acl-manager")
def acl_manager_update(
    request: Request,
    database_dn: str = Form(...),
    rules: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    parsed_rules = [line.strip() for line in rules.splitlines() if line.strip()]
    result = LDAPConfigService(manager).set_acl(database_dn, parsed_rules)
    AuditService(db).record(
        **audit_meta(request, user), operation="OLC_ACCESS_REPLACE", status="SUCCESS", dn=database_dn, new_value={"rules": result["olcAccess"]}
    )
    return RedirectResponse("/acl-manager", status_code=303)


@router.get("/replication", response_class=HTMLResponse)
def replication_page(
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    rows = LDAPConfigService(manager).databases()
    return templates.TemplateResponse("replication.html", page_context(request, user, rows=rows, base_dn=manager.settings.base_dn))


@router.post("/replication")
def replication_update(
    request: Request,
    database_dn: str = Form(...),
    rid: str = Form(...),
    provider: str = Form(...),
    searchbase: str = Form(...),
    binddn: str = Form(...),
    bindcredentials: str = Form(...),
    sync_type: str = Form("refreshAndPersist"),
    retry: str = Form("5 5 300 +"),
    tls_reqcert: str = Form(""),
    mirror_mode: bool = Form(False),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    service = LDAPConfigService(manager)
    definition = service.build_syncrepl(
        rid=rid,
        provider=provider,
        searchbase=searchbase,
        binddn=binddn,
        bindcredentials=bindcredentials,
        sync_type=sync_type,
        retry=retry,
        tls_reqcert=tls_reqcert or None,
    )
    result = service.set_replication(database_dn, [definition], mirror_mode)
    AuditService(db).record(
        **audit_meta(request, user),
        operation="SYNCREPL_UPDATE",
        status="SUCCESS",
        dn=database_dn,
        new_value={"syncrepl": result["olcSyncRepl"], "mirror_mode": mirror_mode},
    )
    return RedirectResponse("/replication", status_code=303)


@router.post("/replication/disable")
def replication_disable(
    request: Request,
    database_dn: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation, "DISABLE")
    LDAPConfigService(manager).disable_replication(database_dn)
    AuditService(db).record(**audit_meta(request, user), operation="SYNCREPL_DISABLE", status="SUCCESS", dn=database_dn)
    return RedirectResponse("/replication", status_code=303)


@router.get("/password-policies", response_class=HTMLResponse)
def password_policies_page(
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    rows = LDAPPasswordPolicyService(manager).list()
    return templates.TemplateResponse("password_policies.html", page_context(request, user, rows=rows))


@router.post("/password-policies")
def password_policy_save(
    request: Request,
    name: str = Form(...),
    pwd_min_length: int = Form(12),
    pwd_min_age: int = Form(0),
    pwd_max_age: int = Form(7776000),
    pwd_in_history: int = Form(5),
    pwd_expire_warning: int = Form(604800),
    pwd_grace_authn_limit: int = Form(0),
    pwd_max_failure: int = Form(5),
    pwd_failure_count_interval: int = Form(900),
    pwd_lockout_duration: int = Form(900),
    pwd_lockout: bool = Form(False),
    pwd_must_change: bool = Form(False),
    pwd_allow_user_change: bool = Form(False),
    pwd_safe_modify: bool = Form(False),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation)
    values = {
        "pwdMinLength": pwd_min_length,
        "pwdMinAge": pwd_min_age,
        "pwdMaxAge": pwd_max_age,
        "pwdInHistory": pwd_in_history,
        "pwdExpireWarning": pwd_expire_warning,
        "pwdGraceAuthnLimit": pwd_grace_authn_limit,
        "pwdMaxFailure": pwd_max_failure,
        "pwdFailureCountInterval": pwd_failure_count_interval,
        "pwdLockoutDuration": pwd_lockout_duration,
        "pwdLockout": pwd_lockout,
        "pwdMustChange": pwd_must_change,
        "pwdAllowUserChange": pwd_allow_user_change,
        "pwdSafeModify": pwd_safe_modify,
    }
    result = LDAPPasswordPolicyService(manager).upsert(name, values)
    AuditService(db).record(
        **audit_meta(request, user), operation="PASSWORD_POLICY_UPSERT", status="SUCCESS", dn=result["dn"], new_value=values
    )
    return RedirectResponse("/password-policies", status_code=303)


@router.post("/password-policies/delete")
def password_policy_delete(
    request: Request,
    name: str = Form(...),
    confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
):
    user = require_admin(request, db)
    verify_csrf(request, csrf_token)
    require_apply(confirmation, f"DELETE {name}")
    dn = LDAPPasswordPolicyService(manager).delete(name)
    AuditService(db).record(**audit_meta(request, user), operation="PASSWORD_POLICY_DELETE", status="SUCCESS", dn=dn)
    return RedirectResponse("/password-policies", status_code=303)
