from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager, LDAPUserService
from app.ldap.access import (
    LDAPAccountLifecycleService,
    LDAPCommandAccessService,
    LDAPConfigService,
    LDAPPasswordPolicyService,
    LDAPSSHKeyService,
)

router = APIRouter(prefix="/api/v1")
settings = get_settings()


class CommandAccessPayload(BaseModel):
    role_name: str | None = Field(default=None, max_length=128)
    commands: list[str] = Field(min_length=1, max_length=200)
    hosts: list[str] = Field(default_factory=lambda: ["ALL"], max_length=100)
    run_as_users: list[str] = Field(default_factory=lambda: ["root"], max_length=100)
    run_as_groups: list[str] = Field(default_factory=list, max_length=100)
    options: list[str] = Field(default_factory=list, max_length=100)
    order: int | None = Field(default=None, ge=0, le=999999)
    confirm: bool = False


class SSHKeyPayload(BaseModel):
    key: str = Field(min_length=20, max_length=16384)
    confirm: bool = False


class LifecyclePayload(BaseModel):
    enabled: bool | None = None
    expires_on: date | None = None
    clear_expiry: bool = False
    password_reset_required: bool | None = None
    confirm: bool = False


class PasswordPolicyPayload(BaseModel):
    pwdMinAge: int | None = Field(default=None, ge=0)
    pwdMaxAge: int | None = Field(default=None, ge=0)
    pwdInHistory: int | None = Field(default=None, ge=0)
    pwdMinLength: int | None = Field(default=None, ge=0)
    pwdExpireWarning: int | None = Field(default=None, ge=0)
    pwdGraceAuthnLimit: int | None = Field(default=None, ge=0)
    pwdMaxFailure: int | None = Field(default=None, ge=0)
    pwdFailureCountInterval: int | None = Field(default=None, ge=0)
    pwdLockoutDuration: int | None = Field(default=None, ge=0)
    pwdLockout: bool | None = None
    pwdMustChange: bool | None = None
    pwdAllowUserChange: bool | None = None
    pwdSafeModify: bool | None = None
    confirm: bool = False


class PolicyAssignmentPayload(BaseModel):
    policy_name: str | None = None
    confirm: bool = False


class ACLPayload(BaseModel):
    rules: list[str] = Field(min_length=1, max_length=200)
    confirm: bool = False


class ReplicationPayload(BaseModel):
    rid: str = Field(pattern=r"^\d{3}$")
    provider: str
    searchbase: str
    binddn: str
    bindcredentials: str
    bindmethod: str = "simple"
    schemachecking: bool = True
    sync_type: str = "refreshAndPersist"
    retry: str = "5 5 300 +"
    tls_reqcert: str | None = None
    mirror_mode: bool = False
    confirm: bool = False


def _meta(request: Request, auth: AuthContext) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": auth.username,
        "source_ip": request.client.host if request.client else None,
    }


def _confirm(value: bool, preview: Any) -> None:
    if not value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"message": "Operation requires confirmation", "preview": preview})


@router.get("/users/{username}/command-access")
def command_access_list(
    username: str,
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.sudo.read")),
) -> list[dict[str, Any]]:
    return LDAPCommandAccessService(manager).list(username)


@router.put("/users/{username}/command-access")
def command_access_set(
    username: str,
    payload: CommandAccessPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.sudo.write")),
) -> dict[str, Any]:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    preview = payload.model_dump(exclude={"confirm", "bindcredentials"})
    _confirm(payload.confirm, preview)
    result = LDAPCommandAccessService(manager).upsert_user_role(
        username,
        payload.commands,
        role_name=payload.role_name,
        hosts=payload.hosts,
        run_as_users=payload.run_as_users,
        run_as_groups=payload.run_as_groups,
        options=payload.options,
        order=payload.order,
    )
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="SUDO_ROLE_UPSERT", status="SUCCESS", dn=result["dn"], new_value=preview
    )
    return {"role": result, "operation_id": operation_id}


@router.delete("/sudo-roles/{role_name}", status_code=204)
def command_access_delete(
    role_name: str,
    confirm: bool,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.sudo.write")),
) -> Response:
    _confirm(confirm, {"role_name": role_name, "operation": "DELETE"})
    dn = LDAPCommandAccessService(manager).delete(role_name)
    AuditService(db).record(**_meta(request, auth), operation="SUDO_ROLE_DELETE", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.get("/users/{username}/ssh-keys")
def ssh_keys_list(
    username: str,
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.ssh.read")),
) -> list[dict[str, str]]:
    return LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max).list(username)


@router.post("/users/{username}/ssh-keys", status_code=201)
def ssh_key_add(
    username: str,
    payload: SSHKeyPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.ssh.write")),
) -> dict[str, str]:
    _confirm(payload.confirm, {"username": username, "fingerprint": LDAPSSHKeyService.fingerprint(payload.key)})
    result = LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max).add(username, payload.key)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="SSH_KEY_ADD", status="SUCCESS", dn=username, new_value={"fingerprint": result["fingerprint"]}
    )
    return {**result, "operation_id": operation_id}


@router.delete("/users/{username}/ssh-keys", status_code=204)
def ssh_key_delete(
    username: str,
    payload: SSHKeyPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.ssh.write")),
) -> Response:
    fingerprint = LDAPSSHKeyService.fingerprint(payload.key)
    _confirm(payload.confirm, {"username": username, "fingerprint": fingerprint, "operation": "DELETE"})
    LDAPSSHKeyService(manager, settings.uid_min, settings.uid_max).delete(username, payload.key)
    AuditService(db).record(**_meta(request, auth), operation="SSH_KEY_DELETE", status="SUCCESS", dn=username, old_value={"fingerprint": fingerprint})
    return Response(status_code=204)


@router.get("/users/{username}/lifecycle")
def lifecycle_get(
    username: str,
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.lifecycle.read")),
) -> dict[str, Any]:
    return LDAPAccountLifecycleService(manager, settings.uid_min, settings.uid_max).status(username)


@router.put("/users/{username}/lifecycle")
def lifecycle_update(
    username: str,
    payload: LifecyclePayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.lifecycle.write")),
) -> dict[str, Any]:
    preview = payload.model_dump(exclude={"confirm"}, mode="json")
    _confirm(payload.confirm, preview)
    service = LDAPAccountLifecycleService(manager, settings.uid_min, settings.uid_max)
    result = service.status(username)
    if payload.enabled is not None:
        result = service.set_enabled(username, payload.enabled)
    if payload.clear_expiry:
        result = service.set_expiry(username, None)
    elif payload.expires_on is not None:
        result = service.set_expiry(username, payload.expires_on)
    if payload.password_reset_required is not None:
        result = service.require_password_change(username, payload.password_reset_required)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="ACCOUNT_LIFECYCLE_UPDATE", status="SUCCESS", dn=result["dn"], new_value=preview
    )
    return {**result, "operation_id": operation_id}


@router.get("/password-policies")
def password_policies_list(
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.ppolicy.read")),
) -> list[dict[str, Any]]:
    return LDAPPasswordPolicyService(manager).list()


@router.put("/password-policies/{name}")
def password_policy_upsert(
    name: str,
    payload: PasswordPolicyPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.ppolicy.write")),
) -> dict[str, Any]:
    values = payload.model_dump(exclude={"confirm"}, exclude_none=True)
    _confirm(payload.confirm, {"name": name, **values})
    result = LDAPPasswordPolicyService(manager).upsert(name, values)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="PASSWORD_POLICY_UPSERT", status="SUCCESS", dn=result["dn"], new_value=values
    )
    return {"policy": result, "operation_id": operation_id}


@router.delete("/password-policies/{name}", status_code=204)
def password_policy_delete(
    name: str,
    confirm: bool,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.ppolicy.write")),
) -> Response:
    _confirm(confirm, {"name": name, "operation": "DELETE"})
    dn = LDAPPasswordPolicyService(manager).delete(name)
    AuditService(db).record(**_meta(request, auth), operation="PASSWORD_POLICY_DELETE", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.put("/users/{username}/password-policy")
def password_policy_assign(
    username: str,
    payload: PolicyAssignmentPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.ppolicy.write")),
) -> dict[str, str | None]:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service = LDAPPasswordPolicyService(manager)
    policy_dn = None
    if payload.policy_name:
        policy = service.get(payload.policy_name)
        if not policy:
            raise HTTPException(status_code=404, detail="Password policy not found")
        policy_dn = policy["dn"]
    _confirm(payload.confirm, {"username": username, "policy_dn": policy_dn})
    service.assign(user["dn"], policy_dn)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="PASSWORD_POLICY_ASSIGN", status="SUCCESS", dn=user["dn"], new_value={"policy_dn": policy_dn}
    )
    return {"username": username, "policy_dn": policy_dn, "operation_id": operation_id}


@router.get("/config/databases")
def config_databases(
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.config.read")),
) -> list[dict[str, Any]]:
    return LDAPConfigService(manager).databases()


@router.put("/config/acl")
def acl_update(
    database_dn: str,
    payload: ACLPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.config.write")),
) -> dict[str, Any]:
    normalized = LDAPConfigService.normalize_acl(payload.rules)
    _confirm(payload.confirm, {"database_dn": database_dn, "olcAccess": normalized})
    result = LDAPConfigService(manager).set_acl(database_dn, payload.rules)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="OLC_ACCESS_REPLACE", status="SUCCESS", dn=database_dn, new_value={"rules": normalized}
    )
    return {**result, "operation_id": operation_id}


@router.put("/config/replication")
def replication_update(
    database_dn: str,
    payload: ReplicationPayload,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.config.write")),
) -> dict[str, Any]:
    service = LDAPConfigService(manager)
    definition = service.build_syncrepl(
        rid=payload.rid,
        provider=payload.provider,
        searchbase=payload.searchbase,
        binddn=payload.binddn,
        bindcredentials=payload.bindcredentials,
        bindmethod=payload.bindmethod,
        schemachecking=payload.schemachecking,
        sync_type=payload.sync_type,
        retry=payload.retry,
        tls_reqcert=payload.tls_reqcert,
    )
    preview = {"database_dn": database_dn, "syncrepl": service.redact_syncrepl(definition), "mirror_mode": payload.mirror_mode}
    _confirm(payload.confirm, preview)
    result = service.set_replication(database_dn, [definition], payload.mirror_mode)
    operation_id = AuditService(db).record(
        **_meta(request, auth), operation="SYNCREPL_UPDATE", status="SUCCESS", dn=database_dn, new_value=preview
    )
    return {**result, "operation_id": operation_id}


@router.delete("/config/replication", status_code=204)
def replication_disable(
    database_dn: str,
    confirm: bool,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.config.write")),
) -> Response:
    _confirm(confirm, {"database_dn": database_dn, "operation": "DISABLE_REPLICATION"})
    LDAPConfigService(manager).disable_replication(database_dn)
    AuditService(db).record(**_meta(request, auth), operation="SYNCREPL_DISABLE", status="SUCCESS", dn=database_dn)
    return Response(status_code=204)
