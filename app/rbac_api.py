from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.database import get_db
from app.dependencies import AuthContext, require_permission
from app.models import AccessRole, PanelUser
from app.rbac import PERMISSION_CATALOG, decode_permissions, encode_permissions, list_roles, normalize_permissions

router = APIRouter(prefix="/api/v1/rbac", tags=["RBAC"])
ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,127}$")


class RolePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2048)
    permissions: list[str] = Field(default_factory=list, max_length=100)
    enabled: bool = True


class RoleAssignmentPayload(BaseModel):
    role: str = Field(min_length=1, max_length=128)


def _meta(request: Request, auth: AuthContext) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": auth.username,
        "source_ip": request.client.host if request.client else None,
    }


def _serialize(role: AccessRole) -> dict[str, Any]:
    return {
        "name": role.name,
        "description": role.description,
        "permissions": sorted(decode_permissions(role.permissions)),
        "built_in": role.built_in,
        "enabled": role.enabled,
        "created_at": role.created_at,
    }


def _validate_custom(name: str, permissions: list[str]) -> tuple[str, set[str]]:
    clean_name = name.strip()
    if not ROLE_NAME_RE.fullmatch(clean_name):
        raise HTTPException(status_code=422, detail="Invalid role name")
    try:
        clean_permissions = normalize_permissions(permissions)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "*" in clean_permissions:
        raise HTTPException(status_code=422, detail="Wildcard permission is reserved for the built-in Administrator role")
    return clean_name, clean_permissions


@router.get("/permissions")
def permissions_catalog(_: AuthContext = Depends(require_permission("*"))) -> dict[str, str]:
    return dict(PERMISSION_CATALOG)


@router.get("/roles")
def roles_list(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_permission("*")),
) -> list[dict[str, Any]]:
    return [_serialize(role) for role in list_roles(db)]


@router.post("/roles", status_code=status.HTTP_201_CREATED)
def role_create(
    payload: RolePayload,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    name, permissions = _validate_custom(payload.name, payload.permissions)
    if db.get(AccessRole, name):
        raise HTTPException(status_code=409, detail="Role already exists")
    role = AccessRole(
        name=name,
        description=(payload.description or "").strip() or None,
        permissions=encode_permissions(permissions),
        built_in=False,
        enabled=payload.enabled,
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    AuditService(db).record(**_meta(request, auth), operation="RBAC_ROLE_CREATE", status="SUCCESS", new_value=_serialize(role))
    return _serialize(role)


@router.put("/roles/{role_name}")
def role_update(
    role_name: str,
    payload: RolePayload,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    role = db.get(AccessRole, role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.built_in:
        raise HTTPException(status_code=409, detail="Built-in roles are immutable")
    clean_name, permissions = _validate_custom(payload.name, payload.permissions)
    if clean_name != role.name:
        raise HTTPException(status_code=422, detail="Role name cannot be changed; create a new role instead")
    before = _serialize(role)
    role.description = (payload.description or "").strip() or None
    role.permissions = encode_permissions(permissions)
    role.enabled = payload.enabled
    db.commit()
    db.refresh(role)
    AuditService(db).record(**_meta(request, auth), operation="RBAC_ROLE_UPDATE", status="SUCCESS", old_value=before, new_value=_serialize(role))
    return _serialize(role)


@router.delete("/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
def role_delete(
    role_name: str,
    request: Request,
    confirm: bool = Query(False),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("*")),
) -> None:
    if not confirm:
        raise HTTPException(status_code=409, detail="Deleting a role requires confirm=true")
    role = db.get(AccessRole, role_name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.built_in:
        raise HTTPException(status_code=409, detail="Built-in roles cannot be deleted")
    users = db.scalar(select(func.count(PanelUser.id)).where(PanelUser.role == role.name)) or 0
    if users:
        raise HTTPException(status_code=409, detail="Role is assigned to panel users")
    snapshot = _serialize(role)
    db.delete(role)
    db.commit()
    AuditService(db).record(**_meta(request, auth), operation="RBAC_ROLE_DELETE", status="SUCCESS", old_value=snapshot)


@router.put("/users/{user_id}/role")
def assign_role(
    user_id: int,
    payload: RoleAssignmentPayload,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("*")),
) -> dict[str, Any]:
    user = db.get(PanelUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Panel user not found")
    role = db.get(AccessRole, payload.role)
    if not role or not role.enabled:
        raise HTTPException(status_code=422, detail="Role does not exist or is disabled")
    if user.username == auth.username and role.name != "Administrator":
        raise HTTPException(status_code=409, detail="Administrator cannot remove their own Administrator role")
    old_role = user.role
    user.role = role.name
    db.commit()
    AuditService(db).record(
        **_meta(request, auth), operation="RBAC_ROLE_ASSIGN", status="SUCCESS", dn=f"panel-user:{user.id}", old_value={"role": old_role}, new_value={"role": role.name}
    )
    return {"id": user.id, "username": user.username, "role": user.role}
