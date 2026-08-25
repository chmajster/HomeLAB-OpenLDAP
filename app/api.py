from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPHealthService, LDAPOUService, LDAPSchemaService, LDAPSearchService, LDAPUserService
from app.ldap.connection import LDAPOperationError, LDAPSettings
from app.models import APIToken, AuditLog
from app.schemas import APITokenCreate, GroupCreate, GroupUpdate, HealthResponse, LDAPTestRequest, LDAPTestResponse, OUCreate, SearchRequest, UserCreate, UserUpdate
from app.security import generate_api_token, hash_api_token

router = APIRouter(prefix="/api/v1")
settings = get_settings()


def request_meta(request: Request, auth: AuthContext) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": auth.username,
        "source_ip": request.client.host if request.client else None,
    }


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database = "unavailable"
    ldap = "unavailable"
    try:
        manager = next(iter([get_ldap_manager(db)]))
        ldap = "ok" if LDAPHealthService(manager).check()["ok"] else "unavailable"
    except Exception:
        ldap = "unavailable"
    overall = "healthy" if database == "ok" and ldap == "ok" else "degraded"
    return HealthResponse(status=overall, application="ok", database=database, ldap=ldap)


@router.get("/version")
def version() -> dict[str, str]:
    return {"version": settings.version}


@router.get("/status")
def ldap_status(
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.read")),
) -> dict[str, Any]:
    return LDAPHealthService(manager).check()


@router.post("/ldap/test", response_model=LDAPTestResponse)
def test_ldap(payload: LDAPTestRequest, _: AuthContext = Depends(require_permission("ldap.read"))) -> LDAPTestResponse:
    manager = LDAPConnectionManager(LDAPSettings(**payload.model_dump()))
    steps = manager.test()
    return LDAPTestResponse(ok=all(s["ok"] for s in steps if s["name"] != "write_permissions"), steps=steps)


@router.get("/users")
def users(
    search: str | None = None,
    limit: int = 50,
    cookie: str | None = None,
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    _: AuthContext = Depends(require_permission("ldap.users.read")),
) -> dict[str, Any]:
    raw_cookie = base64.b64decode(cookie) if cookie else None
    return LDAPUserService(manager, settings.uid_min, settings.uid_max).list(search=search, page_size=limit, cookie=raw_cookie)


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.users.write")),
) -> dict[str, Any]:
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    audit = AuditService(db)
    try:
        result = service.create(payload.model_dump())
        op = audit.record(**request_meta(request, auth), operation="ADD", status="SUCCESS", dn=result["dn"], new_value={k: v for k, v in payload.model_dump().items() if k != "password"})
        return {**result, "operation_id": op}
    except Exception as exc:
        audit.record(**request_meta(request, auth), operation="ADD", status="FAILED", new_value=payload.model_dump(), message=str(exc))
        raise


@router.get("/users/{username}")
def get_user(username: str, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.users.read"))) -> dict[str, Any]:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    return user


@router.put("/users/{username}")
def update_user(
    username: str,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.users.write")),
) -> dict[str, Any]:
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    before = service.get(username)
    if not before:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    result = service.update(username, payload.model_dump(exclude_none=True))
    op = AuditService(db).record(**request_meta(request, auth), operation="MODIFY", status="SUCCESS", dn=before["dn"], old_value=before, new_value=result)
    return {"entry": result, "operation_id": op}


@router.delete("/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.users.write")),
) -> Response:
    dn = LDAPUserService(manager, settings.uid_min, settings.uid_max).delete(username)
    AuditService(db).record(**request_meta(request, auth), operation="DELETE", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.post("/users/{username}/password", status_code=204)
def reset_password(
    username: str,
    payload: dict[str, str],
    request: Request,
    db: Session = Depends(get_db),
    manager: LDAPConnectionManager = Depends(get_ldap_manager),
    auth: AuthContext = Depends(require_permission("ldap.users.write")),
) -> Response:
    password = payload.get("password", "")
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    user = service.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service.reset_password(username, password)
    AuditService(db).record(**request_meta(request, auth), operation="PASSWORD_RESET", status="SUCCESS", dn=user["dn"], attribute="userPassword", new_value="[REDACTED]")
    return Response(status_code=204)


@router.post("/users/{username}/disable", status_code=204)
def disable_user(username: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    user = service.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service.disable(username)
    AuditService(db).record(**request_meta(request, auth), operation="DISABLE", status="SUCCESS", dn=user["dn"])
    return Response(status_code=204)


@router.post("/users/{username}/enable", status_code=204)
def enable_user(username: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    service = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    user = service.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    service.enable(username)
    AuditService(db).record(**request_meta(request, auth), operation="ENABLE", status="SUCCESS", dn=user["dn"])
    return Response(status_code=204)


@router.get("/groups")
def groups(manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.groups.read"))) -> list[dict[str, Any]]:
    return LDAPGroupService(manager, settings.gid_min, settings.gid_max).list()


@router.post("/groups", status_code=201)
def create_group(payload: GroupCreate, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.groups.write"))) -> dict[str, Any]:
    result = LDAPGroupService(manager, settings.gid_min, settings.gid_max).create(payload.model_dump())
    op = AuditService(db).record(**request_meta(request, auth), operation="ADD_GROUP", status="SUCCESS", dn=result["dn"], new_value=payload.model_dump())
    return {**result, "operation_id": op}


@router.get("/groups/{name}")
def get_group(name: str, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.groups.read"))) -> dict[str, Any]:
    group = LDAPGroupService(manager, settings.gid_min, settings.gid_max).get(name)
    if not group:
        raise HTTPException(status_code=404, detail="LDAP group not found")
    return group


@router.put("/groups/{name}")
def update_group(name: str, payload: GroupUpdate, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.groups.write"))) -> dict[str, Any]:
    service = LDAPGroupService(manager, settings.gid_min, settings.gid_max)
    before = service.get(name)
    if not before:
        raise HTTPException(status_code=404, detail="LDAP group not found")
    result = service.update(name, payload.model_dump(exclude_none=True))
    op = AuditService(db).record(**request_meta(request, auth), operation="MODIFY_GROUP", status="SUCCESS", dn=before["dn"], old_value=before, new_value=result)
    return {"entry": result, "operation_id": op}


@router.delete("/groups/{name}", status_code=204)
def delete_group(name: str, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.groups.write"))) -> Response:
    dn = LDAPGroupService(manager, settings.gid_min, settings.gid_max).delete(name)
    AuditService(db).record(**request_meta(request, auth), operation="DELETE_GROUP", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.get("/ous")
def ous(manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.ou.read"))) -> list[dict[str, Any]]:
    return LDAPOUService(manager).list()


@router.post("/ous", status_code=201)
def create_ou(payload: OUCreate, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.ou.write"))) -> dict[str, Any]:
    result = LDAPOUService(manager).create(payload.name, payload.parent_dn)
    op = AuditService(db).record(**request_meta(request, auth), operation="ADD_OU", status="SUCCESS", dn=result["dn"], new_value=payload.model_dump())
    return {**result, "operation_id": op}


@router.post("/search")
def search(payload: SearchRequest, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> list[dict[str, Any]]:
    return LDAPSearchService(manager).search(**payload.model_dump())


@router.get("/schema")
def schema(manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.schema.read"))) -> dict[str, Any]:
    return LDAPSchemaService(manager).get()


@router.get("/audit")
def audit(limit: int = 100, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("audit.read"))) -> list[dict[str, Any]]:
    rows = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(min(max(limit, 1), 1000))).all()
    return [{"operation_id": r.operation_id, "request_id": r.request_id, "created_at": r.created_at, "user": r.panel_user, "source_ip": r.source_ip, "operation": r.operation, "dn": r.dn, "attribute": r.attribute, "old_value": r.old_value, "new_value": r.new_value, "status": r.status, "message": r.message} for r in rows]


@router.post("/tokens", status_code=201)
def create_token(payload: APITokenCreate, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    token = generate_api_token()
    expires = datetime.fromisoformat(payload.expires_at) if payload.expires_at else None
    row = APIToken(name=payload.name, token_prefix=token[:14], token_hash=hash_api_token(token), permissions=",".join(payload.permissions), expires_at=expires)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "token": token, "permissions": payload.permissions, "warning": "This token is shown only once."}


@router.delete("/tokens/{token_id}", status_code=204)
def revoke_token(token_id: int, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> Response:
    token = db.get(APIToken, token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    token.enabled = False
    db.commit()
    return Response(status_code=204)
