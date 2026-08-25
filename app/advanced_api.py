from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.advanced import LDAPEntryService, LDAPMembershipService, LDAPQueryBuilder, decode_dn, encode_dn
from app.audit import AuditService
from app.config import get_settings
from app.database import get_db
from app.dependencies import AuthContext, get_ldap_manager, require_permission
from app.ldap import LDAPConnectionManager, LDAPGroupService, LDAPOUService, LDAPUserService
from app.models import AppSetting

router = APIRouter(prefix="/api/v1")
settings = get_settings()


class EntryModifyPayload(BaseModel):
    attributes: dict[str, Any]
    confirm: bool = False


class EntryMovePayload(BaseModel):
    new_parent_dn: str
    new_rdn: str | None = None
    confirm: bool = False


class EntryCopyPayload(BaseModel):
    target_dn: str
    replacements: dict[str, Any] = Field(default_factory=dict)
    confirm: bool = False


class AttributeValuePayload(BaseModel):
    attribute: str
    values: list[Any]
    confirm: bool = False


class MembershipPayload(BaseModel):
    group_dn: str
    user_dn: str
    confirm: bool = False


class QueryCondition(BaseModel):
    attribute: str
    operator: Literal["equals", "not_equals", "contains", "starts_with", "ends_with", "present"]
    value: str | None = None


class QueryBuilderPayload(BaseModel):
    operator: Literal["AND", "OR", "NOT"] = "AND"
    conditions: list[QueryCondition] = Field(min_length=1, max_length=50)


class BulkUsersPayload(BaseModel):
    usernames: list[str] = Field(min_length=1, max_length=500)
    operation: Literal["enable", "disable", "delete", "move", "add_to_group", "remove_from_group"]
    target_dn: str | None = None
    confirm: bool = False


class BulkGroupsPayload(BaseModel):
    names: list[str] = Field(min_length=1, max_length=500)
    operation: Literal["delete", "move"]
    target_dn: str | None = None
    confirm: bool = False


class OUMovePayload(BaseModel):
    dn: str
    new_parent_dn: str
    new_name: str | None = None
    confirm: bool = False


class OUDeletePayload(BaseModel):
    dn: str
    confirm: bool = False


class MappingPayload(BaseModel):
    username: str = "uid"
    email: str = "mail"
    first_name: str = "givenName"
    last_name: str = "sn"
    display_name: str = "displayName"
    uid: str = "uidNumber"
    gid: str = "gidNumber"


class TemplatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    object_classes: list[str] = Field(min_length=1, max_length=50)
    defaults: dict[str, Any] = Field(default_factory=dict)


def meta(request: Request, auth: AuthContext) -> dict[str, str | None]:
    return {
        "request_id": getattr(request.state, "request_id", "unknown"),
        "panel_user": auth.username,
        "source_ip": request.client.host if request.client else None,
    }


def require_confirmation(confirm: bool, detail: Any) -> None:
    if not confirm:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"message": "Operation requires confirmation", "preview": detail})


@router.get("/directory/entry/{encoded_dn}")
def get_entry(encoded_dn: str, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> dict[str, Any]:
    dn = decode_dn(encoded_dn)
    entry = LDAPEntryService(manager).get(dn)
    if not entry:
        raise HTTPException(status_code=404, detail="LDAP entry not found")
    return {"encoded_dn": encoded_dn, "entry": entry}


@router.post("/directory/entry/{encoded_dn}/preview")
def preview_entry_modify(encoded_dn: str, payload: EntryModifyPayload, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.read"))) -> dict[str, Any]:
    return LDAPEntryService(manager).preview(decode_dn(encoded_dn), payload.attributes)


@router.put("/directory/entry/{encoded_dn}")
def modify_entry(encoded_dn: str, payload: EntryModifyPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, Any]:
    dn = decode_dn(encoded_dn)
    service = LDAPEntryService(manager)
    preview = service.preview(dn, payload.attributes)
    require_confirmation(payload.confirm, preview)
    before = service.get(dn)
    result = service.modify(dn, payload.attributes)
    op = AuditService(db).record(**meta(request, auth), operation="MODIFY_ENTRY", status="SUCCESS", dn=dn, old_value=before, new_value=result)
    return {"entry": result, "diff": preview, "operation_id": op}


@router.post("/directory/entry/{encoded_dn}/attributes")
def add_entry_attribute(encoded_dn: str, payload: AttributeValuePayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, str]:
    dn = decode_dn(encoded_dn)
    require_confirmation(payload.confirm, {"dn": dn, "attribute": payload.attribute, "add": payload.values})
    LDAPEntryService(manager).add_attribute_value(dn, payload.attribute, payload.values)
    op = AuditService(db).record(**meta(request, auth), operation="ADD_ATTRIBUTE", status="SUCCESS", dn=dn, attribute=payload.attribute, new_value=payload.values)
    return {"operation_id": op}


@router.delete("/directory/entry/{encoded_dn}/attributes")
def delete_entry_attribute(encoded_dn: str, payload: AttributeValuePayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, str]:
    dn = decode_dn(encoded_dn)
    require_confirmation(payload.confirm, {"dn": dn, "attribute": payload.attribute, "delete": payload.values})
    LDAPEntryService(manager).delete_attribute_value(dn, payload.attribute, payload.values or None)
    op = AuditService(db).record(**meta(request, auth), operation="DELETE_ATTRIBUTE", status="SUCCESS", dn=dn, attribute=payload.attribute, old_value=payload.values)
    return {"operation_id": op}


@router.post("/directory/entry/{encoded_dn}/move")
def move_entry(encoded_dn: str, payload: EntryMovePayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, Any]:
    dn = decode_dn(encoded_dn)
    preview = {"dn": dn, "new_parent_dn": payload.new_parent_dn, "new_rdn": payload.new_rdn}
    require_confirmation(payload.confirm, preview)
    new_dn = LDAPEntryService(manager).move(dn, payload.new_parent_dn, payload.new_rdn)
    op = AuditService(db).record(**meta(request, auth), operation="MODDN", status="SUCCESS", dn=dn, old_value=dn, new_value=new_dn)
    return {"old_dn": dn, "new_dn": new_dn, "encoded_dn": encode_dn(new_dn), "operation_id": op}


@router.post("/directory/entry/{encoded_dn}/copy", status_code=201)
def copy_entry(encoded_dn: str, payload: EntryCopyPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, Any]:
    source_dn = decode_dn(encoded_dn)
    preview = {"source_dn": source_dn, "target_dn": payload.target_dn, "replacements": payload.replacements}
    require_confirmation(payload.confirm, preview)
    result = LDAPEntryService(manager).copy(source_dn, payload.target_dn, payload.replacements)
    op = AuditService(db).record(**meta(request, auth), operation="COPY_ENTRY", status="SUCCESS", dn=payload.target_dn, old_value={"source_dn": source_dn}, new_value=result)
    return {"entry": result, "encoded_dn": encode_dn(payload.target_dn), "operation_id": op}


@router.delete("/directory/entry/{encoded_dn}", status_code=204)
def delete_entry(encoded_dn: str, confirm: bool = False, request: Request = None, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    dn = decode_dn(encoded_dn)
    require_confirmation(confirm, {"dn": dn, "operation": "PERMANENT_DELETE"})
    LDAPEntryService(manager).delete(dn, require_empty=False)
    AuditService(db).record(**meta(request, auth), operation="PERMANENT_DELETE_ENTRY", status="SUCCESS", dn=dn)
    return Response(status_code=204)


@router.post("/query-builder")
def query_builder(payload: QueryBuilderPayload, _: AuthContext = Depends(require_permission("ldap.read"))) -> dict[str, Any]:
    filters = [LDAPQueryBuilder.condition(condition.attribute, condition.operator, condition.value) for condition in payload.conditions]
    return {"filter": LDAPQueryBuilder.combine(payload.operator, filters), "conditions": filters}


@router.post("/users/{username}/groups", status_code=204)
def add_user_to_group(username: str, payload: MembershipPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    require_confirmation(payload.confirm, {"user_dn": user["dn"], "group_dn": payload.group_dn, "operation": "ADD"})
    LDAPMembershipService(manager).change(payload.group_dn, user["dn"], True)
    AuditService(db).record(**meta(request, auth), operation="ADD_TO_GROUP", status="SUCCESS", dn=user["dn"], new_value={"group_dn": payload.group_dn})
    return Response(status_code=204)


@router.delete("/users/{username}/groups", status_code=204)
def remove_user_from_group(username: str, payload: MembershipPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> Response:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    require_confirmation(payload.confirm, {"user_dn": user["dn"], "group_dn": payload.group_dn, "operation": "REMOVE"})
    LDAPMembershipService(manager).change(payload.group_dn, user["dn"], False)
    AuditService(db).record(**meta(request, auth), operation="REMOVE_FROM_GROUP", status="SUCCESS", dn=user["dn"], old_value={"group_dn": payload.group_dn})
    return Response(status_code=204)


@router.get("/users/{username}/groups")
def user_groups(username: str, manager: LDAPConnectionManager = Depends(get_ldap_manager), _: AuthContext = Depends(require_permission("ldap.users.read"))) -> list[dict[str, Any]]:
    user = LDAPUserService(manager, settings.uid_min, settings.uid_max).get(username)
    if not user:
        raise HTTPException(status_code=404, detail="LDAP user not found")
    return LDAPMembershipService(manager).groups_for_user(user["dn"], username)


@router.post("/bulk/users")
def bulk_users(payload: BulkUsersPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.users.write"))) -> dict[str, Any]:
    require_confirmation(payload.confirm, payload.model_dump(exclude={"confirm"}))
    users = LDAPUserService(manager, settings.uid_min, settings.uid_max)
    entries = LDAPEntryService(manager)
    memberships = LDAPMembershipService(manager)
    results: list[dict[str, str]] = []
    for username in payload.usernames:
        try:
            user = users.get(username)
            if not user:
                raise KeyError(username)
            if payload.operation == "enable":
                users.enable(username)
            elif payload.operation == "disable":
                users.disable(username)
            elif payload.operation == "delete":
                users.delete(username)
            elif payload.operation == "move":
                if not payload.target_dn:
                    raise ValueError("target_dn is required for move")
                entries.move(user["dn"], payload.target_dn)
            elif payload.operation in {"add_to_group", "remove_from_group"}:
                if not payload.target_dn:
                    raise ValueError("target_dn must contain group DN")
                memberships.change(payload.target_dn, user["dn"], payload.operation == "add_to_group")
            results.append({"item": username, "status": "SUCCESS"})
        except Exception as exc:
            results.append({"item": username, "status": "FAILED", "error": str(exc)})
    success = sum(1 for result in results if result["status"] == "SUCCESS")
    failed = len(results) - success
    op = AuditService(db).record(**meta(request, auth), operation=f"BULK_USERS_{payload.operation.upper()}", status="SUCCESS" if failed == 0 else "PARTIAL", new_value={"success": success, "failed": failed})
    return {"status": "SUCCESS" if failed == 0 else "PARTIAL", "success": success, "failed": failed, "skipped": 0, "results": results, "operation_id": op}


@router.post("/bulk/groups")
def bulk_groups(payload: BulkGroupsPayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.groups.write"))) -> dict[str, Any]:
    require_confirmation(payload.confirm, payload.model_dump(exclude={"confirm"}))
    groups = LDAPGroupService(manager, settings.gid_min, settings.gid_max)
    entries = LDAPEntryService(manager)
    results: list[dict[str, str]] = []
    for name in payload.names:
        try:
            group = groups.get(name)
            if not group:
                raise KeyError(name)
            if payload.operation == "delete":
                groups.delete(name)
            elif payload.operation == "move":
                if not payload.target_dn:
                    raise ValueError("target_dn is required for move")
                entries.move(group["dn"], payload.target_dn)
            results.append({"item": name, "status": "SUCCESS"})
        except Exception as exc:
            results.append({"item": name, "status": "FAILED", "error": str(exc)})
    success = sum(1 for result in results if result["status"] == "SUCCESS")
    failed = len(results) - success
    op = AuditService(db).record(**meta(request, auth), operation=f"BULK_GROUPS_{payload.operation.upper()}", status="SUCCESS" if failed == 0 else "PARTIAL", new_value={"success": success, "failed": failed})
    return {"status": "SUCCESS" if failed == 0 else "PARTIAL", "success": success, "failed": failed, "results": results, "operation_id": op}


@router.delete("/ous", status_code=204)
def delete_ou(payload: OUDeletePayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.ou.write"))) -> Response:
    require_confirmation(payload.confirm, {"dn": payload.dn, "operation": "DELETE_OU"})
    LDAPOUService(manager).delete(payload.dn)
    AuditService(db).record(**meta(request, auth), operation="DELETE_OU", status="SUCCESS", dn=payload.dn)
    return Response(status_code=204)


@router.post("/ous/move")
def move_ou(payload: OUMovePayload, request: Request, db: Session = Depends(get_db), manager: LDAPConnectionManager = Depends(get_ldap_manager), auth: AuthContext = Depends(require_permission("ldap.ou.write"))) -> dict[str, Any]:
    new_rdn = f"ou={payload.new_name}" if payload.new_name else None
    preview = {"dn": payload.dn, "new_parent_dn": payload.new_parent_dn, "new_rdn": new_rdn}
    require_confirmation(payload.confirm, preview)
    new_dn = LDAPEntryService(manager).move(payload.dn, payload.new_parent_dn, new_rdn)
    op = AuditService(db).record(**meta(request, auth), operation="MOVE_OU", status="SUCCESS", dn=payload.dn, old_value=payload.dn, new_value=new_dn)
    return {"old_dn": payload.dn, "new_dn": new_dn, "operation_id": op}


def get_setting(db: Session, key: str, default: str) -> str:
    row = db.get(AppSetting, key)
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value, encrypted=False))
    db.commit()


@router.get("/settings/attribute-mapping")
def get_attribute_mapping(db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    return json.loads(get_setting(db, "ldap.attribute_mapping", MappingPayload().model_dump_json()))


@router.put("/settings/attribute-mapping")
def update_attribute_mapping(payload: MappingPayload, db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> dict[str, Any]:
    set_setting(db, "ldap.attribute_mapping", payload.model_dump_json())
    return payload.model_dump()


@router.get("/settings/objectclass-templates")
def get_objectclass_templates(db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> list[dict[str, Any]]:
    default = [
        {"name": "Basic User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {}},
        {"name": "Linux User", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount", "shadowAccount"], "defaults": {"loginShell": "/bin/bash"}},
        {"name": "Service Account", "object_classes": ["top", "person", "organizationalPerson", "inetOrgPerson"], "defaults": {}},
    ]
    return json.loads(get_setting(db, "ldap.objectclass_templates", json.dumps(default)))


@router.put("/settings/objectclass-templates")
def update_objectclass_templates(payload: list[TemplatePayload], db: Session = Depends(get_db), _: AuthContext = Depends(require_permission("*"))) -> list[dict[str, Any]]:
    if len(payload) > 100:
        raise HTTPException(status_code=422, detail="Too many templates")
    data = [item.model_dump() for item in payload]
    set_setting(db, "ldap.objectclass_templates", json.dumps(data, ensure_ascii=False))
    return data
