from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded"]
    application: str
    database: str
    ldap: str


class LDAPTestRequest(BaseModel):
    url: str
    base_dn: str
    bind_dn: str
    bind_password: str
    starttls: bool = False
    verify_tls: bool = True
    ca_cert: str | None = None
    connect_timeout: int = Field(default=10, ge=1, le=120)


class LDAPTestStep(BaseModel):
    name: str
    ok: bool
    detail: str
    duration_ms: float | None = None


class LDAPTestResponse(BaseModel):
    ok: bool
    steps: list[LDAPTestStep]


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    first_name: str = Field(min_length=1, max_length=128)
    last_name: str = Field(min_length=1, max_length=128)
    display_name: str | None = None
    email: str | None = None
    password: str = Field(min_length=8, max_length=1024)
    uid_number: int | None = None
    gid_number: int
    home_directory: str | None = None
    login_shell: str = "/bin/bash"
    organizational_unit: str | None = None
    groups: list[str] = Field(default_factory=list)
    object_classes: list[str] = Field(default_factory=lambda: ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"])
    attributes: dict[str, Any] = Field(default_factory=dict)


class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    email: str | None = None
    gid_number: int | None = None
    home_directory: str | None = None
    login_shell: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    group_type: Literal["groupOfNames", "groupOfUniqueNames", "posixGroup"] = "groupOfNames"
    gid_number: int | None = None
    members: list[str] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    members: list[str] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class OUCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    parent_dn: str | None = None


class SearchRequest(BaseModel):
    base_dn: str | None = None
    scope: Literal["BASE", "LEVEL", "SUBTREE"] = "SUBTREE"
    ldap_filter: str = "(objectClass=*)"
    attributes: list[str] = Field(default_factory=lambda: ["*"])
    size_limit: int = Field(default=100, ge=1, le=5000)
    time_limit: int = Field(default=10, ge=1, le=120)


class APITokenCreate(BaseModel):
    name: str
    permissions: list[str] = Field(default_factory=lambda: ["ldap.read"])
    expires_at: str | None = None
