from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PanelUser(Base):
    __tablename__ = "panel_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(128), default="Read Only")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    theme: Mapped[str] = mapped_column(String(16), default="system")
    auth_source: Mapped[str] = mapped_column(String(16), default="local")
    ldap_dn: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PanelSession(Base):
    __tablename__ = "panel_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("panel_users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)


class AccessRole(Base):
    __tablename__ = "access_roles"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    permissions: Mapped[str] = mapped_column(Text, default="")
    built_in: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LDAPServer(Base):
    __tablename__ = "ldap_servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), default="Default")
    url: Mapped[str] = mapped_column(String(512))
    base_dn: Mapped[str] = mapped_column(String(1024))
    bind_dn: Mapped[str] = mapped_column(String(1024))
    encrypted_bind_password: Mapped[str] = mapped_column(Text)
    users_base_dn: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    groups_base_dn: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    starttls: Mapped[bool] = mapped_column(Boolean, default=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
    connect_timeout: Mapped[int] = mapped_column(Integer, default=10)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    request_id: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    panel_user: Mapped[str] = mapped_column(String(128), default="system")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operation: Mapped[str] = mapped_column(String(64))
    dn: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    attribute: Mapped[str | None] = mapped_column(String(512), nullable=True)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32))
    message: Mapped[str | None] = mapped_column(Text, nullable=True)


class APIToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token_prefix: Mapped[str] = mapped_column(String(16), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    permissions: Mapped[str] = mapped_column(Text, default="ldap.read")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
