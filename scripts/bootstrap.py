#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

from sqlalchemy import func, select

from app.database import SessionLocal, init_db
from app.ldap.connection import LDAPConnectionManager, LDAPSettings
from app.models import LDAPServer, PanelUser
from app.security import encrypt_secret, hash_password


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap HomeLAB OpenLDAP Manager")
    parser.add_argument("--admin-user", default=os.getenv("ADMIN_USER"))
    parser.add_argument("--admin-password", default=os.getenv("ADMIN_PASSWORD"))
    parser.add_argument("--skip-ldap-test", action="store_true")
    args = parser.parse_args()

    if not args.admin_user or not args.admin_password:
        print("ADMIN_USER and ADMIN_PASSWORD are required", file=sys.stderr)
        return 2
    if len(args.admin_password) < 12:
        print("Administrator password must contain at least 12 characters", file=sys.stderr)
        return 2

    ldap_url = os.getenv("LDAP_URL")
    base_dn = os.getenv("LDAP_BASE_DN")
    bind_dn = os.getenv("LDAP_BIND_DN")
    bind_password = os.getenv("LDAP_BIND_PASSWORD")
    if not all([ldap_url, base_dn, bind_dn, bind_password]):
        print("LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN and LDAP_BIND_PASSWORD are required", file=sys.stderr)
        return 2

    ldap_settings = LDAPSettings(
        url=ldap_url,
        base_dn=base_dn,
        bind_dn=bind_dn,
        bind_password=bind_password,
        starttls=parse_bool(os.getenv("LDAP_STARTTLS")),
        verify_tls=parse_bool(os.getenv("LDAP_VERIFY_TLS"), True),
        ca_cert=os.getenv("LDAP_CA_CERT") or None,
        users_base_dn=os.getenv("USERS_BASE_DN") or None,
        groups_base_dn=os.getenv("GROUPS_BASE_DN") or None,
    )
    if not args.skip_ldap_test:
        steps = LDAPConnectionManager(ldap_settings).test()
        if not all(s["ok"] for s in steps if s["name"] != "write_permissions"):
            print("LDAP connection test failed", file=sys.stderr)
            for step in steps:
                print(f"{step['name']}: {'OK' if step['ok'] else 'FAIL'} - {step['detail']}", file=sys.stderr)
            return 3

    init_db()
    with SessionLocal() as db:
        if db.scalar(select(func.count(PanelUser.id))) == 0:
            db.add(PanelUser(username=args.admin_user, password_hash=hash_password(args.admin_password), role="Administrator"))
        if db.scalar(select(func.count(LDAPServer.id))) == 0:
            db.add(LDAPServer(
                name="Default",
                url=ldap_settings.url,
                base_dn=ldap_settings.base_dn,
                bind_dn=ldap_settings.bind_dn,
                encrypted_bind_password=encrypt_secret(ldap_settings.bind_password),
                users_base_dn=ldap_settings.users_base_dn,
                groups_base_dn=ldap_settings.groups_base_dn,
                starttls=ldap_settings.starttls,
                verify_tls=ldap_settings.verify_tls,
                ca_cert=ldap_settings.ca_cert,
            ))
        db.commit()
    print("Bootstrap completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
