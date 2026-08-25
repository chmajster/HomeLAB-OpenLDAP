# Changelog

## 0.2.0 - 2026-08-25

- Added per-user command authorization backed by native LDAP `sudoRole` entries.
- Added SSH public key management through `ldapPublicKey` / `sshPublicKey`.
- Added account lifecycle controls for enable/disable, expiry and password-reset-required state.
- Added full `pwdPolicy` object management and per-user policy assignment.
- Added `olcAccess` ACL manager for `cn=config` databases.
- Added `syncrepl` replication manager with credential redaction in UI and audit records.
- Added granular API permissions for sudo, SSH, lifecycle and password-policy operations.
- Added REST API routes, web UI, confirmation gates, audit logging and unit tests for the new security features.

## 0.1.0 - 2026-08-25

- Initial FastAPI/Jinja2 application.
- OpenLDAP integration through ldap3.
- Users, groups, OU, search, schema and LDAP browser.
- Panel authentication, RBAC, API tokens and audit correlation IDs.
- Native installer, silent JSON installation, systemd/nginx and backup helper.
- Docker development environment, tests and GitHub Actions.
