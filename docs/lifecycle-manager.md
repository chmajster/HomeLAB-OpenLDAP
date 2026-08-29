# Lifecycle Manager

The Lifecycle Manager provides a central account-state view for the currently selected LDAP server.

It reports:

- active accounts
- accounts expiring within 30 days
- expired accounts
- locked/disabled accounts
- accounts requiring a password change
- account expiry dates

Web UI:

```text
/lifecycle
```

REST API:

```text
GET /api/v1/lifecycle/accounts
```

Supported query parameters are `state`, `search`, and `limit`.

The page reuses the existing `LDAPAccountLifecycleService` for mutations. Users need `ldap.lifecycle.read` to view the manager and `ldap.lifecycle.write` to change account state. Mutations are audit logged and honor the active multi-server LDAP selection.
