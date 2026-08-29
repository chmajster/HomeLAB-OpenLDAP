# LDAP object history

Object history presents the existing application audit trail as a DN-scoped timeline.

Features:

- exact-DN history
- operation and status filters
- actor and event summaries
- parsed JSON `old_value` / `new_value`
- attribute-level added / removed / changed diffs
- operation ID, request ID and source IP context

Web UI:

```text
/history?dn=<LDAP DN>
```

REST API:

```text
GET /api/v1/history?dn=<LDAP DN>&operation=<operation>&status=<status>&limit=200
```

Access requires `audit.read`.

History does not reconstruct secrets. Values displayed by this feature come from `AuditLog`, where `AuditService` has already redacted sensitive attributes and structures before persistence.

This feature is read-only. It does not implement rollback or replay of historical LDAP changes.
