# LDAP capability inspector

A successful LDAP bind does not prove write access. The application therefore separates connection health from permission verification.

## Non-destructive inspection

The capability inspector checks:

- service account bind
- base DN search
- LDAP compare
- schema visibility
- `cn=config` visibility

Write permissions remain `unknown` after these checks.

## Explicit write probe

Administrators can explicitly run a write probe against a chosen base DN. The probe:

1. creates a temporary `organizationalRole`,
2. modifies its `description`,
3. deletes the temporary entry,
4. attempts cleanup if an intermediate operation fails.

The UI requires the confirmation text `PROBE WRITE`. The REST API requires `confirm=true`.

REST endpoints:

```text
GET  /api/v1/ldap/capabilities
POST /api/v1/ldap/capabilities/write-probe
```

Example request body:

```json
{
  "confirm": true,
  "probe_base_dn": "ou=PermissionProbe,dc=example,dc=org"
}
```

Write probes are audit logged. Use a dedicated test OU where possible because the probe performs real LDAP add/modify/delete operations.
