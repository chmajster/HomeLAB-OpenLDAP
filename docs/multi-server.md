# Multi-server LDAP

HomeLAB OpenLDAP Manager can store and operate against multiple LDAP server configurations.

## Web UI

Administrators manage server definitions under:

```text
/ldap-servers
```

Each definition contains its own:

- name and LDAP/LDAPS URL,
- Base DN,
- Bind DN and encrypted bind password,
- Users Base DN,
- Groups Base DN,
- StartTLS and TLS verification settings,
- optional CA certificate path,
- connection timeout,
- enabled/disabled state.

The top navigation contains an LDAP server selector. The selected server ID is stored in the signed web session and is used by existing directory, user, group, search, schema, security and tooling routes without changing their URLs.

If the selected server is disabled or deleted, the session selection is cleared and the application falls back to the first enabled LDAP server ordered by database ID. If no enabled database server exists, the legacy environment-based LDAP configuration remains the final fallback.

## REST API

Existing REST endpoints remain backward compatible. Without an explicit server selector they use the first enabled LDAP server.

To target a specific enabled server, send:

```text
X-LDAP-Server-ID: 3
```

An invalid, missing or disabled explicitly requested server returns an error instead of silently executing against another directory.

Available enabled servers:

```text
GET /api/v1/ldap-servers/available
```

Administrator management endpoints:

```text
GET    /api/v1/ldap-servers
POST   /api/v1/ldap-servers
PUT    /api/v1/ldap-servers/{server_id}
POST   /api/v1/ldap-servers/{server_id}/test
DELETE /api/v1/ldap-servers/{server_id}?confirm=true
```

Bind passwords are never returned by the API. New or changed passwords are encrypted with the existing application Fernet encryption key before being stored in SQL.

## Compatibility

No database migration is required because the existing `ldap_servers` table already supports multiple records. The change only makes server selection explicit and exposes management for the existing model.
