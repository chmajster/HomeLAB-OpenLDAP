# LDAP Browser 2.0

The directory browser now uses a dedicated browser service instead of assembling navigation directly in the web route.

Features:

- DN-parser-based breadcrumbs
- parent navigation
- child entry classification (OU, user, group, generic entry)
- safe child filtering across `cn`, `ou`, `uid`, and `mail`
- entry attribute preview
- direct link to the existing advanced entry editor
- active multi-server LDAP support

Web UI:

```text
/directory
```

REST API:

```text
GET /api/v1/browser/node?dn=<DN>&q=<filter>&limit=500
```

The API requires `ldap.read`. User filter input is escaped before it is inserted into an LDAP filter.
