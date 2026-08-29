# Directory Health Analyzer

The analyzer performs read-only structural checks against the currently selected LDAP server.

It checks:

- Base DN readability
- schema metadata availability
- duplicate user `uidNumber` values
- duplicate POSIX-group `gidNumber` values
- required POSIX account attributes (`uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`)
- missing POSIX group `gidNumber`
- orphaned `member`, `uniqueMember`, and `memberUid` references

Web UI:

```text
/directory-health
```

REST API:

```text
GET /api/v1/directory-health
```

The report contains a health score, status, summary counters, connectivity checks and detailed findings. The analyzer never changes LDAP data and requires `ldap.read` permission.
