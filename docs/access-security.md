# Access, security and lifecycle modules

Version 0.2.0 adds native OpenLDAP-backed access-management features. The panel does not emulate these capabilities in its SQL database; it reads and writes the corresponding LDAP objects and `cn=config` attributes.

## Command access with sudoRole

Per-user command access is stored as `sudoRole` entries below:

```text
ou=SUDOers,<Base DN>
```

The panel creates the `ou=SUDOers` container when needed. The OpenLDAP server must have the sudo LDAP schema loaded. Linux clients must be configured to obtain sudo rules from LDAP through the appropriate NSS/sudo integration.

A rule can define:

- `sudoUser`
- `sudoHost`
- `sudoCommand`
- `sudoRunAsUser`
- `sudoRunAsGroup`
- `sudoOption`
- `sudoOrder`

Commands must be absolute paths or `ALL`. Denied commands may be prefixed with `!`.

Example:

```text
sudoUser: chris
sudoHost: web01
sudoCommand: /usr/bin/systemctl restart nginx
sudoRunAsUser: root
```

## SSH public keys

The user access page can add and remove OpenSSH public keys using:

```text
objectClass: ldapPublicKey
sshPublicKey: ssh-ed25519 ...
```

The OpenLDAP server must have a schema that provides `ldapPublicKey` and `sshPublicKey`. The panel validates the public-key format and displays a SHA256 fingerprint. Private keys are never accepted or stored.

## Account lifecycle

Lifecycle state is derived from LDAP attributes rather than from local SQL state.

Supported controls:

- Enable account: remove `pwdAccountLockedTime`.
- Disable account: set `pwdAccountLockedTime=000001010000Z`.
- Account expiry: set `shadowExpire` as days since Unix epoch.
- Clear expiry: remove `shadowExpire`.
- Require password change: set `pwdReset=TRUE` when ppolicy supports it.

`shadowExpire` requires the relevant shadow/posix schema. `pwdAccountLockedTime` and `pwdReset` require ppolicy support.

## Password policies

Password policy objects are stored below:

```text
ou=Policies,<Base DN>
```

The server must have the OpenLDAP ppolicy schema and overlay configured. The panel manages `pwdPolicy` objects and supports per-user assignment through `pwdPolicySubentry`.

Managed attributes include:

- `pwdMinLength`
- `pwdMinAge`
- `pwdMaxAge`
- `pwdInHistory`
- `pwdExpireWarning`
- `pwdGraceAuthnLimit`
- `pwdMaxFailure`
- `pwdFailureCountInterval`
- `pwdLockoutDuration`
- `pwdLockout`
- `pwdMustChange`
- `pwdAllowUserChange`
- `pwdSafeModify`

The UI deliberately does not auto-load server modules or modify ppolicy overlays behind the administrator's back.

## ACL Manager

The ACL Manager reads `olcDatabaseConfig` entries from:

```text
cn=config
```

and replaces ordered `olcAccess` values for a selected database. Only panel Administrators can use this UI/API.

The LDAP bind identity used by the panel must independently have permission to read and modify the relevant `cn=config` entry. A normal directory administrator such as `cn=admin,dc=example,dc=org` commonly does not have that access. Configure a dedicated administrative connection or ACL if you intend to manage `cn=config` remotely.

Every ACL update requires an explicit `APPLY` confirmation and is recorded in the audit log.

Before changing ACLs, ensure an out-of-band recovery method exists because a bad `olcAccess` rule can lock all remote administrators out.

## Replication Manager

Replication management writes:

- `olcSyncRepl`
- `olcMirrorMode`

to a selected `olcDatabaseConfig` entry.

Supported syncrepl fields include:

- `rid`
- provider URL
- search base
- bind DN
- bind credential
- sync type (`refreshOnly` or `refreshAndPersist`)
- schema checking
- retry policy
- TLS `reqcert`
- mirror mode

The credential is required by OpenLDAP's syncrepl configuration. The panel redacts it from status responses, pages and audit records.

## Roles and permissions

Administrator:

```text
*
```

Operator additionally receives read/write access for:

```text
ldap.sudo.*
ldap.ssh.*
ldap.lifecycle.*
```

and read access to:

```text
ldap.ppolicy.read
```

Read Only receives only the corresponding read permissions.

ACL changes, replication changes and password-policy writes remain Administrator-only through the web UI and through API permission checks.

## REST endpoints

New API routes include:

```text
GET    /api/v1/users/{username}/command-access
PUT    /api/v1/users/{username}/command-access
DELETE /api/v1/sudo-roles/{role_name}

GET    /api/v1/users/{username}/ssh-keys
POST   /api/v1/users/{username}/ssh-keys
DELETE /api/v1/users/{username}/ssh-keys

GET    /api/v1/users/{username}/lifecycle
PUT    /api/v1/users/{username}/lifecycle

GET    /api/v1/password-policies
PUT    /api/v1/password-policies/{name}
DELETE /api/v1/password-policies/{name}
PUT    /api/v1/users/{username}/password-policy

GET    /api/v1/config/databases
PUT    /api/v1/config/acl
PUT    /api/v1/config/replication
DELETE /api/v1/config/replication
```

Mutating API requests require the normal API authorization plus the existing confirmation/CSRF rules.
