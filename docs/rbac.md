# Custom RBAC

Panel authorization is database-backed. `PanelUser.role` stores a role name and effective permissions are resolved from `access_roles` on each authenticated request.

## Built-in roles

The application seeds three immutable roles:

- `Administrator` — wildcard `*`
- `Operator` — existing operational permissions
- `Read Only` — existing read permissions

This preserves compatibility with existing installations.

## Custom roles

Administrators can create custom roles under **Administration → Roles & Permissions** and assign them to panel users.

Custom roles can combine granular permissions such as:

```text
ldap.users.read
ldap.users.write
ldap.groups.read
ldap.groups.write
ldap.ou.read
ldap.ou.write
ldap.sudo.read
ldap.sudo.write
ldap.ssh.read
ldap.ssh.write
ldap.lifecycle.read
ldap.lifecycle.write
ldap.ppolicy.read
ldap.ppolicy.write
audit.read
```

Wildcard `*` is reserved for the built-in Administrator role. Built-in roles cannot be deleted or replaced through the RBAC API.

A disabled role resolves to an empty permission set.

## REST API

```text
GET    /api/v1/rbac/permissions
GET    /api/v1/rbac/roles
POST   /api/v1/rbac/roles
PUT    /api/v1/rbac/roles/{role_name}
DELETE /api/v1/rbac/roles/{role_name}?confirm=true
PUT    /api/v1/rbac/users/{user_id}/role
```

RBAC administration itself requires the built-in Administrator privilege (`*`). Role creation, updates, deletion and assignments are audit logged.

## Legacy web actions

Older form handlers originally distinguished only `Administrator`, `Operator` and `Read Only` by role name. Directory CRUD now checks concrete permissions directly. A dedicated web authorization guard protects older sudo, SSH, lifecycle, membership, unlock and LDIF mutation routes so a custom role cannot bypass its effective permissions.

Bulk Operations remain restricted to the built-in Administrator and Operator roles until bulk jobs are migrated to the future background-job engine.
