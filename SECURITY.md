# Security Policy

Do not report vulnerabilities in a public issue when they expose credentials, authentication bypass, LDAP injection, command injection or remote code execution. Use GitHub private vulnerability reporting when enabled.

Secrets must not be committed. LDAP bind passwords are encrypted in the application database; the encryption key is stored separately in `/etc/homelab-openldap-manager/app.env`. API tokens are stored only as SHA-256 hashes and panel passwords use Argon2id.

The application escapes LDAP filters and RDN values. System commands use fixed argv lists and never `shell=True`. Backup/restore is delegated to a root-owned restricted helper.
