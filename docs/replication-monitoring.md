# Replication monitoring

The Replication Manager now inspects configured `olcSyncRepl` definitions and performs a live provider health check.

For each consumer definition it reports:

- RID
- provider URL
- search base
- provider connectivity and bind result
- provider response latency
- local `contextCSN`
- provider `contextCSN`
- calculated replication lag
- health state

Health states:

- `healthy`: provider reachable and lag <= 30 seconds
- `lagging`: lag between 31 and 300 seconds
- `critical`: lag greater than 300 seconds
- `disconnected`: provider connection, TLS or bind failed
- `unknown`: provider is reachable but contextCSN timestamps cannot be compared

The monitor reads the existing syncrepl bind credential from `cn=config` only for the duration of the provider check. Credentials are redacted from API and UI output.

REST endpoint:

```text
GET /api/v1/replication/status
```

The endpoint is Administrator-only and honors the active multi-server LDAP selection, including `X-LDAP-Server-ID`.
