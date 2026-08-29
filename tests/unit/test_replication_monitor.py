from app.ldap.replication import LDAPReplicationMonitorService


def test_parse_syncrepl_and_redact_credentials():
    raw = 'rid=001 provider=ldap://ldap01:389 bindmethod=simple binddn="cn=sync,dc=example,dc=org" credentials="secret value" searchbase="dc=example,dc=org" type=refreshAndPersist'
    parsed = LDAPReplicationMonitorService.parse_syncrepl(raw)
    assert parsed["rid"] == "001"
    assert parsed["provider"] == "ldap://ldap01:389"
    assert parsed["binddn"] == "cn=sync,dc=example,dc=org"
    assert parsed["credentials"] == "secret value"
    redacted = LDAPReplicationMonitorService.redact(raw)
    assert "secret value" not in redacted
    assert "credentials=***" in redacted


def test_context_csn_timestamp_and_health_thresholds():
    stamp = LDAPReplicationMonitorService.newest_csn_timestamp(
        ["20260829120000.000000Z#000000#001#000000", "20260829120530.000000Z#000000#001#000000"]
    )
    assert stamp is not None
    assert stamp.hour == 12
    assert stamp.minute == 5
    assert LDAPReplicationMonitorService.classify(connected=True, lag_seconds=0) == "healthy"
    assert LDAPReplicationMonitorService.classify(connected=True, lag_seconds=30) == "healthy"
    assert LDAPReplicationMonitorService.classify(connected=True, lag_seconds=31) == "lagging"
    assert LDAPReplicationMonitorService.classify(connected=True, lag_seconds=301) == "critical"
    assert LDAPReplicationMonitorService.classify(connected=False, lag_seconds=None) == "disconnected"
    assert LDAPReplicationMonitorService.classify(connected=True, lag_seconds=None) == "unknown"
