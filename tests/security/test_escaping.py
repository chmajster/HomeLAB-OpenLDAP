from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn


def test_filter_escaping_blocks_filter_injection():
    attack = "*)(|(uid=*))"
    escaped = escape_filter_chars(attack)
    assert attack not in escaped
    assert "\\2a" in escaped


def test_rdn_escaping_blocks_dn_breakout():
    value = "admin,ou=Other"
    escaped = escape_rdn(value)
    assert escaped != value
    assert "\\," in escaped
