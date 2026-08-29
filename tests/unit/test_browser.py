from app.browser import LDAPBrowserService


def test_breadcrumbs_stay_inside_base_dn():
    crumbs = LDAPBrowserService.breadcrumbs("uid=alice,ou=People,dc=example,dc=org", "dc=example,dc=org")
    assert [item["dn"] for item in crumbs] == [
        "dc=example,dc=org",
        "ou=People,dc=example,dc=org",
        "uid=alice,ou=People,dc=example,dc=org",
    ]


def test_breadcrumbs_support_escaped_comma_rdn():
    crumbs = LDAPBrowserService.breadcrumbs(r"cn=Doe\, John,ou=People,dc=example,dc=org", "dc=example,dc=org")
    assert crumbs[-1]["dn"] == r"cn=Doe\, John,ou=People,dc=example,dc=org"


def test_breadcrumbs_reject_dn_outside_configured_base():
    try:
        LDAPBrowserService.breadcrumbs("uid=alice,dc=other,dc=org", "dc=example,dc=org")
    except ValueError as exc:
        assert "inside configured Base DN" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_entry_classification():
    assert LDAPBrowserService.classify({"dn": "ou=People,x", "ou": ["People"], "objectClass": ["organizationalUnit"]}) == ("ou", "People")
    assert LDAPBrowserService.classify({"dn": "uid=a,x", "uid": ["a"], "objectClass": ["person"]}) == ("user", "a")
    assert LDAPBrowserService.classify({"dn": "cn=g,x", "cn": ["g"], "objectClass": ["posixGroup"]}) == ("group", "g")
