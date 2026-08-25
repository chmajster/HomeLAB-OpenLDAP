from app.advanced import AttributeMapping, LDAPAdvancedPasswordService, LDAPQueryBuilder, decode_dn, encode_dn


def test_dn_encoding_roundtrip():
    dn = "uid=chris,ou=People,dc=example,dc=local"
    assert decode_dn(encode_dn(dn)) == dn


def test_query_builder_escapes_filter_values():
    condition = LDAPQueryBuilder.condition("uid", "equals", "*)(uid=*)")
    assert condition.startswith("(uid=")
    assert "*)(uid=*)" not in condition
    combined = LDAPQueryBuilder.combine("AND", [condition, "(objectClass=person)"])
    assert combined.startswith("(&")


def test_attribute_mapping_roundtrip():
    mapping = AttributeMapping(username="cn", email="mailPrimaryAddress")
    restored = AttributeMapping.from_json(mapping.to_json())
    assert restored.username == "cn"
    assert restored.email == "mailPrimaryAddress"


def test_advanced_password_schemes_do_not_contain_plaintext():
    password = "LongPasswordForLDAP!123"
    for scheme in ("SSHA", "SHA512", "PBKDF2", "CRYPT"):
        hashed = LDAPAdvancedPasswordService.hash_password(password, scheme)
        assert password not in hashed
        assert hashed.startswith("{")
