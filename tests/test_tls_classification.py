"""Cipher classification tests (no network)."""

from whatthecipher import tls


def test_modern_aead_pfs_suite():
    c = tls.classify_cipher(0xC030, "TLS1.2")  # ECDHE_RSA_AES_256_GCM
    assert c.forward_secret is True
    assert c.aead is True
    assert c.bits == 256
    assert c.weaknesses == []
    assert c.strength == "recommended"


def test_rc4_is_insecure():
    c = tls.classify_cipher(0x0005, "TLS1.2")  # RSA_WITH_RC4_128_SHA
    assert "RC4" in c.weaknesses
    assert c.strength == "insecure"
    assert c.forward_secret is False


def test_3des_sweet32():
    c = tls.classify_cipher(0x000A, "TLS1.2")  # RSA_WITH_3DES_EDE_CBC_SHA
    assert "3DES" in c.weaknesses
    assert c.cbc is True
    assert c.bits == 112


def test_null_cipher():
    c = tls.classify_cipher(0x0001, "TLS1.2")  # RSA_WITH_NULL_MD5
    assert "NULL" in c.weaknesses
    assert "MD5" in c.weaknesses
    assert c.bits == 0


def test_export_and_anon():
    exp = tls.classify_cipher(0x0003, "TLS1.0")  # RSA_EXPORT_WITH_RC4_40_MD5
    assert "EXPORT" in exp.weaknesses
    anon = tls.classify_cipher(0x0034, "TLS1.2")  # DH_anon_WITH_AES_128_CBC_SHA
    assert "ANON" in anon.weaknesses


def test_tls13_suite():
    c = tls.classify_cipher(0x1302, "TLS1.3")  # AES_256_GCM_SHA384
    assert c.forward_secret is True
    assert c.aead is True
    assert c.strength == "recommended"


def test_unknown_suite_has_synthetic_name():
    assert tls.suite_name(0xABCD).startswith("TLS_UNKNOWN_")


def test_hostname_matching_wildcard():
    assert tls._hostname_matches("a.example.com", ["*.example.com"])
    assert not tls._hostname_matches("a.b.example.com", ["*.example.com"])
    assert tls._hostname_matches("example.com", ["example.com"])
