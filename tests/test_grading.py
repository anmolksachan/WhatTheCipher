"""Grading + vulnerability detection tests."""

from whatthecipher import tls

from .conftest import make_result


def test_modern_config_grades_high():
    r = make_result()
    assert r.grade.letter in {"A", "A+"}
    assert r.grade.score >= 90


def test_insecure_cipher_fails():
    r = make_result(ciphers={"TLS1.2": [tls.classify_cipher(0x0005, "TLS1.2")]})
    assert r.grade.letter == "F"


def test_legacy_protocol_caps_grade():
    protos = {
        "SSLv3": False,
        "TLS1.0": True,
        "TLS1.1": False,
        "TLS1.2": True,
        "TLS1.3": True,
    }
    r = make_result(protocols=protos)
    # capped at B for TLS1.0
    assert r.grade.letter in {"B", "C", "D", "E", "F"}
    assert any("TLS 1.0" in cap for cap in r.grade.caps)


def test_sslv3_poodle_detected():
    protos = {
        "SSLv3": True,
        "TLS1.0": False,
        "TLS1.1": False,
        "TLS1.2": True,
        "TLS1.3": False,
    }
    r = make_result(protocols=protos)
    poodle = next(v for v in r.vulnerabilities if v.id == "POODLE")
    assert poodle.present is True


def test_sweet32_detected():
    r = make_result(ciphers={"TLS1.2": [tls.classify_cipher(0x000A, "TLS1.2")]})
    sweet = next(v for v in r.vulnerabilities if v.id == "SWEET32")
    assert sweet.present is True


def test_no_pfs_flagged():
    r = make_result(ciphers={"TLS1.2": [tls.classify_cipher(0x009C, "TLS1.2")]})
    nopfs = next(v for v in r.vulnerabilities if v.id == "NOPFS")
    assert nopfs.present is True


def _cert(**kw):
    c = tls.CertificateInfo()
    c.subject = "x.local"
    c.public_key_type = "RSA"
    c.public_key_bits = 2048
    c.days_until_expiry = 90
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_self_signed_grades_T():
    r = make_result(cert=_cert(self_signed=True))
    assert r.grade.letter == "T"


def test_hostname_mismatch_grades_M():
    r = make_result(cert=_cert(hostname_mismatch=True))
    assert r.grade.letter == "M"


def test_mismatch_wins_over_self_signed():
    r = make_result(cert=_cert(self_signed=True, hostname_mismatch=True))
    assert r.grade.letter == "M"


def test_expired_grades_T():
    r = make_result(cert=_cert(expired=True))
    assert r.grade.letter == "T"


def test_healthy_cert_does_not_trigger_gate():
    r = make_result(cert=_cert())
    assert r.grade.letter in {"A", "A+"}
