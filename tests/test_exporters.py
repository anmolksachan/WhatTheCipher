"""Exporter + certificate-parsing tests."""

import json as _json

from whatthecipher import tls
from whatthecipher.exporters import csv as csv_exp
from whatthecipher.exporters import html as html_exp
from whatthecipher.exporters import json as json_exp
from whatthecipher.exporters import markdown as md_exp

from .conftest import make_result, make_self_signed_der


def test_json_export_is_valid():
    r = make_result()
    payload = _json.loads(json_exp.export([r], "2.0.0"))
    assert payload["tool"] == "WhatTheCipher"
    assert payload["results"][0]["target"] == "example.com"
    assert payload["results"][0]["grade"]["letter"] in {"A", "A+"}


def test_csv_export_has_header_and_row():
    r = make_result()
    out = csv_exp.export([r])
    lines = out.strip().splitlines()
    assert lines[0].startswith("target,ip,port")
    assert "example.com" in lines[1]


def test_markdown_export_has_host_section():
    r = make_result()
    out = md_exp.export([r], "2.0.0")
    assert "## example.com:443" in out
    assert "Executive summary" in out


def test_html_export_is_selfcontained():
    r = make_result()
    out = html_exp.export([r], "2.0.0")
    assert out.strip().startswith("<!DOCTYPE html>")
    assert "example.com" in out
    # data injected, placeholder gone
    assert "/*__DATA__*/null" not in out
    # no external asset references
    assert "http://" not in out.split("github.com")[0]


def test_certificate_parse_self_signed():
    der = make_self_signed_der("selftest.local", days=45)
    cert = tls.parse_certificate_der(der, "selftest.local")
    assert cert.self_signed is True
    assert cert.public_key_type == "RSA"
    assert cert.public_key_bits == 2048
    assert cert.hostname_mismatch is False
    assert 40 <= cert.days_until_expiry <= 46
    assert cert.uses_sha1 is False


def test_certificate_hostname_mismatch():
    der = make_self_signed_der("wrong.local")
    cert = tls.parse_certificate_der(der, "expected.local")
    assert cert.hostname_mismatch is True


def test_certificate_sha1_detected():
    import pytest
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        der = make_self_signed_der("sha1.local", sha1=True)
    except UnsupportedAlgorithm:
        pytest.skip("crypto backend refuses to sign with SHA-1")
    cert = tls.parse_certificate_der(der, "sha1.local")
    assert cert.uses_sha1 is True
