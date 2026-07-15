"""Target parsing + nmap XML tests."""

import os
import tempfile

from whatthecipher.parser import parse_nmap_xml, parse_targets


def test_bare_domain():
    t = parse_targets(["example.com"])
    assert len(t) == 1
    assert t[0].host == "example.com" and t[0].port == 443


def test_host_port():
    t = parse_targets(["example.com:8443"])
    assert t[0].port == 8443


def test_url():
    t = parse_targets(["https://example.com:9000/path"])
    assert t[0].host == "example.com" and t[0].port == 9000


def test_cidr_expands():
    t = parse_targets(["192.168.1.0/30"])
    hosts = {x.host for x in t}
    assert "192.168.1.1" in hosts and "192.168.1.2" in hosts


def test_dedup():
    t = parse_targets(["example.com", "example.com"])
    assert len(t) == 1


def test_file_input():
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("a.com\nb.com:8443\n# comment\n\n")
        path = fh.name
    try:
        t = parse_targets([path])
        hosts = {x.host for x in t}
        assert "a.com" in hosts and "b.com" in hosts
        assert not any(x.host.startswith("#") for x in t)
    finally:
        os.unlink(path)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="93.184.216.34" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="443">
    <script id="ssl-enum-ciphers">
      <table key="TLSv1.2">
        <table><elem key="name">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</elem></table>
      </table>
    </script>
  </port></ports>
 </host>
</nmaprun>"""


def test_nmap_xml_parsing():
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
        fh.write(NMAP_XML)
        path = fh.name
    try:
        parsed = parse_nmap_xml(path)
        key = "93.184.216.34:443"
        assert key in parsed
        assert "TLSv1.2" in parsed[key]["protocols"]
        assert any("AES_128_GCM" in n for n in parsed[key]["ciphers"]["TLSv1.2"])
    finally:
        os.unlink(path)
