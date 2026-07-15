"""Generate demo reports with a spread of grades (for docs/screenshots)."""

from datetime import datetime, timezone

from whatthecipher import grading, recommendations, tls
from whatthecipher.exporters import html, json as json_exp, markdown
from whatthecipher.parser import Target
from whatthecipher.scanner import ScanResult


def _r(host, port, protos, cipher_codes_by_proto, cert=None, features=None):
    r = ScanResult(target=Target(host, port))
    r.reachable = True
    r.ip = "203.0.113." + str(abs(hash(host)) % 250 + 1)
    r.timestamp = datetime.now(timezone.utc).isoformat()
    r.duration = round(0.4 + (abs(hash(host)) % 900) / 1000, 3)
    r.protocols = protos
    r.ciphers = {
        p: [tls.classify_cipher(c, p) for c in codes]
        for p, codes in cipher_codes_by_proto.items()
    }
    r.certificate = cert
    r.features = features or {"hsts": True, "alpn": "h2", "http2": True,
                             "compression": None}
    r.vulnerabilities = grading.detect_vulnerabilities(r)
    r.grade = grading.grade(r)
    r.recommendations = recommendations.generate(r)
    return r


def _cert(subject, days, sha1=False, self_signed=False, bits=2048, mismatch=False):
    c = tls.CertificateInfo()
    c.subject = subject
    c.issuer = subject if self_signed else "DigiCert Global G2"
    c.san = [subject, "www." + subject]
    c.not_after = "2026-09-01T00:00:00+00:00"
    c.days_until_expiry = days
    c.signature_algorithm = "sha1" if sha1 else "sha256"
    c.uses_sha1 = sha1
    c.public_key_type = "RSA"
    c.public_key_bits = bits
    c.self_signed = self_signed
    c.hostname_mismatch = mismatch
    return c


ALL, NONE = (
    {"SSLv3": True, "TLS1.0": True, "TLS1.1": True, "TLS1.2": True, "TLS1.3": False},
    {"SSLv3": False, "TLS1.0": False, "TLS1.1": False, "TLS1.2": True, "TLS1.3": True},
)

results = [
    _r("secure.example.com", 443, NONE,
       {"TLS1.2": [0xC02F, 0xC030, 0xCCA8], "TLS1.3": [0x1301, 0x1302, 0x1303]},
       cert=_cert("secure.example.com", 61)),
    _r("legacy.example.net", 443,
       {"SSLv3": False, "TLS1.0": True, "TLS1.1": True, "TLS1.2": True, "TLS1.3": False},
       {"TLS1.0": [0xC013, 0x002F], "TLS1.1": [0xC013],
        "TLS1.2": [0xC02F, 0xC030, 0x009C]},
       cert=_cert("legacy.example.net", 20),
       features={"hsts": False, "alpn": "http/1.1", "http2": False}),
    _r("ancient.example.org", 443, ALL,
       {"SSLv3": [0x000A, 0x0005], "TLS1.0": [0x0005, 0x000A, 0x002F],
        "TLS1.1": [0x002F], "TLS1.2": [0x009C, 0x000A]},
       cert=_cert("ancient.example.org", 5, sha1=True, bits=1024),
       features={"hsts": False, "compression": "DEFLATE"}),
    _r("selfsigned.internal", 8443, NONE,
       {"TLS1.2": [0xC030], "TLS1.3": [0x1302]},
       cert=_cert("selfsigned.internal", 120, self_signed=True)),
]

# an unreachable host
un = ScanResult(target=Target("down.example.io", 443))
un.reachable = False
un.error = "connection refused"
results.append(un)

html.write(results, "/tmp/demo/report.html", "2.0.0")
markdown.write(results, "/tmp/demo/report.md", "2.0.0")
json_exp.write(results, "/tmp/demo/report.json", "2.0.0")
print("wrote /tmp/demo/report.{html,md,json}")
for r in results:
    g = r.grade.letter if r.grade else "—"
    print(f"  {r.target.host:24} grade={g}")
