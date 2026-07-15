<div align="center">

# WhatTheCipher

**Modern TLS/SSL assessment framework — protocols, ciphers, certificates, grading & reports.**

*by [Anmol K Sachan](https://github.com/anmolksachan) · [@FR13ND0x7F](https://x.com/FR13ND0x7F)*

</div>

```
        _    _ _           _   _____ _          ____ _       _
       | |  | | |         | | |_   _| |        / ___(_)_ __ | |_  ___ _ _
       | |  | | |__   __ _| |_  | | | |__   ___| |   | | '_ \| '_ \/ -_) '_|
       | |/\| | '_ \ / _` | __| | | | '_ \ / _ \ |   | | |_) | | | \___|_|
       \  /\  / | | | (_| | |_  | | | | | |  __/ |___| | .__/| | | |
        \/  \/|_| |_|\__,_|\__| \_/ |_| |_|\___|\____|_|_|   |_| |_|
```

---

## What it is

WhatTheCipher started life as a small wrapper around nmap's `ssl-enum-ciphers`
that scraped `ciphersuite.info` with curl+grep and dumped an HTML page. Version 2
is a complete rewrite: a lightweight, native Python TLS scanner that enumerates
protocols and cipher suites by **crafting its own ClientHello messages at the
socket level** — the same technique used by SSLyze and testssl.sh — so it can
test legacy protocols and individual suites even when the local OpenSSL has them
compiled out. No HTML scraping anywhere; cipher metadata is derived from IANA
suite names plus a bundled JSON database.

Think of a small, readable blend of the ideas behind SSLyze, testssl.sh, the
Mozilla SSL Configuration Guide and the SSL Labs rating model — packaged as a
single `pip install`.

## Features

- **Native TLS engine** — protocol detection (SSLv3 → TLS 1.3) and fast
  pick-and-remove cipher enumeration via raw handshakes. No OpenSSL legacy build
  required.
- **Certificate analysis** — subject/issuer, SAN, validity, expiry countdown,
  signature algorithm, key type & size, SHA-1 detection, self-signed / expired /
  hostname-mismatch checks, OCSP & CRL endpoints, must-staple.
- **Passive vulnerability detection** — DROWN, POODLE, BEAST, Sweet32, FREAK,
  Logjam, Lucky13, RC4, NULL/anonymous suites, ROBOT indicator, CRIME, missing
  forward secrecy, and more, each mapped to its CVE.
- **SSL Labs-style grading** — A+ … F with documented caps and a 0–100 score.
- **Actionable recommendations** — referenced to the relevant RFCs and the
  Mozilla SSL Configuration Guide.
- **Parallel scanning** — `ThreadPoolExecutor`, hundreds of hosts at once, live
  Rich progress.
- **Rich terminal UI** — colored panels, tables and a summary dashboard.
- **Four report formats** — a self-contained interactive **HTML** dashboard
  (dark/light, search, sortable tables, copy-to-markdown, charts), plus **JSON**,
  **Markdown** and **CSV**.
- **Flexible input** — domains, IPs, URLs, `host:port`, target files, CIDR
  ranges and stdin.
- **STARTTLS** — SMTP, IMAP, POP3, FTP, XMPP.
- **Interop** — ingest existing nmap `ssl-enum-ciphers` XML.

## Installation

```bash
# from source
git clone https://github.com/anmolksachan/WhatTheCipher
cd WhatTheCipher
pip install .

# or, once published
pip install whatthecipher
```

Requires **Python ≥ 3.11**. Dependencies: `rich`, `cryptography`.

## Usage

```bash
wtc example.com                       # single host
wtc example.com -p 8443               # custom port
wtc example.com google.com github.com # several hosts
wtc targets.txt                       # a file of targets
wtc --cidr 192.168.1.0/24             # a whole range
cat hosts.txt | wtc --stdin           # from stdin

# reports (written into ./wtc-report/ by default, override with -o)
wtc example.com --html --json --csv --markdown -o report/

# performance
wtc targets.txt --threads 50 --timeout 5

# STARTTLS
wtc mail.example.com --starttls smtp -p 587

# ingest an existing nmap scan
wtc --nmap-xml scan.xml

# quieter / louder
wtc example.com --no-banner --no-details
wtc example.com --verbose --log-file scan.log
```

### All flags

| Flag | Purpose |
|---|---|
| `-p, --port` | Default port (443) |
| `--cidr RANGE` | Scan a CIDR range (repeatable) |
| `--stdin` | Read targets from stdin |
| `--starttls PROTO` | smtp / imap / pop3 / ftp / xmpp |
| `--nmap-xml FILE` | Ingest nmap ssl-enum-ciphers XML |
| `--threads N` | Concurrent workers (20) |
| `--timeout S` | Per-connection timeout (8s) |
| `--json / --html / --csv / --markdown` | Report formats |
| `-o, --output DIR` | Report output directory |
| `--no-cert / --no-features` | Skip cert / feature detection |
| `--no-banner / --no-details` | Quieter terminal output |
| `-v/--verbose`, `-q/--quiet`, `--log-file` | Logging |

The process exit code is non-zero (3) if any host grades F/T/M, so it drops
straight into CI gates.

## Architecture

```
whatthecipher/
├── cli.py            # argparse CLI, wiring
├── scanner.py        # orchestration, ScanResult, ThreadPoolExecutor
├── tls.py            # native TLS engine: ClientHello, ciphers, cert, STARTTLS
├── parser.py         # target parsing (domain/IP/URL/CIDR/file/stdin) + nmap XML
├── grading.py        # SSL Labs-style grade + passive vuln detection
├── recommendations.py# remediation advice (RFC / Mozilla references)
├── reporter.py       # Rich terminal output
├── exporters/        # html · json · markdown · csv
├── utils/            # logger · colors · banner
├── modules/          # optional: crt.sh (done), JARM/JA3, Shodan/Censys/SSL Labs
└── data/             # bundled IANA cipher-suite database
```

## Output formats

**JSON** — machine-readable, one object per host with full protocol, cipher,
certificate, vulnerability and recommendation detail. Ideal for automation.

```json
{
  "tool": "WhatTheCipher",
  "results": [{
    "target": "example.com", "port": 443,
    "grade": { "letter": "A", "score": 97 },
    "protocols": {
      "TLS1.3": { "supported": true, "ciphers": [
        { "name": "TLS_AES_256_GCM_SHA384", "bits": 256,
          "forward_secret": true, "aead": true, "strength": "recommended" }
      ]}
    },
    "certificate": { "subject": "example.com", "days_until_expiry": 61 },
    "vulnerabilities": [ { "id": "POODLE", "present": false } ]
  }]
}
```

**HTML** — a single self-contained file (no external assets, works offline):
grade-distribution donut, risk overview, per-host cards with an "instrument
panel" protocol strip, sortable cipher tables, certificate detail, findings and
copy-to-markdown recommendations, plus a dark/light toggle and live search.

**Markdown** — an executive-summary table followed by a per-host section, ready
to paste into a pentest report.

**CSV** — one summary row per host for triage in a spreadsheet.

## Optional modules

`whatthecipher/modules/` holds opt-in enrichers, decoupled to keep the core fast:

- `ct.py` — **implemented** crt.sh Certificate Transparency search / subdomain
  discovery (standard library only).
- `fingerprint.py` — a working ServerHello fingerprint, plus JARM / JA3S
  scaffolds with references to the reference algorithms.
- `integrations.py` — documented stubs for Shodan, Censys, Qualys SSL Labs,
  Mozilla config comparison and DNS CAA, each with a stable signature.

## Roadmap

- Full JARM & JA3S fingerprints
- Active Heartbleed / ROBOT / CCS-injection probes
- SSLv2 handshake probe and weak-DH parameter extraction
- STARTTLS for LDAP, MySQL, PostgreSQL, RDP, MQTT, Redis
- HTTP/3 & QUIC detection, DNSSEC & CAA, full HTTP security-header audit
- Shodan / Censys / SSL Labs / Mozilla enrichment wired into the report

## Contributing

Issues and PRs welcome. Please run the dev checks before opening a PR:

```bash
pip install -e ".[dev]"
pre-commit run --all-files
pytest --cov=whatthecipher
```

## FAQ

**Does it need nmap?** No — the native engine is self-contained. nmap XML can be
ingested for interoperability, but it isn't required.

**Can it test SSLv2 / very old protocols my OpenSSL refuses?** SSLv3–TLS1.3 are
tested with raw handshakes independent of the local OpenSSL. A dedicated SSLv2
probe is on the roadmap.

**Is it safe to run against systems I don't own?** Only scan hosts you are
authorised to test. TLS enumeration is active traffic.

## Acknowledgements

Inspired by the excellent work of SSLyze, testssl.sh, nmap's `ssl-enum-ciphers`,
the Mozilla SSL Configuration Guide and Qualys SSL Labs. Cipher metadata follows
the IANA TLS Cipher Suite registry.

## License

MIT © Anmol K Sachan
