"""Optional / pluggable modules.

These are opt-in enrichers that reach out to third-party services or implement
heavier fingerprinting. They are intentionally decoupled from the core scan so
the base tool stays fast and dependency-light.

Status:
  ct.py            — implemented (crt.sh Certificate Transparency search)
  fingerprint.py   — JARM/JA3 scaffolding with a working server-hello hash
  integrations.py  — Shodan / Censys / SSL Labs / Mozilla — documented stubs
"""
