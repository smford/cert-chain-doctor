---
title: "cert-chain-doctor Documentation"
description: "Visual TLS Handshake & Intermediate Cert Debugger"
---

# cert-chain-doctor

[![CI](https://github.com/smford/cert-chain-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/smford/cert-chain-doctor/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-v0.1.0-blue.svg)](https://github.com/smford/cert-chain-doctor/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**The visual diagnostic tool and automatic repair surgeon for broken TLS handshakes and intermediate certificate chains.**

`cert-chain-doctor` is a single-binary CLI diagnostic tool (`cert-chain-doctor api.example.com` or `cert-chain-doctor --file bundle.pem`) that inspects TLS handshakes and X.509 certificate chains, diagnoses broken intermediate chains (*"works in Chrome, fails in curl/Alpine/Go"*), diagnoses misordered chains and redundant Root CAs, follows Authority Information Access (AIA) URLs to automatically fetch missing intermediate certificates, and outputs the exact repaired `.pem` bundle ready for Nginx, Envoy, or Kubernetes Secrets.

---

## Quick Demo

```text
================================================================================
              CERT CHAIN DOCTOR - TLS & CHAIN DIAGNOSTIC
================================================================================
Target:     api.example.com:443
SNI:        api.example.com
Remote IP:  93.184.216.34:443
TLS Conn:   TLS 1.3 | TLS_AES_128_GCM_SHA256 | ALPN: h2 | OCSP Stapled: No | Handshake: 14ms

CERTIFICATE CHAIN TREE:
├── [0] Leaf: api.example.com
│   ├── Subject:  CN=api.example.com, O=Example Corp
│   ├── Issuer:   CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc
│   ├── Validity: 2026-10-01 to 2027-01-01 (68 days left)
│   ├── Key:      ECDSA 256-bit | Sig: ECDSA-SHA256
│   ├── SANs:     api.example.com, example.com
│   ├── SKI:      02:4F:C9:13:78:7E:F7:9E:3B:5A:76:4D:EA:68:08:05:C2:A4:B9:ED
│   ├── AKI:      5F:87:AF:B0:7D:28:31:0E:BD:AC:2E:B7:BB:5D:E1:8A:0E:F1:42:00 -> MISSING INTERMEDIATE
│   └── AIA URL:  http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
│
└── [1] Intermediate (RESOLVED VIA AIA): DigiCert Global G2 TLS RSA SHA256 2020 CA1
    ├── Subject:  CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc
    ├── Issuer:   CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc
    ├── Validity: 2020-09-23 to 2030-09-22 (1428 days left)
    └── Fetched:  http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt

FINDINGS & DIAGNOSIS:
  [ERROR  ] MISSING_INTERMEDIATE_AIA_AVAILABLE
            Chain is missing intermediate CA certificate(s) ('unknown authority' error in curl/Alpine/Go).
            AIA download URL found: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
            -> Remediation: Run cert-chain-doctor with --fix-bundle <repaired.pem> to automatically fetch and assemble the complete chain.

--------------------------------------------------------------------------------
VERDICT: BROKEN CHAIN: Missing intermediate CA certificate (fixable via AIA with --fix-bundle)
--------------------------------------------------------------------------------
```

---

## Core Problems Solved

1. **The "Works in Chrome, Fails in curl/Alpine/Go" Outage**
   Desktop browsers silently fetch missing intermediate certificates using Authority Information Access (AIA) or reuse cached intermediates from other sessions. Command-line tools (`curl`), container runtimes (Alpine Docker), Python microservices, and Go binaries strictly enforce complete chains. `cert-chain-doctor` finds the gap, downloads the missing intermediate via AIA, and reassembles a valid fullchain.

2. **Misordered Certificate Bundles**
   Web servers like Nginx and Envoy require certificates in strict hierarchical order: `Leaf -> Intermediate 1 -> Intermediate 2`. Inverted or disordered bundles are flagged and automatically sorted.

3. **Handshake Bloat from Redundant Root CAs**
   Sending self-signed Root CAs in the TLS handshake wastes packet bytes, inflates latency, and can trigger extra TCP round-trips over mobile networks. `cert-chain-doctor` strips redundant roots automatically.

4. **Expiring & Weak Cryptography Warnings**
   Provides early warnings for certificates expiring within 14 days (customizable via `--expiry-warn`), flags deprecated signature algorithms (MD5, SHA-1), and identifies weak RSA keys (<2048 bits).

---

## Quick Navigation

* [Getting Started](getting-started.md) — Installation, basic usage, and first scan.
* [Worked Examples](examples.md) — Step-by-step solutions for Nginx, Kubernetes, STARTTLS, and batch audits.
* [CLI Reference](cli-reference.md) — Comprehensive flag specifications and exit codes.
* [Architecture](architecture.md) — Internal design, zero-CGO implementation, and PKI engine.
* [Troubleshooting](troubleshooting.md) — Diagnosing common TLS errors.
