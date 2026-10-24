# cert-chain-doctor

[![Go Report Card](https://goreportcard.com/badge/github.com/smford/cert-chain-doctor)](https://goreportcard.com/report/github.com/smford/cert-chain-doctor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`cert-chain-doctor` is a single-binary CLI diagnostic tool that inspects TLS handshakes and X.509 certificate chains, pinpoints broken intermediate chains (*"works in Chrome, fails in curl/Alpine/Go"*), diagnoses misordered chains and redundant Root CAs, follows Authority Information Access (AIA) URLs to automatically fetch missing intermediate certificates, and outputs the exact repaired `.pem` bundle ready for Nginx, Envoy, or Kubernetes TLS Secrets.

```
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
  [ERROR]   MISSING_INTERMEDIATE_AIA_AVAILABLE
            Chain is missing intermediate CA certificate(s) ('unknown authority' error in curl/Alpine/Go).
            AIA download URL found: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
            -> Remediation: Run cert-chain-doctor with --fix-bundle <repaired.pem> to automatically fetch and assemble the complete chain.

--------------------------------------------------------------------------------
VERDICT: BROKEN CHAIN: Missing intermediate CA certificate (fixable via AIA with --fix-bundle)
--------------------------------------------------------------------------------
```

---

## The Problem: "Works in Chrome, Fails in curl/Alpine/Go"

One of the most frequent SRE and production outages occurs when a TLS certificate works perfectly in desktop web browsers but fails catastrophically with `x509: certificate signed by unknown authority` in:
- `curl` / `wget`
- Alpine Linux Docker containers
- Python (`requests` / `urllib3`)
- Go microservices
- Kubernetes admission webhooks

### Why does this happen?
Desktop web browsers (Chrome, Edge, Safari) cache previously seen intermediate certificates and automatically perform **Authority Information Access (AIA) chasing** over HTTP when an intermediate is omitted.

Standard TLS clients (`curl`, Go's `crypto/tls`, OpenSSL, Python) strictly follow RFC 5246 / RFC 8446 and **do not** chase AIA links. If your server only serves the leaf certificate and omits the intermediate CA certificate, non-browser clients immediately drop the connection with an untrusted root or unknown authority error.

`cert-chain-doctor` solves this by:
1. Dialing with `InsecureSkipVerify: true` to capture raw peer certificates even when verification fails.
2. Detecting the exact intermediate gap using Subject Key Identifier (`SKI`) and Authority Key Identifier (`AKI`) links.
3. Automatically querying the AIA URL to download the missing intermediate DER/PEM certificates.
4. Cryptographically verifying the entire hierarchy (`leaf.CheckSignatureFrom(intermediate)`).
5. Writing out the clean, correctly-ordered `.pem` bundle ready to drop into Nginx, Envoy, Apache, or Kubernetes Secrets.

---

## Features

- **Automated AIA Chain Repair (`--fix-bundle <out.pem>`)**: Downloads missing intermediates (DER/PEM), verifies cryptographic signatures, orders certificates `Leaf -> Intermediate(s)`, and strips redundant Root CAs.
- **Visual ASCII Chain Tree**: Renders an intuitive tree diagram showing cert roles, validity windows, key types, SANs, and cryptographic parent-child links.
- **Misordered Chain Detection**: Flags when an intermediate is placed before the leaf, or certificates are inverted.
- **Redundant Root CA Warning**: Identifies self-signed root certificates bundled into the server handshake that unnecessarily inflate TLS handshake packet size.
- **Cryptographic Weakness Auditing**: Catches deprecated signatures (`MD5`, `SHA1`) and short RSA keys (`<2048` bits).
- **STARTTLS Protocol Support**: Probes TLS after plain-text handshakes on `smtp`, `imap`, `pop3`, `postgres`, and `mysql`.
- **Local PEM File Support (`--file <bundle.pem>`)**: Audits and fixes certificates offline in CI/CD pipelines before deployment.
- **Machine-Readable Output (`--format json`)**: Full JSON schema for scripting, alerts, and integration into monitoring agents.
- **Zero-CGO & Minimal Footprint**: Compiles as a statically linked binary with standard library dependencies.

---

## Installation

### From Source
Requires Go 1.23+:

```bash
git clone https://github.com/smford/cert-chain-doctor.git
cd cert-chain-doctor
make build
# Binary created at bin/cert-chain-doctor
```

Or install directly to your `$GOPATH/bin`:
```bash
go install github.com/smford/cert-chain-doctor/cmd/cert-chain-doctor@latest
```

---

## Usage

### 1. Diagnose a Live Host
```bash
cert-chain-doctor api.example.com
```

### 2. Auto-Repair Broken Intermediate Chain
```bash
cert-chain-doctor api.example.com --fix-bundle /etc/ssl/repaired-fullchain.pem
```

### 3. Diagnose an IP with SNI Override
```bash
cert-chain-doctor 192.0.2.1:443 --sni api.example.com
```

### 4. Inspect a Local Bundle File Offline
```bash
cert-chain-doctor --file /path/to/server-bundle.pem
```

### 5. Check Mail / Database Servers via STARTTLS
```bash
# SMTP
cert-chain-doctor mail.example.com:587 --starttls smtp

# PostgreSQL
cert-chain-doctor db.internal.net:5432 --starttls postgres

# IMAP
cert-chain-doctor imap.example.com:143 --starttls imap
```

### 6. Verify Against Custom CA (Private PKI)
```bash
cert-chain-doctor internal.service.local --ca-file /etc/pki/internal-ca.pem
```

### 7. JSON Output for CI/CD Pipelines
```bash
cert-chain-doctor api.example.com --format json | jq '.analysis.is_valid'
```

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `<host[:port]>` | Port `:443` | Target server address to probe |
| `--file <path>` | `""` | Local PEM certificate bundle file to inspect offline |
| `--fix-bundle <path>` | `""` | Automatically fetch AIA intermediates and write clean fullchain PEM |
| `--sni <hostname>` | host | Override TLS Server Name Indication header |
| `--alpn <protocols>` | `""` | Comma-separated list of ALPN protocols (e.g. `h2,http/1.1`) |
| `--starttls <protocol>`| `""` | STARTTLS protocol: `smtp`, `imap`, `pop3`, `postgres`, `mysql` |
| `--expiry-warn <days>` | `14` | Fail with exit code 2 if any cert expires within N days |
| `--format <text\|json>`| `text` | Output format: ASCII tree diagram or structured JSON |
| `--ca-file <path>` | system | Path to custom root CA certificates PEM file |
| `--timeout <sec>` | `10` | Dial and handshake timeout in seconds |
| `--version` | `false` | Print version information and exit |

---

## Exit Codes

`cert-chain-doctor` adheres to standard UNIX exit conventions for use in deployment checks and CI/CD pipelines:

| Exit Code | Meaning |
|:---------:|---------|
| `0` | **Healthy**: Chain is complete, cryptographically verified, and valid (or `--fix-bundle` successfully repaired it). |
| `1` | **Broken / Error**: Chain verification failed (missing intermediate, hostname mismatch, expired cert, or dial failure). |
| `2` | **Expiring Soon**: Chain is valid, but at least one certificate expires within the `--expiry-warn` window. |

---

## Architecture

```
cert-chain-doctor
├── cmd/cert-chain-doctor/   # CLI entry point, argument reordering, exit code engine
├── internal/
│   ├── analyzer/            # X.509 chain continuity, SKI/AKI matching, SAN & expiry verification
│   ├── aia/                 # HTTP AIA fetcher (DER/PEM), signature verifier & bundle builder
│   ├── probe/               # Custom crypto/tls dialer, STARTTLS protocol drivers, file loader
│   ├── render/              # ASCII tree diagram generator and JSON formatter
│   └── testpki/             # In-memory dynamic PKI engine with httptest AIA server for testing
├── Makefile                 # Build, test, test-race, vet, clean
└── README.md
```

---

## Development & Testing

Run all unit and integration tests:
```bash
make test
```

Run race condition detection:
```bash
make test-race
```

Run static analysis:
```bash
make vet
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
