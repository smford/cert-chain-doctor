# cert-chain-doctor

[![CI](https://github.com/smford/cert-chain-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/smford/cert-chain-doctor/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/smford/cert-chain-doctor)](https://goreportcard.com/report/github.com/smford/cert-chain-doctor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **The visual diagnostic tool and automatic repair surgeon for broken TLS handshakes and intermediate certificate chains.**

`cert-chain-doctor` is a single-binary CLI tool that inspects TLS handshakes and X.509 certificate chains, clearly explains broken chains with a visual ASCII tree diagram, and automatically downloads missing intermediate certificates from Authority Information Access (AIA) servers to output clean, production-ready `.pem` bundles.

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
  [ERROR  ] MISSING_INTERMEDIATE_AIA_AVAILABLE
            Chain is missing intermediate CA certificate(s) ('unknown authority' error in curl/Alpine/Go).
            AIA download URL found: http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt
            -> Remediation: Run cert-chain-doctor with --fix-bundle <repaired.pem> to automatically fetch and assemble the complete chain.

--------------------------------------------------------------------------------
VERDICT: BROKEN CHAIN: Missing intermediate CA certificate (fixable via AIA with --fix-bundle)
--------------------------------------------------------------------------------
```

---

## What Problems Does This Tool Solve?

If you have ever managed a web service, API, or Kubernetes cluster, you have likely run into one of these frustrating TLS headaches:

### 1. The "Works in My Browser, Fails in Production" Mystery
* **The Problem:** You install an SSL certificate on your server. You open the site in Chrome or Safari on your laptop, and it displays a comforting green padlock. But 10 minutes later, your Docker containers, Go microservices, Python scripts, and `curl` commands crash with:
  ```text
  x509: certificate signed by unknown authority
  ```
* **Why it happens:** Desktop web browsers cheat. When a server forgets to serve its intermediate certificate, browsers quietly query the Certificate Authority's AIA (Authority Information Access) HTTP URL in the background or use certificates cached from other sites you visited earlier. Non-browser clients (like `curl`, Go, Python, and Alpine Linux) do not do this—they strictly require the server to provide the full chain.
* **How `cert-chain-doctor` solves it:** It dials your server and captures the exact certificates presented—even when the TLS handshake fails. It identifies the missing intermediate certificate, automatically downloads it from the CA's official AIA URL over HTTP, cryptographically verifies the chain (`Leaf.CheckSignatureFrom(Intermediate)`), and writes out a clean, ready-to-use fullchain `.pem` file.

### 2. The "Upside-Down Certificate" (Misordered Chain)
* **The Problem:** Web servers like Nginx, Envoy, and Apache expect your certificates in a strict sequence: your domain's leaf certificate first, followed by intermediate CA certificates. If certificates are pasted in reverse order or scrambled, strict TLS clients drop the connection.
* **How `cert-chain-doctor` solves it:** It analyzes cryptographic signatures and Subject/Authority Key Identifiers (`SKI`/`AKI`) to detect inverted or scrambled chains, and automatically sorts them in the correct `Leaf -> Intermediate 1 -> Intermediate 2` sequence.

### 3. Handshake Payload Bloat (Redundant Root CA)
* **The Problem:** Many administrators accidentally copy the Root CA certificate into their server bundle. Because clients already have the Root CA installed in their operating system trust store, sending the Root CA over the wire is completely redundant. It wastes bytes on every new TLS connection and can force TLS handshakes into additional TCP round trips on mobile connections.
* **How `cert-chain-doctor` solves it:** It flags redundant Root CAs with a warning badge and automatically strips them when generating repaired bundles.

### 4. Silent Expirations & Insecure Cryptography
* **The Problem:** Certificates expire quietly, or use weak 1024-bit RSA keys or deprecated SHA-1 signatures that modern operating systems reject.
* **How `cert-chain-doctor` solves it:** It alerts you with configurable expiry thresholds (failing with exit code `2` if a certificate expires within 14 days), checks CA/Browser Forum 398-day maximum validity limits, and flags insecure keys and signature algorithms.

---

## Worked Examples & Common Tasks

### Task 1: Diagnose Why `curl` or Alpine Fails on Your Domain
Run `cert-chain-doctor` against any domain to instantly see what certificates are sent and whether intermediate CAs are missing:

```bash
cert-chain-doctor api.example.com
```

### Task 2: Automatically Repair a Broken Intermediate Chain
Fix a broken server certificate chain by automatically downloading missing intermediate CAs and outputting a clean bundle for Nginx or Envoy:

```bash
cert-chain-doctor api.example.com --fix-bundle /etc/ssl/certs/repaired-fullchain.pem
```

Then simply update your Nginx configuration:
```nginx
ssl_certificate /etc/ssl/certs/repaired-fullchain.pem;
ssl_certificate_key /etc/ssl/private/server.key;
```

### Task 3: Export a Repaired Chain Directly as a Kubernetes Secret
Generate a ready-to-apply Kubernetes TLS Secret manifest with your repaired bundle base64-encoded:

```bash
cert-chain-doctor api.example.com \
  --k8s-secret my-api-tls \
  --k8s-namespace production \
  --fix-bundle /tmp/repaired.pem > k8s-tls-secret.yaml

kubectl apply -f k8s-tls-secret.yaml
```

### Task 4: Validate Local PEM Files Offline in CI/CD
Check your certificate bundles in git or deployment pipelines before releasing to production:

```bash
cert-chain-doctor --file /path/to/server-bundle.pem --expiry-warn 30
```
* Returns exit code `0` if the bundle is complete, trusted, and healthy.
* Returns exit code `1` if the chain is broken, missing intermediates, or invalid.
* Returns exit code `2` if any certificate in the chain expires within 30 days.

### Task 5: Diagnose an IP Address with SNI Override
When troubleshooting a specific load balancer, ingress controller, or origin IP before updating DNS:

```bash
cert-chain-doctor 198.51.100.24:443 --sni api.example.com
```

### Task 6: Audit Mail and Database Servers with STARTTLS
Probe services that upgrade plain-text connections to TLS:

```bash
# SMTP (Port 587)
cert-chain-doctor mail.example.com:587 --starttls smtp

# PostgreSQL (Port 5432)
cert-chain-doctor db.internal.net:5432 --starttls postgres

# IMAP (Port 143)
cert-chain-doctor imap.example.com:143 --starttls imap
```

### Task 7: Batch Audit Multiple Endpoints
Scan an entire fleet of domains or microservices from a text file:

```bash
cat <<EOF > endpoints.txt
api.example.com:443
auth.example.com:443
mail.example.com:587
db.internal.net:5432
EOF

cert-chain-doctor --hosts-file endpoints.txt
```

Outputs an aligned summary table:
```
================================================================================
                   CERT CHAIN DOCTOR - BATCH AUDIT SUMMARY
================================================================================
TARGET                           TLS        STATUS       EXPIRY   FINDINGS
--------------------------------------------------------------------------------
api.example.com:443              TLS 1.3    HEALTHY      68d      None
auth.example.com:443             TLS 1.3    BROKEN       89d      MISSING_INTERMEDIATE
mail.example.com:587             TLS 1.3    WARNING      4d       CERT_EXPIRING_SOON
db.internal.net:5432             TLS 1.3    HEALTHY      180d     None
--------------------------------------------------------------------------------
```

### Task 8: Check OCSP Responder Reachability
Actively verify that the Certificate Authority's OCSP server is reachable and answering:

```bash
cert-chain-doctor api.example.com --check-revocation
```

### Task 9: Run as a Diagnostic Microservice / Kubernetes Sidecar
Start a lightweight HTTP diagnostic server:

```bash
cert-chain-doctor serve --addr :8080
```
* `GET /healthz` — Service health check (`{"status":"ok"}`)
* `GET /version` — Version and build information
* `GET /diagnose?target=api.example.com` — Full JSON diagnosis endpoint

---

## Installation

### Pre-Compiled Binaries
Download the latest binary for your operating system (Linux, macOS, Windows) from the [Releases](https://github.com/smford/cert-chain-doctor/releases) page.

### Homebrew (macOS / Linux)
```bash
brew tap smford/homebrew-tap
brew install cert-chain-doctor
```

### From Source (Go 1.23+)
```bash
git clone https://github.com/smford/cert-chain-doctor.git
cd cert-chain-doctor
make build
# Binary created at bin/cert-chain-doctor
```

---

## CLI Reference

```text
Usage:
  cert-chain-doctor [flags] <host[:port]>
  cert-chain-doctor --file <bundle.pem> [flags]
  cert-chain-doctor --hosts-file <hosts.txt> [flags]
  cert-chain-doctor serve [--addr :8080]

Flags:
  -file string
        Analyze a local PEM certificate file/bundle offline instead of dialing a network host
  -fix-bundle string
        Automatically chase AIA URLs, verify signatures, and write clean fullchain PEM bundle to this path
  -sni string
        Override TLS Server Name Indication (SNI)
  -alpn string
        Comma-separated list of ALPN protocols (e.g. 'h2,http/1.1')
  -starttls string
        STARTTLS protocol (smtp, imap, pop3, postgres, mysql)
  -expiry-warn int
        Warning threshold in days for certificate expiration (default 14)
  -format string
        Output format: 'text' (default) or 'json'
  -color string
        ANSI color output: 'auto' (default), 'always', or 'never'
  -k8s-secret string
        Generate a Kubernetes TLS Secret YAML manifest with the repaired bundle
  -k8s-namespace string
        Kubernetes namespace for generated TLS secret (default "default")
  -hosts-file string
        Batch audit multiple endpoints from a newline-delimited text file
  -check-revocation
        Actively check reachability of OCSP and CRL distribution endpoints
  -ca-file string
        Path to custom CA root certificate(s) PEM file for verification
  -timeout int
        Network dial and handshake timeout in seconds (default 10)
  -v, -version
        Print version information and exit
```

---

## Exit Codes

`cert-chain-doctor` adheres to standard UNIX exit conventions for use in deployment scripts and CI/CD pipelines:

| Exit Code | Meaning | Description |
|:---------:|---------|-------------|
| **`0`** | **Healthy / Repaired** | Certificate chain is complete and trusted, or `--fix-bundle` successfully repaired it. |
| **`1`** | **Broken / Error** | Verification failed (missing intermediate, hostname mismatch, expired cert, or connection error). |
| **`2`** | **Expiring Soon** | Chain is cryptographically trusted, but at least one certificate expires within `--expiry-warn` days. |

---

## Architecture

```
cert-chain-doctor
├── cmd/cert-chain-doctor/   # CLI entry point, argument reordering, batch runner, HTTP serve mode
├── internal/
│   ├── analyzer/            # Continuity validator, SKI/AKI matching, CA/B Forum checks, SAN verifier
│   ├── aia/                 # HTTP AIA fetcher (DER/PEM/PKCS#7), signature verifier & bundle repairer
│   ├── probe/               # Custom TLS dialer, STARTTLS protocol drivers (SMTP, Postgres, etc.)
│   ├── render/              # Visual ASCII tree diagram, ANSI color engine, K8s Secret generator
│   ├── revocation/          # Active OCSP & CRL endpoint reachability prober
│   └── testpki/             # In-memory dynamic PKI engine with httptest AIA server for testing
├── Makefile                 # Cross-platform build, test-race, vet, clean
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
