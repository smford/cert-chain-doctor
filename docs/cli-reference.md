---
title: "CLI Reference"
description: "Comprehensive command-line flags, options, exit codes, and environment variables"
---

# CLI Reference

`cert-chain-doctor` is controlled via standard command-line flags and POSIX environment variables.

---

## Command Synopsis

```text
cert-chain-doctor [flags] <host[:port]>
cert-chain-doctor --file <bundle.pem> [flags]
cert-chain-doctor --hosts-file <hosts.txt> [flags]
cert-chain-doctor serve [--addr :8080]
cert-chain-doctor --version
```

---

## Options & Flags

### Target & Mode Selection

| Flag | Type | Default | Description |
|:-----|:----:|:-------:|:------------|
| `<host[:port]>` | argument | — | The network target to dial. If port is omitted, `:443` is assumed. |
| `--file <path>` | string | `""` | Analyze a local `.pem` certificate file/bundle offline instead of dialing a network endpoint. |
| `--hosts-file <path>` | string | `""` | Batch audit multiple endpoints listed line-by-line in a plain-text file. Lines starting with `#` are ignored. |
| `serve [--addr <ip:port>]` | subcommand | `:8080` | Run as an HTTP microservice daemon exposing `/diagnose?target=<host>`. |

### Repair & Export

| Flag | Type | Default | Description |
|:-----|:----:|:-------:|:------------|
| `--fix-bundle <path>` | string | `""` | Automatically fetch missing intermediates via AIA HTTP URLs, verify signatures, and write clean fullchain PEM bundle to this path. |
| `--k8s-secret <name>` | string | `""` | Generate a `kubernetes.io/tls` Kubernetes Secret YAML manifest containing the repaired certificate bundle. |
| `--k8s-namespace <ns>` | string | `"default"` | Kubernetes namespace applied to the generated TLS Secret manifest. |

### TLS & Network Configuration

| Flag | Type | Default | Description |
|:-----|:----:|:-------:|:------------|
| `--sni <hostname>` | string | target host | Override the TLS Server Name Indication (SNI) header in the `ClientHello`. |
| `--alpn <protocols>` | string | `""` | Comma-separated list of Application-Layer Protocol Negotiation tokens (e.g. `h2,http/1.1`). |
| `--starttls <protocol>` | string | `""` | Negotiate TLS via plain-text command protocol: `smtp`, `imap`, `pop3`, `postgres`, `mysql`. |
| `--ca-file <path>` | string | system store | Path to a custom CA root certificate(s) PEM file for private or enterprise PKI verification. |
| `--timeout <sec>` | int | `10` | Network dial and TLS handshake timeout in seconds. |
| `--check-revocation` | bool | `false` | Actively query reachability of OCSP responder and CRL distribution endpoints over HTTP. |

### Output & Formatting

| Flag | Type | Default | Description |
|:-----|:----:|:-------:|:------------|
| `--format <text\|json>` | string | `"text"` | Output format: human-readable visual ASCII tree (`text`) or structured machine-readable JSON (`json`). |
| `--color <auto\|always\|never>` | string | `"auto"` | Terminal ANSI color highlighting. Auto-disabled when piped or when `NO_COLOR` is set. |
| `--expiry-warn <days>` | int | `14` | Expiration warning threshold in days (triggers exit code 2 if certificate expires within this window). |
| `-v, --version` | bool | `false` | Print detailed binary version, git commit hash, and build timestamp. |

---

## Exit Codes

`cert-chain-doctor` adheres to standard UNIX exit conventions for automated pipelines:

| Exit Code | Status | Meaning |
|:---------:|:-------|:--------|
| **`0`** | **HEALTHY / REPAIRED** | The certificate chain is cryptographically valid, properly ordered, and trusted by the root store (or `--fix-bundle` successfully reconstructed it). |
| **`1`** | **BROKEN / ERROR** | The chain failed verification (missing intermediate, misordered chain, hostname mismatch, expired cert, or network dial failure). |
| **`2`** | **EXPIRING SOON** | The chain is cryptographically trusted, but at least one certificate expires within the `--expiry-warn` window (default 14 days). |

---

## Environment Variables

| Variable | Description |
|:---------|:------------|
| `NO_COLOR` | When set to any non-empty value, disables all ANSI color formatting (per [no-color.org](https://no-color.org)). |
| `SSL_CERT_FILE` | Standard Go override path to a custom CA certificate PEM bundle. |
| `SSL_CERT_DIR` | Standard Go override path to a directory of trusted CA certificate PEM files. |
| `HTTP_PROXY` / `HTTPS_PROXY` | Standard HTTP/HTTPS proxy configuration for network dials and AIA fetches. |

---

## STARTTLS Protocol Support

| Protocol | Default Port | Negotiation Standard |
|:---------|:------------:|:---------------------|
| `smtp` | `587` (Submission) / `25` | RFC 3207 (`STARTTLS` command) |
| `imap` | `143` | RFC 3501 / RFC 2595 (`STARTTLS` command) |
| `pop3` | `110` | RFC 2595 (`STLS` command) |
| `postgres` | `5432` | PostgreSQL SSLRequest packet (`80877103`) |
| `mysql` | `3306` | MySQL SSL negotiation request packet |

---

## JSON Output Schema

When invoked with `--format json`, `cert-chain-doctor` emits structured JSON:

```json
{
  "target": "api.example.com:443",
  "handshake": {
    "server_name": "api.example.com",
    "tls_version": "TLS 1.3",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "ocsp_stapled": false,
    "handshake_ms": 14
  },
  "analysis": {
    "status": "BROKEN",
    "certificates": [
      {
        "position": 0,
        "is_leaf": true,
        "subject": "CN=api.example.com",
        "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
        "not_before": "2026-10-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "days_until_expiry": 68,
        "key_algorithm": "ECDSA",
        "key_size": 256,
        "signature_algorithm": "ECDSA-SHA256",
        "sans": ["api.example.com"],
        "ski": "02:4F:C9...",
        "aki": "5F:87:AF...",
        "aia_issuing_urls": [
          "http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt"
        ]
      }
    ],
    "issues": [
      {
        "code": "MISSING_INTERMEDIATE_AIA_AVAILABLE",
        "severity": "ERROR",
        "message": "Chain is missing intermediate CA certificate(s)",
        "remediation": "Run cert-chain-doctor with --fix-bundle <path>"
      }
    ]
  }
}
```
