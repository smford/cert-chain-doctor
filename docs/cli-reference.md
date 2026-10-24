---
title: "CLI Reference"
description: "Flags, options, and exit codes for cert-chain-doctor"
---

# CLI Reference

## Usage

```text
cert-chain-doctor [flags] <host[:port]>
cert-chain-doctor --file <bundle.pem> [flags]
cert-chain-doctor --hosts-file <hosts.txt> [flags]
cert-chain-doctor serve [--addr :8080]
```

---

## Flags & Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--file <path>` | string | `""` | Analyze a local PEM certificate file/bundle offline instead of dialing a network host. |
| `--fix-bundle <path>` | string | `""` | Automatically chase AIA URLs, verify signatures, and write clean fullchain PEM bundle to this path. |
| `--sni <hostname>` | string | host | Override TLS Server Name Indication (SNI). Defaults to host without port. |
| `--alpn <protocols>` | string | `""` | Comma-separated list of ALPN protocols to negotiate (e.g. `h2,http/1.1`). |
| `--starttls <protocol>` | string | `""` | Negotiate TLS via plain-text command protocol: `smtp`, `imap`, `pop3`, `postgres`, `mysql`. |
| `--expiry-warn <days>` | int | `14` | Warning threshold in days for certificate expiration (triggers exit code 2). |
| `--format <text\|json>` | string | `text` | Output format: human-readable ASCII tree (`text`) or structured JSON (`json`). |
| `--color <auto\|always\|never>` | string | `auto` | Terminal ANSI color highlighting. Auto-disabled when piped or when `NO_COLOR` is set. |
| `--k8s-secret <name>` | string | `""` | Generate a Kubernetes TLS Secret YAML manifest containing the repaired bundle. |
| `--k8s-namespace <ns>` | string | `default` | Kubernetes namespace for generated TLS secret manifest. |
| `--hosts-file <path>` | string | `""` | Batch audit multiple endpoints from a newline-delimited text file. |
| `--check-revocation` | bool | `false` | Actively check reachability of OCSP responder and CRL distribution endpoints. |
| `--ca-file <path>` | string | system | Path to custom CA root certificate(s) PEM file for private or enterprise PKI verification. |
| `--timeout <sec>` | int | `10` | Network dial and TLS handshake timeout in seconds. |
| `-v, --version` | bool | `false` | Print detailed version, commit, and build date information. |

---

## Exit Codes

`cert-chain-doctor` returns standard UNIX exit codes suitable for shell scripts, CI/CD gates, and monitoring agents:

| Code | Status | Meaning |
|:----:|--------|---------|
| **`0`** | **HEALTHY / REPAIRED** | The certificate chain is complete, cryptographically verified, and valid (or `--fix-bundle` successfully repaired it). |
| **`1`** | **BROKEN / ERROR** | The chain failed verification (missing intermediate, misordered chain, hostname mismatch, expired cert, or network dial failure). |
| **`2`** | **EXPIRING SOON** | The chain is cryptographically trusted, but at least one certificate expires within the `--expiry-warn` window. |
