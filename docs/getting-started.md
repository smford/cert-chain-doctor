---
title: "Getting Started"
description: "Installation, quickstart guide, and output anatomy for cert-chain-doctor"
---

# Getting Started

Welcome to `cert-chain-doctor`! This guide walks you through installing the tool, verifying your environment, running your first diagnostic scan, understanding the visual tree output, and executing an automated chain repair.

---

## Installation

`cert-chain-doctor` is distributed as a single static binary with zero external runtime dependencies. Choose your preferred installation method:

::: tabs
::: tab Homebrew (macOS & Linux)
The recommended package manager on macOS and Linux:

```bash
brew tap smford/homebrew-tap
brew install cert-chain-doctor
```

Upgrade anytime with:

```bash
brew upgrade cert-chain-doctor
```
::: tab Pre-Built Binaries
Download pre-compiled, static binaries for Linux, macOS, and Windows from GitHub Releases:

```bash
# macOS (Apple Silicon arm64)
curl -sSL https://github.com/smford/cert-chain-doctor/releases/download/v0.1.1/cert-chain-doctor_0.1.1_darwin_arm64.tar.gz | tar -xz
sudo mv cert-chain-doctor /usr/local/bin/

# Linux (amd64)
curl -sSL https://github.com/smford/cert-chain-doctor/releases/download/v0.1.1/cert-chain-doctor_0.1.1_linux_amd64.tar.gz | tar -xz
sudo mv cert-chain-doctor /usr/local/bin/
```
::: tab From Source (Go 1.23+)
Compile directly using the Go toolchain with zero CGO dependencies:

```bash
# Using go install
go install github.com/smford/cert-chain-doctor/cmd/cert-chain-doctor@latest

# Or clone and compile locally
git clone https://github.com/smford/cert-chain-doctor.git
cd cert-chain-doctor
make build
# Binary is produced at bin/cert-chain-doctor
```
::: tab Docker Container
Run directly via Docker without installing to your local system:

```bash
docker run --rm ghcr.io/smford/cert-chain-doctor:v0.1.1 api.example.com
```
:::

---

## Verifying the Installation

Check that the binary is in your system `PATH` and displays valid build metadata:

```bash
cert-chain-doctor --version
```

Output:
```text
cert-chain-doctor 0.1.1 (commit: 53bd45c, date: 2026-10-24T01:12:52Z)
Copyright (c) 2026 smford
Licensed under the MIT License
```

> [!TIP]
> `cert-chain-doctor` automatically enables ANSI colors when outputting to an interactive terminal, and disables color codes when piping to another program or when the `NO_COLOR` environment variable is present.

---

## Your First Diagnostic Scan

To analyze any remote endpoint, run `cert-chain-doctor` followed by the domain name. Port `:443` is automatically assumed if omitted:

```bash
cert-chain-doctor github.com
```

Here is the resulting diagnostic output:

![Terminal Output: Live Scan](assets/screenshot-healthy-scan.svg)

---

## Anatomy of the Diagnostic Output

`cert-chain-doctor` splits the diagnosis into five distinct, intuitive sections:

### 1. Target & TLS Connection Summary
* **Target & SNI:** The remote hostname dialed and the Server Name Indication header transmitted in the TLS `ClientHello`.
* **Remote IP:** The exact resolved IP and port of the remote server.
* **TLS Conn:** Negotiated protocol (`TLS 1.3` or `TLS 1.2`), cipher suite (e.g. `TLS_AES_128_GCM_SHA256`), ALPN token, OCSP stapling status, and round-trip handshake latency.

### 2. Certificate Chain Tree
Each certificate in the presented chain is displayed in a hierarchical branch starting from index `[0]` (the leaf / server certificate) down to the intermediate CAs:

* **Subject:** The Distinguished Name (DN) representing the entity to which the certificate was issued.
* **Issuer:** The CA that signed and issued this certificate.
* **Validity:** Active start date, expiration date, and a color-coded **countdown of days remaining**.
* **Key & Sig:** The public key type and bit length (e.g., `ECDSA 256-bit`, `RSA 2048-bit`), followed by the signature algorithm (e.g. `ECDSA-SHA256`).
* **SANs:** Subject Alternative Names covering valid hostnames and domain patterns.
* **SKI & AKI Pointers:** The Subject Key Identifier and Authority Key Identifier. An arrow (`-> [1]`) visually indicates which certificate in the tree satisfies the cryptographic parent relationship.
* **AIA URL:** The Authority Information Access URL where the issuing intermediate certificate can be downloaded if missing.

### 3. Findings & Diagnosis
A list of all detected warnings or errors, ranked by severity:
* `[OK]`: No defects found.
* `[WARNING]`: Non-critical conditions (e.g. certificate expiring within 14 days, redundant root in handshake).
* `[ERROR]`: Fatal verification failures (missing intermediate CA, inverted bundle ordering, expired certificate, hostname mismatch).

### 4. Verdict Banner
A prominent concluding banner summarizing the overall state of the chain:
* `HEALTHY`: Fully trusted, properly ordered, and valid.
* `BROKEN CHAIN`: Failed cryptographic verification. Actionable remediation advice is provided.
* `REPAIRED`: Chain was successfully reconstructed and verified via AIA.

---

## Running an Automated Chain Repair

If an endpoint is missing its intermediate CA, pass `--fix-bundle` with the target output path:

```bash
cert-chain-doctor api.example.com --fix-bundle /etc/ssl/certs/repaired-bundle.pem
```

What `cert-chain-doctor` does behind the scenes:
1. Connects to `api.example.com` and captures the peer certificate list.
2. Identifies that the intermediate CA certificate is missing.
3. Parses the Leaf certificate's `Authority Information Access (AIA)` extension.
4. Downloads the intermediate CA certificate over HTTP.
5. Verifies cryptographically that the downloaded intermediate signed the leaf certificate.
6. Writes the properly ordered, complete fullchain (`Leaf -> Intermediate`) to your specified path.

---

## Inspecting Local PEM Bundles Offline

You don't need a live internet connection to validate certificate files. You can audit PEM bundles on disk:

```bash
cert-chain-doctor --file /etc/nginx/ssl/server.pem
```

This verifies certificate ordering, expiration dates, key strengths, and chain continuity before deploying configuration files to production.

---

## Exit Codes for CI/CD Integration

`cert-chain-doctor` returns standard UNIX exit codes suitable for shell scripts and automated deployment pipelines:

| Exit Code | Meaning | Typical Action |
|:---------:|---------|----------------|
| **`0`** | **HEALTHY / REPAIRED** | Allow deployment to proceed. |
| **`1`** | **BROKEN / FATAL ERROR** | Halt deployment pipeline and trigger immediate alert. |
| **`2`** | **EXPIRING SOON** | Emit warning to Slack/PagerDuty to renew certificate. |

Example shell script:

```bash
if cert-chain-doctor api.example.com; then
  echo "TLS certificate chain is healthy!"
else
  echo "TLS verification failed! Halting deployment."
  exit 1
fi
```

---

## Next Steps

* Explore [**Worked Examples**](examples.md) for Kubernetes secrets, Nginx configs, STARTTLS audits, and batch scans.
* Consult the [**CLI Reference**](cli-reference.md) for all available command flags.
* Read the [**Troubleshooting Guide**](troubleshooting.md) for detailed explanations of every error code.
