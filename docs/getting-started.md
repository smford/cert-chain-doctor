---
title: "Getting Started"
description: "Installation, quickstart, and first steps with cert-chain-doctor"
---

# Getting Started

## Installation

### Homebrew (macOS & Linux)

The easiest way to install `cert-chain-doctor` is via Homebrew:

```bash
brew tap smford/homebrew-tap
brew install cert-chain-doctor
```

### Pre-Built Binaries

Download pre-compiled, static binaries for Linux, macOS, and Windows from GitHub Releases:

```bash
# macOS (Apple Silicon arm64)
curl -sSL https://github.com/smford/cert-chain-doctor/releases/download/v0.1.1/cert-chain-doctor_0.1.0_darwin_arm64.tar.gz | tar -xz
sudo mv cert-chain-doctor /usr/local/bin/

# Linux (amd64)
curl -sSL https://github.com/smford/cert-chain-doctor/releases/download/v0.1.1/cert-chain-doctor_0.1.0_linux_amd64.tar.gz | tar -xz
sudo mv cert-chain-doctor /usr/local/bin/
```

### From Source (Go 1.23+)

Compile directly using Go with zero CGO dependencies:

```bash
git clone https://github.com/smford/cert-chain-doctor.git
cd cert-chain-doctor
make build
# Binary is created at bin/cert-chain-doctor
```

Verify your installation:

```bash
cert-chain-doctor --version
```

Output:
```text
cert-chain-doctor 0.1.0 (commit: 53bd45c, date: 2026-10-24T01:12:52Z)
Copyright (c) 2026 smford
Licensed under the MIT License
```

---

## Basic Usage

### Inspect a Remote Web Endpoint

To diagnose any public or internal HTTPS endpoint, pass the hostname (port `:443` is assumed if omitted):

```bash
cert-chain-doctor api.example.com
```

### Inspect a Local PEM File Offline

To inspect a certificate bundle on disk before deploying it:

```bash
cert-chain-doctor --file /etc/ssl/certs/bundle.pem
```

### Automatically Fix a Broken Intermediate Chain

If an endpoint or bundle is missing intermediate certificates, pass `--fix-bundle` to automatically fetch missing intermediates from AIA servers, cryptographically verify signatures, and write the repaired bundle:

```bash
cert-chain-doctor api.example.com --fix-bundle /etc/ssl/certs/repaired-bundle.pem
```

---

## Output Formats

### Colorized Visual Tree (Default)

`cert-chain-doctor` produces a rich ASCII tree diagram showing:
* Key sizes and signature algorithms
* Expiration dates and days remaining
* Cryptographic continuity links (`AKI -> SKI`)
* Diagnostic badges (`EXPIRED`, `EXPIRING SOON`, `REDUNDANT ROOT`)

Colors are automatically enabled when outputting to an interactive terminal, and disabled when piping or when `NO_COLOR` is set. You can force color with `--color always` or disable it with `--color never`.

### Machine-Readable JSON

For scripting, monitoring, and CI/CD automation, pass `--format json`:

```bash
cert-chain-doctor api.example.com --format json | jq '.analysis.is_valid'
```
