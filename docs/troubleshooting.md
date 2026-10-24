---
title: "Troubleshooting Guide"
description: "Diagnosing and fixing common TLS and certificate chain errors"
---

# Troubleshooting Guide

### 1. `MISSING_INTERMEDIATE_AIA_AVAILABLE`
* **Symptom:** Connection succeeds in Chrome, but fails in `curl`, Go, Python, or Alpine Linux Docker containers with `x509: certificate signed by unknown authority`.
* **Root Cause:** The server sent only the leaf certificate and omitted the intermediate CA certificate.
* **Solution:** Run `cert-chain-doctor <host> --fix-bundle fullchain.pem` to automatically download the missing intermediate and write the complete bundle.

---

### 2. `MISORDERED_CHAIN_REVERSED` or `MISORDERED_CHAIN_LEAF_NOT_FIRST`
* **Symptom:** Strict TLS clients drop the connection with `x509: certificate signed by unknown authority` even though all certificates are present in the `.pem` file.
* **Root Cause:** The intermediate CA was placed before the leaf certificate, or certificates were appended in reverse order.
* **Solution:** Reorder the bundle so the leaf certificate is at index `0`, followed by intermediate certificates:
  ```text
  -----BEGIN CERTIFICATE-----  <- Leaf / Domain Certificate
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----  <- Intermediate CA Certificate
  -----END CERTIFICATE-----
  ```

---

### 3. `REDUNDANT_ROOT_IN_HANDSHAKE`
* **Symptom:** Warning reported by `cert-chain-doctor`.
* **Root Cause:** The self-signed Root CA certificate was included in the server bundle.
* **Solution:** Root CAs are pre-installed in operating system trust stores. Remove the Root CA from your server bundle to save handshake bytes and improve TLS latency.

---

### 4. `HOSTNAME_MISMATCH`
* **Symptom:** Verification fails with `x509: certificate is valid for *.example.com, not sub.dev.example.com`.
* **Root Cause:** Wildcard certificates (`*.example.com`) only match a single DNS subdomain level.
* **Solution:** Reissue the certificate with an explicit Subject Alternative Name (SAN) covering the full domain name.

---

### 5. `CERT_EXPIRING_SOON` / `CERT_EXPIRED`
* **Symptom:** `cert-chain-doctor` exits with code `2` (expiring soon) or code `1` (expired).
* **Solution:** Renew your certificate before the expiration window lapses.
