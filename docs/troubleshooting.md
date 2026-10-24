---
title: "Troubleshooting & Error Codes"
description: "Comprehensive diagnostic code catalog, symptoms, root causes, and fixes"
---

# Troubleshooting & Error Codes

This catalog provides diagnostic descriptions, client symptoms, root causes, and exact remediation commands for every issue code reported by `cert-chain-doctor`.

---

## Chain Completeness & Trust

### 1. `MISSING_INTERMEDIATE_AIA_AVAILABLE`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:**
  * Opens with a green lock in Chrome/Safari, but fails in backend services.
  * `curl: (60) SSL certificate problem: unable to get local issuer certificate`
  * Python: `ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate`
  * Go: `x509: certificate signed by unknown authority`
  * Alpine Linux: `wget: note: TLS certificate validation not implemented` / `unknown authority`
* **Root Cause:** The server configuration only includes the Leaf certificate. Desktop browsers silently fetch the missing intermediate CA via AIA, while strict clients reject the handshake.
* **Remediation:**
  ```bash
  cert-chain-doctor <target> --fix-bundle /path/to/repaired-fullchain.pem
  ```
  `cert-chain-doctor` automatically downloads the missing intermediate certificate from the CA's AIA repository and outputs a valid fullchain.

---

### 2. `MISSING_INTERMEDIATE_NO_AIA`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** Same client errors as above, but `cert-chain-doctor` indicates `No AIA URL found`.
* **Root Cause:** The certificate is issued by a private or internal CA that did not embed an Authority Information Access extension.
* **Remediation:** Obtain the issuing intermediate CA certificate from your organization's internal PKI team, append it to your leaf certificate in order (`Leaf -> Intermediate`), and verify:
  ```bash
  cat leaf.crt intermediate.crt > fullchain.pem
  cert-chain-doctor --file fullchain.pem
  ```

---

### 3. `UNTRUSTED_ROOT_AUTHORITY`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** `x509: certificate signed by unknown authority` on all clients.
* **Root Cause:** The certificate chain terminates at a Root CA that is not in the system trust store (e.g. self-signed internal CA or corporate MITM proxy).
* **Remediation:** Provide the custom root certificate using `--ca-file`:
  ```bash
  cert-chain-doctor <target> --ca-file /path/to/internal-root.pem
  ```

---

## Chain Ordering & Structure

### 4. `MISORDERED_CHAIN_REVERSED` / `MISORDERED_CHAIN_LEAF_NOT_FIRST`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** Strict TLS clients drop the connection or fail with `unable to get local issuer certificate` even though all intermediate certificates are present in the `.pem` file.
* **Root Cause:** Certificates in the server configuration were concatenated backwards (e.g. Intermediate before Leaf) or in random order. Per RFC 5280 §6.1, the Leaf certificate must occupy position `[0]`.
* **Remediation:** Run `cert-chain-doctor` with `--fix-bundle` on the file to automatically reorder the certificates:
  ```bash
  cert-chain-doctor --file /etc/ssl/certs/disordered.pem --fix-bundle /etc/ssl/certs/ordered.pem
  ```

---

### 5. `REDUNDANT_ROOT_IN_HANDSHAKE`
* **Severity:** `WARNING` (Exit code `0`)
* **Symptoms:** Non-fatal warning reported during diagnostic scans.
* **Root Cause:** A self-signed Root CA certificate was included in the server bundle. Per RFC 8446 (TLS 1.3), Root CAs should not be sent over the wire because clients rely on their local trust stores.
* **Remediation:** Strip the Root CA from your server bundle to save 1.5KB of handshake bloat:
  ```bash
  cert-chain-doctor <target> --fix-bundle clean-fullchain.pem
  ```

---

## Identity & Hostname Validation

### 6. `HOSTNAME_MISMATCH`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:**
  * `curl: (51) SSL: certificate subject name 'example.com' does not match target host name 'api.example.com'`
  * Go: `x509: certificate is valid for example.com, not api.example.com`
* **Root Cause:** The requested domain name does not match the Common Name (CN) or any Subject Alternative Names (SANs) listed in the certificate.
* **Remediation:** Inspect the SANs listed in `cert-chain-doctor`'s output. Reissue the certificate with the proper SANs, or verify that your DNS and load balancer routing are pointing to the intended service.

---

## Validity & Expiration

### 7. `CERT_EXPIRING_SOON`
* **Severity:** `WARNING` (Exit code `2`)
* **Symptoms:** Handshake succeeds, but `cert-chain-doctor` exits with code `2`.
* **Root Cause:** At least one certificate in the chain expires within the configured threshold (default 14 days, adjustable via `--expiry-warn <days>`).
* **Remediation:** Initiate certificate renewal before the validity window expires.

---

### 8. `CERT_EXPIRED`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** `x509: certificate has expired or is not yet valid`.
* **Root Cause:** The `NotAfter` timestamp is in the past.
* **Remediation:** Renew and deploy a new certificate immediately.

---

### 9. `CERT_NOT_YET_VALID`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** `x509: certificate is not yet valid`.
* **Root Cause:** The `NotBefore` timestamp is in the future. Usually caused by system clock skew on the client or server, or an erroneously issued certificate.
* **Remediation:** Verify NTP synchronization on your servers:
  ```bash
  timedatectl status
  ```

---

## Cryptographic Weaknesses

### 10. `WEAK_SIGNATURE_ALGORITHM`
* **Severity:** `WARNING` (Exit code `0`)
* **Symptoms:** Modern browsers or operating systems mark the connection as insecure or fail the handshake.
* **Root Cause:** The certificate is signed using obsolete hash algorithms such as MD5 (`MD5-RSA`) or SHA-1 (`SHA1-RSA`).
* **Remediation:** Reissue the certificate with SHA-256 (`SHA256-RSA`) or ECDSA (`ECDSA-SHA256`).

---

### 11. `WEAK_PUBLIC_KEY`
* **Severity:** `WARNING` (Exit code `0`)
* **Symptoms:** Fails security compliance audits or modern cipher suite negotiation.
* **Root Cause:** The certificate uses an RSA key smaller than 2048 bits (e.g. 1024 bits).
* **Remediation:** Reissue the certificate with an RSA key length &ge; 2048 bits or an ECDSA key (P-256 / P-384).

---

## Network & Protocol Failures

### 12. `CONNECT_FAILED`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** `dial tcp <ip>:443: connect: connection refused` or `timeout`.
* **Root Cause:** Firewall blocking port 443, service not running, or incorrect DNS record.
* **Remediation:** Verify that the service is running and listening on the designated port with `nc -zv <host> <port>`.

---

### 13. `STARTTLS_FAILED`
* **Severity:** `ERROR` (Exit code `1`)
* **Symptoms:** STARTTLS negotiation failed during handshake.
* **Root Cause:** Server did not advertise TLS capability or rejected the upgrade command.
* **Remediation:** Verify the server configuration allows STARTTLS upgrades for the specified protocol.
