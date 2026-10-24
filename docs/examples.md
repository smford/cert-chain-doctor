---
title: "Worked Examples"
description: "Common and useful tasks with cert-chain-doctor"
---

# Worked Examples

### Example 1: Diagnosing Why curl or Alpine Fails on Your Domain

When your website opens in a desktop browser but fails in `curl`:

```bash
curl -v https://api.example.com
# Error: curl: (60) SSL certificate problem: unable to get local issuer certificate
```

Diagnose the problem with `cert-chain-doctor`:

```bash
cert-chain-doctor api.example.com
```

The tool pinpoints:
* Leaf certificate presented by the server.
* The missing intermediate CA certificate.
* The exact Authority Information Access (AIA) URL where the intermediate can be retrieved.

---

### Example 2: Automatically Repairing a Broken Intermediate Chain for Nginx or Envoy

To download the missing intermediate certificate and assemble a clean fullchain PEM bundle:

```bash
cert-chain-doctor api.example.com --fix-bundle /etc/nginx/ssl/api-fullchain.pem
```

Configure Nginx to use the repaired bundle:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/nginx/ssl/api-fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/api.key;
}
```

Reload Nginx:
```bash
nginx -t && nginx -s reload
```

---

### Example 3: Exporting a Repaired Chain as a Kubernetes Secret

Generate a complete `kubernetes.io/tls` secret manifest with your repaired certificate bundle:

```bash
cert-chain-doctor api.example.com \
  --k8s-secret api-tls-cert \
  --k8s-namespace production \
  --fix-bundle /tmp/repaired.pem > k8s-secret.yaml
```

Inspect the generated manifest:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-tls-cert
  namespace: production
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tC...
  tls.key: "" # Optional: base64 encoded private key
```

Apply to your Kubernetes cluster:

```bash
kubectl apply -f k8s-secret.yaml
```

---

### Example 4: Testing an Ingress Controller or Load Balancer via IP with SNI

When you need to test a server before changing public DNS records:

```bash
cert-chain-doctor 198.51.100.24:443 --sni api.example.com
```

This ensures the TLS handshake passes the correct Server Name Indication (`SNI`) header without modifying `/etc/hosts`.

---

### Example 5: Auditing Email and Database TLS Handshakes (STARTTLS)

Probe servers that start in plain text before negotiating TLS:

```bash
# SMTP over submission port 587
cert-chain-doctor smtp.example.com:587 --starttls smtp

# PostgreSQL database server
cert-chain-doctor postgres.internal.net:5432 --starttls postgres

# IMAP email server
cert-chain-doctor imap.example.com:143 --starttls imap
```

---

### Example 6: Batch Scanning an Entire Fleet or Environment

Audit multiple services from a text file:

```bash
cat <<EOF > endpoints.txt
# Production endpoints
api.example.com:443
auth.example.com:443
# Database
db-primary.internal.net:5432
# Mail
mail.example.com:587
EOF

cert-chain-doctor --hosts-file endpoints.txt
```

Summary output:

```text
================================================================================
                   CERT CHAIN DOCTOR - BATCH AUDIT SUMMARY
================================================================================
TARGET                           TLS        STATUS       EXPIRY   FINDINGS
--------------------------------------------------------------------------------
api.example.com:443              TLS 1.3    HEALTHY      68d      None
auth.example.com:443             TLS 1.3    BROKEN       89d      MISSING_INTERMEDIATE
db-primary.internal.net:5432     TLS 1.3    HEALTHY      180d     None
mail.example.com:587             TLS 1.3    WARNING      4d       CERT_EXPIRING_SOON
--------------------------------------------------------------------------------
```

---

### Example 7: Checking Active OCSP Responder Reachability

Verify that the Certificate Authority's OCSP server is online and responding:

```bash
cert-chain-doctor api.example.com --check-revocation
```

Output:
```text
REVOCATION ENDPOINTS:
  OCSP Responder:     REACHABLE (OCSP responder reachable (http://ocsp.digicert.com))
  CRL Distribution:   REACHABLE (http://crl3.digicert.com/DigiCertGlobalRootG2.crl)
```

---

### Example 8: Running as an HTTP Diagnostic Microservice

Run `cert-chain-doctor` inside a Docker container or Kubernetes pod as an internal diagnosis API:

```bash
cert-chain-doctor serve --addr :8080
```

Query the API:
```bash
curl http://localhost:8080/diagnose?target=api.example.com | jq .
```
