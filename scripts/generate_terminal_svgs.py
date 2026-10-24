#!/usr/bin/env python3
"""
Generates crisp, high-resolution SVG terminal screenshots for cert-chain-doctor documentation.
"""
import html
import os

FONT_FAMILY = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"

def generate_terminal_svg(title: str, lines: list, output_path: str):
    line_height = 20
    padding_top = 46
    padding_bottom = 22
    padding_x = 22
    width = 860
    content_height = len(lines) * line_height
    total_height = padding_top + content_height + padding_bottom

    svg_lines = []
    svg_lines.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {total_height}" width="100%" height="{total_height}" style="max-width: 100%; border-radius: 8px; box-shadow: 0 16px 36px rgba(0,0,0,0.35);">')
    svg_lines.append('  <defs>')
    svg_lines.append('    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="0%" y2="100%">')
    svg_lines.append('      <stop offset="0%" stop-color="#1f242c" />')
    svg_lines.append('      <stop offset="100%" stop-color="#161b22" />')
    svg_lines.append('    </linearGradient>')
    svg_lines.append('  </defs>')
    svg_lines.append(f'  <!-- Window Background -->')
    svg_lines.append(f'  <rect width="{width}" height="{total_height}" rx="10" ry="10" fill="#0d1117" stroke="#30363d" stroke-width="1.2" />')

    # Titlebar
    svg_lines.append(f'  <path d="M 0 10 C 0 4.477 4.477 0 10 0 L {width-10} 0 C {width-4.477} 0 {width} 4.477 {width} 10 L {width} 36 L 0 36 Z" fill="url(#headerGrad)" stroke="#30363d" stroke-width="1.2" />')
    svg_lines.append(f'  <line x1="0" y1="36" x2="{width}" y2="36" stroke="#30363d" stroke-width="1" />')

    # Window controls (macOS style)
    svg_lines.append('  <circle cx="20" cy="18" r="6" fill="#ff5f56" stroke="#e0443e" stroke-width="0.5" />')
    svg_lines.append('  <circle cx="38" cy="18" r="6" fill="#ffbd2e" stroke="#dea123" stroke-width="0.5" />')
    svg_lines.append('  <circle cx="56" cy="18" r="6" fill="#27c93f" stroke="#1aab29" stroke-width="0.5" />')

    # Window title
    safe_title = html.escape(title)
    svg_lines.append(f'  <text x="{width/2}" y="22" font-family="{FONT_FAMILY}" font-size="12" fill="#8b949e" text-anchor="middle" font-weight="500">{safe_title}</text>')

    # Terminal text
    svg_lines.append(f'  <text font-family="{FONT_FAMILY}" font-size="12.5" xml:space="preserve">')

    for i, line_tokens in enumerate(lines):
        y = padding_top + (i * line_height)
        tspan_str = f'    <tspan x="{padding_x}" y="{y}">'
        for text, color, bold in line_tokens:
            style = f'fill: {color};'
            if bold:
                style += ' font-weight: bold;'
            tspan_str += f'<tspan style="{style}">{html.escape(text)}</tspan>'
        tspan_str += '</tspan>'
        svg_lines.append(tspan_str)

    svg_lines.append('  </text>')
    svg_lines.append('</svg>')

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(svg_lines))
    print(f"Generated {output_path}")

def build_healthy_scan():
    c_prompt = "#3fb950"
    c_cmd = "#e6edf3"
    c_border = "#8b949e"
    c_banner = "#58a6ff"
    c_white = "#e6edf3"
    c_cyan = "#79c0ff"
    c_green = "#3fb950"
    c_purple = "#d2a8ff"
    c_muted = "#8b949e"
    c_gold = "#e3b341"

    lines = [
        [("$ ", c_prompt, True), ("cert-chain-doctor github.com", c_cmd, True)],
        [("=" * 80, c_border, False)],
        [("              CERT CHAIN DOCTOR - TLS & CHAIN DIAGNOSTIC", c_banner, True)],
        [("=" * 80, c_border, False)],
        [("Target:     ", c_muted, False), ("github.com", c_white, True)],
        [("SNI:        ", c_muted, False), ("github.com", c_cyan, False)],
        [("Remote IP:  ", c_muted, False), ("20.26.156.215:443", c_white, False)],
        [("TLS Conn:   ", c_muted, False),
         ("TLS 1.3", c_purple, True),
         (" | TLS_AES_128_GCM_SHA256 | OCSP Stapled: No | Handshake: ", c_white, False),
         ("29ms", c_green, True)],
        [("", c_white, False)],
        [("CERTIFICATE CHAIN TREE:", c_gold, True)],
        [("├── [0] Leaf: ", c_border, False), ("github.com", c_green, True)],
        [("│   ├── Subject:  ", c_border, False), ("CN=github.com", c_white, False)],
        [("│   ├── Issuer:   ", c_border, False), ("CN=Sectigo Public Server Authentication CA DV E36", c_muted, False)],
        [("│   ├── Validity: ", c_border, False), ("2026-09-01 to 2026-11-29 (", c_white, False), ("36 days left", c_green, True), (")", c_white, False)],
        [("│   ├── Key:      ", c_border, False), ("ECDSA 256-bit", c_purple, False), (" | Sig: ECDSA-SHA256", c_muted, False)],
        [("│   ├── SANs:     ", c_border, False), ("github.com, www.github.com", c_cyan, False)],
        [("│   ├── SKI:      ", c_border, False), ("66:98:EC:4C...56:D4:E0", c_muted, False)],
        [("│   ├── AKI:      ", c_border, False), ("17:99:A8:04...B8:26:63 -> [1]", c_cyan, True)],
        [("│   └── AIA URL:  ", c_border, False), ("http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt", c_muted, False)],
        [("│", c_border, False)],
        [("├── [1] Intermediate CA: ", c_border, False), ("Sectigo Public Server Authentication CA DV E36", c_white, True)],
        [("│   ├── Subject:  ", c_border, False), ("CN=Sectigo Public Server Authentication CA DV E36", c_white, False)],
        [("│   ├── Issuer:   ", c_border, False), ("CN=Sectigo Public Server Authentication Root E46", c_muted, False)],
        [("│   ├── Validity: ", c_border, False), ("2021-03-22 to 2036-03-21 (3436 days left)", c_white, False)],
        [("│   ├── Key:      ", c_border, False), ("ECDSA 256-bit", c_purple, False), (" | Sig: ECDSA-SHA384", c_muted, False)],
        [("│   ├── SKI:      ", c_border, False), ("17:99:A8:04...B8:26:63", c_muted, False)],
        [("│   ├── AKI:      ", c_border, False), ("D1:22:DA:4C...FB:A9:61 -> [2]", c_cyan, True)],
        [("│   └── AIA URL:  ", c_border, False), ("http://crt.sectigo.com/SectigoPublicServerAuthenticationRootE46.p7c", c_muted, False)],
        [("│", c_border, False)],
        [("└── [2] Intermediate CA: ", c_border, False), ("Sectigo Public Server Authentication Root E46", c_white, True)],
        [("    ├── Subject:  ", c_border, False), ("CN=Sectigo Public Server Authentication Root E46", c_white, False)],
        [("    ├── Issuer:   ", c_border, False), ("CN=USERTrust ECC Certification Authority", c_muted, False)],
        [("    ├── Validity: ", c_border, False), ("2021-03-22 to 2038-01-18 (4104 days left)", c_white, False)],
        [("    ├── Key:      ", c_border, False), ("ECDSA 384-bit", c_purple, False), (" | Sig: ECDSA-SHA384", c_muted, False)],
        [("    └── AKI:      ", c_border, False), ("3A:E1:09:86...63:63:9A -> ", c_muted, False), ("Trusted Root Store", c_green, True)],
        [("", c_white, False)],
        [("FINDINGS & DIAGNOSIS:", c_gold, True)],
        [("  [", c_muted, False), ("OK", c_green, True), ("] No issues detected. Chain structure is optimal.", c_white, False)],
        [("-" * 80, c_border, False)],
        [("VERDICT: ", c_muted, False), ("HEALTHY: Certificate chain is complete, properly ordered, and trusted", c_green, True)],
        [("-" * 80, c_border, False)]
    ]
    generate_terminal_svg("cert-chain-doctor github.com", lines, "docs/assets/screenshot-healthy-scan.svg")

def build_broken_aia_repair():
    c_prompt = "#3fb950"
    c_cmd = "#e6edf3"
    c_border = "#8b949e"
    c_banner = "#f85149"
    c_white = "#e6edf3"
    c_cyan = "#79c0ff"
    c_green = "#3fb950"
    c_purple = "#d2a8ff"
    c_muted = "#8b949e"
    c_gold = "#e3b341"
    c_red = "#f85149"

    lines = [
        [("$ ", c_prompt, True), ("cert-chain-doctor api.example.com --fix-bundle /etc/ssl/repaired.pem", c_cmd, True)],
        [("=" * 80, c_border, False)],
        [("              CERT CHAIN DOCTOR - TLS & CHAIN DIAGNOSTIC", c_banner, True)],
        [("=" * 80, c_border, False)],
        [("Target:     ", c_muted, False), ("api.example.com:443", c_white, True)],
        [("SNI:        ", c_muted, False), ("api.example.com", c_cyan, False)],
        [("Remote IP:  ", c_muted, False), ("93.184.216.34:443", c_white, False)],
        [("TLS Conn:   ", c_muted, False), ("TLS 1.3 | TLS_AES_128_GCM_SHA256 | Handshake: 14ms", c_white, False)],
        [("", c_white, False)],
        [("CERTIFICATE CHAIN TREE:", c_gold, True)],
        [("├── [0] Leaf: ", c_border, False), ("api.example.com", c_white, True)],
        [("│   ├── Subject:  ", c_border, False), ("CN=api.example.com, O=Example Corp", c_white, False)],
        [("│   ├── Issuer:   ", c_border, False), ("CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1", c_muted, False)],
        [("│   ├── Validity: ", c_border, False), ("2026-10-01 to 2027-01-01 (68 days left)", c_white, False)],
        [("│   ├── AKI:      ", c_border, False), ("5F:87:AF:B0...0E:F1:42:00 -> ", c_muted, False), ("MISSING INTERMEDIATE", c_red, True)],
        [("│   └── AIA URL:  ", c_border, False), ("http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt", c_cyan, False)],
        [("│", c_border, False)],
        [("└── [1] Intermediate ", c_border, False), ("(RESOLVED VIA AIA)", c_green, True), (": DigiCert Global G2 TLS CA", c_white, True)],
        [("    ├── Subject:  ", c_border, False), ("CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc", c_white, False)],
        [("    ├── Issuer:   ", c_border, False), ("CN=DigiCert Global Root G2", c_muted, False)],
        [("    ├── Validity: ", c_border, False), ("2020-09-23 to 2030-09-22 (1428 days left)", c_white, False)],
        [("    ├── Download: ", c_border, False), ("HTTP GET 200 OK (application/pkix-cert, 1284 bytes)", c_green, False)],
        [("    └── Verified: ", c_border, False), ("Cryptographic signature matches Leaf certificate", c_green, True)],
        [("", c_white, False)],
        [("FINDINGS & DIAGNOSIS:", c_gold, True)],
        [("  [", c_muted, False), ("ERROR", c_red, True), ("] ", c_muted, False), ("MISSING_INTERMEDIATE_AIA_AVAILABLE", c_red, True)],
        [("          Chain is missing intermediate CA ('unknown authority' in curl/Alpine/Go).", c_muted, False)],
        [("          AIA download URL found: http://cacerts.digicert.com/...-1.crt", c_cyan, False)],
        [("  [", c_muted, False), ("REPAIRED", c_green, True), ("] Wrote repaired fullchain bundle to /etc/ssl/repaired.pem", c_green, True)],
        [("-" * 80, c_border, False)],
        [("VERDICT: ", c_muted, False), ("REPAIRED: Missing intermediate fetched via AIA and verified", c_green, True)],
        [("-" * 80, c_border, False)]
    ]
    generate_terminal_svg("cert-chain-doctor api.example.com --fix-bundle", lines, "docs/assets/screenshot-broken-aia-repair.svg")

def build_batch_audit():
    c_prompt = "#3fb950"
    c_cmd = "#e6edf3"
    c_border = "#8b949e"
    c_banner = "#58a6ff"
    c_white = "#e6edf3"
    c_cyan = "#79c0ff"
    c_green = "#3fb950"
    c_purple = "#d2a8ff"
    c_muted = "#8b949e"
    c_gold = "#e3b341"
    c_red = "#f85149"

    lines = [
        [("$ ", c_prompt, True), ("cert-chain-doctor --hosts-file fleet-targets.txt", c_cmd, True)],
        [("=" * 80, c_border, False)],
        [("                   CERT CHAIN DOCTOR - BATCH AUDIT SUMMARY", c_banner, True)],
        [("=" * 80, c_border, False)],
        [("TARGET                           TLS        STATUS       EXPIRY   FINDINGS", c_gold, True)],
        [("-" * 80, c_border, False)],
        [("api.production.example.com:443   ", c_white, False), ("TLS 1.3    ", c_purple, False), ("HEALTHY      ", c_green, True), ("68d      ", c_white, False), ("None", c_muted, False)],
        [("auth.production.example.com:443  ", c_white, False), ("TLS 1.3    ", c_purple, False), ("BROKEN       ", c_red, True), ("89d      ", c_white, False), ("MISSING_INTERMEDIATE", c_red, True)],
        [("db-primary.internal.net:5432     ", c_white, False), ("TLS 1.3    ", c_purple, False), ("HEALTHY      ", c_green, True), ("180d     ", c_white, False), ("None", c_muted, False)],
        [("mail-gw.customer.example.com:587 ", c_white, False), ("TLS 1.2    ", c_purple, False), ("WARNING      ", c_gold, True), ("5d       ", c_gold, True), ("CERT_EXPIRING_SOON", c_gold, True)],
        [("billing-web.us-east.net:443      ", c_white, False), ("TLS 1.3    ", c_purple, False), ("HEALTHY      ", c_green, True), ("44d      ", c_white, False), ("None", c_muted, False)],
        [("legacy-vpn.office.net:443        ", c_white, False), ("TLS 1.2    ", c_purple, False), ("WARNING      ", c_gold, True), ("210d     ", c_white, False), ("REDUNDANT_ROOT", c_gold, False)],
        [("k8s-ingress.edge.net:443         ", c_white, False), ("TLS 1.3    ", c_purple, False), ("HEALTHY      ", c_green, True), ("72d      ", c_white, False), ("None", c_muted, False)],
        [("-" * 80, c_border, False)],
        [("SUMMARY: 7 targets audited | ", c_white, False),
         ("4 HEALTHY", c_green, True), (" | ", c_muted, False),
         ("2 WARNING", c_gold, True), (" | ", c_muted, False),
         ("1 BROKEN", c_red, True)],
        [("", c_white, False)],
        [("Run ", c_muted, False), ("cert-chain-doctor auth.production.example.com --fix-bundle fullchain.pem", c_cyan, True), (" to auto-repair.", c_muted, False)]
    ]
    generate_terminal_svg("cert-chain-doctor --hosts-file fleet-targets.txt", lines, "docs/assets/screenshot-batch-audit.svg")

def build_k8s_secret():
    c_prompt = "#3fb950"
    c_cmd = "#e6edf3"
    c_border = "#8b949e"
    c_banner = "#58a6ff"
    c_white = "#e6edf3"
    c_cyan = "#79c0ff"
    c_green = "#3fb950"
    c_purple = "#d2a8ff"
    c_muted = "#8b949e"
    c_gold = "#e3b341"

    lines = [
        [("$ ", c_prompt, True), ("cert-chain-doctor api.example.com --k8s-secret api-tls --k8s-namespace production", c_cmd, True)],
        [("apiVersion: ", c_purple, False), ("v1", c_white, True)],
        [("kind: ", c_purple, False), ("Secret", c_white, True)],
        [("metadata:", c_purple, False)],
        [("  name: ", c_white, False), ("api-tls", c_green, True)],
        [("  namespace: ", c_white, False), ("production", c_cyan, True)],
        [("  annotations:", c_purple, False)],
        [("    cert-chain-doctor.io/repaired-at: ", c_muted, False), ('"2026-10-24T02:40:00Z"', c_gold, False)],
        [("    cert-chain-doctor.io/source: ", c_muted, False), ('"api.example.com:443"', c_white, False)],
        [("type: ", c_purple, False), ("kubernetes.io/tls", c_cyan, True)],
        [("data:", c_purple, False)],
        [("  tls.crt: ", c_white, False), ("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZkekNDQTErZ0F3S... (repaired fullchain)", c_muted, False)],
        [("  tls.key: ", c_white, False), ('""', c_muted, False), ("  # populate with base64 private key before applying", c_muted, False)],
        [("", c_white, False)],
        [("# Apply directly with kubectl:", c_muted, False)],
        [("$ ", c_prompt, True), ("cert-chain-doctor api.example.com --k8s-secret api-tls | kubectl apply -f -", c_cyan, True)],
        [("secret/api-tls created in namespace production", c_green, True)]
    ]
    generate_terminal_svg("cert-chain-doctor --k8s-secret api-tls", lines, "docs/assets/screenshot-k8s-secret.svg")

if __name__ == "__main__":
    build_healthy_scan()
    build_broken_aia_repair()
    build_batch_audit()
    build_k8s_secret()
