package analyzer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Severity indicates the seriousness of a diagnostic finding.
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
)

// Issue represents a diagnosed finding in the certificate chain.
type Issue struct {
	Severity    Severity `json:"severity"`
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	CertIndex   int      `json:"cert_index,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// CertDetails contains human-readable properties of an individual certificate.
type CertDetails struct {
	Index              int       `json:"index"`
	Subject            string    `json:"subject"`
	CommonName         string    `json:"common_name"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
	IsCA               bool      `json:"is_ca"`
	IsSelfSigned       bool      `json:"is_self_signed"`
	IsRoot             bool      `json:"is_root"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeySize            int       `json:"key_size"`
	SubjectKeyID       string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string    `json:"authority_key_id,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	AIAIssuers         []string  `json:"aia_issuers,omitempty"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	CRLDistribution    []string  `json:"crl_distribution_points,omitempty"`
}

// AnalysisResult contains the complete findings of the certificate chain diagnosis.
type AnalysisResult struct {
	Hostname             string        `json:"hostname,omitempty"`
	Certificates         []CertDetails `json:"certificates"`
	ChainLength          int           `json:"chain_length"`
	IsValid              bool          `json:"is_valid"`
	VerifiedChainsCount  int           `json:"verified_chains_count"`
	HasMissingInter      bool          `json:"has_missing_intermediate"`
	HasRedundantRoot     bool          `json:"has_redundant_root"`
	IsMisordered         bool          `json:"is_misordered"`
	CanFixViaAIA         bool          `json:"can_fix_via_aia"`
	CandidateAIAURLs     []string      `json:"candidate_aia_urls,omitempty"`
	Issues               []Issue       `json:"issues"`
	VerificationError    string        `json:"verification_error,omitempty"`
	SummaryVerdict       string        `json:"summary_verdict"`
}

// AnalyzeOptions configures the chain analyzer.
type AnalyzeOptions struct {
	Hostname        string
	RootPool        *x509.CertPool
	WarnExpiryDays  int
	CurrentTime     time.Time
}

// Analyze evaluates a list of raw certificates from a TLS handshake or PEM bundle.
func Analyze(certs []*x509.Certificate, opts AnalyzeOptions) *AnalysisResult {
	if opts.WarnExpiryDays <= 0 {
		opts.WarnExpiryDays = 14
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	result := &AnalysisResult{
		Hostname:     opts.Hostname,
		ChainLength:  len(certs),
		Certificates: make([]CertDetails, 0, len(certs)),
		Issues:       make([]Issue, 0),
	}

	if len(certs) == 0 {
		result.Issues = append(result.Issues, Issue{
			Severity:    SeverityError,
			Code:        "NO_CERTIFICATES",
			Message:     "No certificates provided in chain",
			Remediation: "Ensure the server presents a certificate or the PEM file contains valid certificates.",
		})
		result.SummaryVerdict = "FAILED: No certificates provided"
		return result
	}

	// 1. Populate CertDetails
	for i, cert := range certs {
		isSelfSigned := isCertSelfSigned(cert)
		isRoot := cert.IsCA && isSelfSigned
		daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)

		ipStrs := make([]string, len(cert.IPAddresses))
		for idx, ip := range cert.IPAddresses {
			ipStrs[idx] = ip.String()
		}

		keyAlg, keySize := getKeyInfo(cert)

		cd := CertDetails{
			Index:              i,
			Subject:            cert.Subject.String(),
			CommonName:         cert.Subject.CommonName,
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.Text(16),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			DaysUntilExpiry:    daysUntil,
			IsCA:               cert.IsCA,
			IsSelfSigned:       isSelfSigned,
			IsRoot:             isRoot,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			KeyAlgorithm:       keyAlg,
			KeySize:            keySize,
			SubjectKeyID:       formatKeyID(cert.SubjectKeyId),
			AuthorityKeyID:     formatKeyID(cert.AuthorityKeyId),
			DNSNames:           cert.DNSNames,
			IPAddresses:        ipStrs,
			AIAIssuers:         cert.IssuingCertificateURL,
			OCSPServers:        cert.OCSPServer,
			CRLDistribution:    cert.CRLDistributionPoints,
		}
		result.Certificates = append(result.Certificates, cd)
	}

	// 2. Check each certificate individually (Expiry, weak algorithm, weak keys)
	for i, cert := range certs {
		// Expiry check
		if now.Before(cert.NotBefore) {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityError,
				Code:        "CERT_NOT_YET_VALID",
				Message:     fmt.Sprintf("Certificate [%d] (%s) is not valid until %s", i, cert.Subject.CommonName, cert.NotBefore.Format(time.RFC3339)),
				CertIndex:   i,
				Remediation: "Check system clocks or wait until certificate validity begins.",
			})
		} else if now.After(cert.NotAfter) {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityError,
				Code:        "CERT_EXPIRED",
				Message:     fmt.Sprintf("Certificate [%d] (%s) expired on %s (%d days ago)", i, cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339), -result.Certificates[i].DaysUntilExpiry),
				CertIndex:   i,
				Remediation: "Renew certificate immediately.",
			})
		} else if result.Certificates[i].DaysUntilExpiry <= opts.WarnExpiryDays {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityWarning,
				Code:        "CERT_EXPIRING_SOON",
				Message:     fmt.Sprintf("Certificate [%d] (%s) expires in %d days (%s)", i, cert.Subject.CommonName, result.Certificates[i].DaysUntilExpiry, cert.NotAfter.Format(time.RFC3339)),
				CertIndex:   i,
				Remediation: fmt.Sprintf("Schedule renewal before expiration within %d days.", opts.WarnExpiryDays),
			})
		}

		// Weak signature algorithm
		if isWeakSignature(cert.SignatureAlgorithm) {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityError,
				Code:        "WEAK_SIGNATURE_ALGORITHM",
				Message:     fmt.Sprintf("Certificate [%d] uses deprecated/weak signature algorithm: %s", i, cert.SignatureAlgorithm.String()),
				CertIndex:   i,
				Remediation: "Re-issue certificate with SHA-256 or stronger signature.",
			})
		}

		// Weak key size
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			bits := rsaKey.N.BitLen()
			if bits < 2048 {
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "INSECURE_RSA_KEY_SIZE",
					Message:     fmt.Sprintf("Certificate [%d] uses weak RSA key size (%d bits < 2048 bits)", i, bits),
					CertIndex:   i,
					Remediation: "Generate a new private key of at least 2048 bits (3072+ recommended) or ECDSA P-256.",
				})
			}
		}
	}

	// 3. Leaf Certificate SAN / Hostname check
	leafCert := certs[0]
	if opts.Hostname != "" {
		hostOnly := opts.Hostname
		if h, _, err := net.SplitHostPort(opts.Hostname); err == nil {
			hostOnly = h
		}
		if err := leafCert.VerifyHostname(hostOnly); err != nil {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityError,
				Code:        "HOSTNAME_MISMATCH",
				Message:     fmt.Sprintf("Leaf certificate does not match target hostname '%s': %v", hostOnly, err),
				CertIndex:   0,
				Remediation: fmt.Sprintf("Reissue certificate with SAN (Subject Alternative Name) containing '%s'.", hostOnly),
			})
		}
	}

	// 4. Chain Ordering check
	// Leaf should be at index 0. If index 0 is CA and a later cert is non-CA, it's misordered.
	if leafCert.IsCA && len(certs) > 1 {
		// check if any non-CA exists later
		for j := 1; j < len(certs); j++ {
			if !certs[j].IsCA {
				result.IsMisordered = true
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "MISORDERED_CHAIN_LEAF_NOT_FIRST",
					Message:     fmt.Sprintf("Chain is misordered: CA certificate is at index 0 while leaf certificate is at index %d", j),
					Remediation: "Order bundle starting with the end-entity (leaf) certificate followed by intermediate certificates.",
				})
				break
			}
		}
	}

	// Check parent-child continuity along the provided chain
	for i := 0; i < len(certs)-1; i++ {
		child := certs[i]
		parent := certs[i+1]

		// Check if parent issued child
		err := child.CheckSignatureFrom(parent)
		if err != nil {
			// They don't link directly! Check if reversed
			if revErr := parent.CheckSignatureFrom(child); revErr == nil {
				result.IsMisordered = true
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "MISORDERED_CHAIN_REVERSED",
					Message:     fmt.Sprintf("Chain order is inverted between cert [%d] (%s) and cert [%d] (%s)", i, child.Subject.CommonName, i+1, parent.Subject.CommonName),
					Remediation: "Reorder certificates in the PEM bundle: Leaf -> Intermediate(s).",
				})
			} else {
				// Disconnected chain segment
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "BROKEN_CHAIN_LINK",
					Message:     fmt.Sprintf("Certificate [%d] (%s) was not signed by following certificate [%d] (%s)", i, child.Subject.CommonName, i+1, parent.Subject.CommonName),
					Remediation: "Ensure intermediate certificates form an unbroken cryptographic chain.",
				})
			}
		}
	}

	// 5. Unnecessary / Redundant Root CA in handshake
	lastCert := certs[len(certs)-1]
	if isCertSelfSigned(lastCert) && lastCert.IsCA {
		result.HasRedundantRoot = true
		result.Issues = append(result.Issues, Issue{
			Severity:    SeverityWarning,
			Code:        "REDUNDANT_ROOT_IN_HANDSHAKE",
			Message:     fmt.Sprintf("Handshake includes self-signed Root CA at index [%d] (%s). Root CAs should not be sent over TLS as clients already have them in trust stores.", len(certs)-1, lastCert.Subject.CommonName),
			CertIndex:   len(certs) - 1,
			Remediation: "Remove the Root CA from your server certificate bundle to save TLS handshake bytes and reduce latency.",
		})
	}

	// 6. Verification against Root Pool & Missing Intermediate Detection
	roots := opts.RootPool
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
	}

	interPool := x509.NewCertPool()
	for _, c := range certs[1:] {
		interPool.AddCert(c)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: interPool,
		CurrentTime:   now,
	}
	if opts.Hostname != "" {
		hostOnly := opts.Hostname
		if h, _, err := net.SplitHostPort(opts.Hostname); err == nil {
			hostOnly = h
		}
		verifyOpts.DNSName = hostOnly
	}

	verifiedChains, verifyErr := leafCert.Verify(verifyOpts)
	if verifyErr != nil {
		result.IsValid = false
		result.VerificationError = verifyErr.Error()

		// Diagnose if missing intermediate is the cause
		// Check if the terminal non-root cert's issuer is unknown
		var terminalCert *x509.Certificate
		// Find the last cert in the chain that is signed by someone else
		terminalCert = certs[len(certs)-1]
		if isCertSelfSigned(terminalCert) && len(certs) > 1 {
			terminalCert = certs[len(certs)-2]
		}

		// If verify failed with unknown authority, check AIA URLs
		if isUnknownAuthority(verifyErr) {
			result.HasMissingInter = true

			// Collect AIA URLs from leaf and intermediates
			var aiaURLs []string
			for _, c := range certs {
				aiaURLs = append(aiaURLs, c.IssuingCertificateURL...)
			}
			if len(aiaURLs) > 0 {
				result.CanFixViaAIA = true
				result.CandidateAIAURLs = aiaURLs
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "MISSING_INTERMEDIATE_AIA_AVAILABLE",
					Message:     fmt.Sprintf("Chain is missing intermediate CA certificate(s) ('unknown authority' error in curl/Alpine/Go). AIA download URL found: %s", strings.Join(aiaURLs, ", ")),
					Remediation: "Run cert-chain-doctor with --fix-bundle <repaired.pem> to automatically fetch and assemble the complete chain.",
				})
			} else {
				result.Issues = append(result.Issues, Issue{
					Severity:    SeverityError,
					Code:        "MISSING_INTERMEDIATE_NO_AIA",
					Message:     "Chain is missing intermediate CA certificate(s), and no AIA (Authority Information Access) URL is present in the certificate to auto-resolve it.",
					Remediation: "Obtain intermediate CA certificates from your Certificate Authority and bundle them with the leaf certificate.",
				})
			}
		} else {
			result.Issues = append(result.Issues, Issue{
				Severity:    SeverityError,
				Code:        "VERIFICATION_FAILED",
				Message:     fmt.Sprintf("Certificate verification failed: %v", verifyErr),
				Remediation: "Resolve certificate validity or hostname issues.",
			})
		}
	} else {
		result.IsValid = true
		result.VerifiedChainsCount = len(verifiedChains)
	}

	// 7. Overall Verdict Formulation
	hasErrors := false
	hasWarnings := false
	for _, iss := range result.Issues {
		if iss.Severity == SeverityError {
			hasErrors = true
		} else if iss.Severity == SeverityWarning {
			hasWarnings = true
		}
	}

	if hasErrors {
		if result.HasMissingInter && result.CanFixViaAIA {
			result.SummaryVerdict = "BROKEN CHAIN: Missing intermediate CA certificate (fixable via AIA with --fix-bundle)"
		} else if result.IsMisordered {
			result.SummaryVerdict = "BROKEN CHAIN: Certificate chain is misordered"
		} else {
			result.SummaryVerdict = fmt.Sprintf("FAILED: %s", result.VerificationError)
		}
	} else if hasWarnings {
		result.SummaryVerdict = "WARNINGS FOUND: Chain is cryptographically trusted but has configuration warnings"
	} else {
		result.SummaryVerdict = "HEALTHY: Certificate chain is complete, properly ordered, and cryptographically trusted"
	}

	return result
}

func isCertSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		err := cert.CheckSignatureFrom(cert)
		return err == nil
	}
	return false
}

func formatKeyID(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	parts := make([]string, len(id))
	for i, b := range id {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func getKeyInfo(cert *x509.Certificate) (string, int) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

func isWeakSignature(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func isUnknownAuthority(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(x509.UnknownAuthorityError); ok {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown authority") ||
		strings.Contains(msg, "signed by unknown authority") ||
		strings.Contains(msg, "not trusted") ||
		strings.Contains(msg, "certificate is not trusted") ||
		strings.Contains(msg, "bad signature")
}

// FormatHex returns lower-cased hex representation.
func FormatHex(b []byte) string {
	return hex.EncodeToString(b)
}
