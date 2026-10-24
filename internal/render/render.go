package render

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/probe"
)

// ColorMode specifies when to apply ANSI terminal colors.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// OutputData packages all diagnosis results for rendering.
type OutputData struct {
	Target          string                   `json:"target,omitempty"`
	Handshake       *probe.HandshakeDetails  `json:"handshake,omitempty"`
	Analysis        *analyzer.AnalysisResult `json:"analysis"`
	RepairResult    *aia.RepairResult        `json:"repair,omitempty"`
	FixBundlePath   string                   `json:"fix_bundle_path,omitempty"`
	K8sSecretName   string                   `json:"k8s_secret_name,omitempty"`
	K8sNamespace    string                   `json:"k8s_namespace,omitempty"`
	Revocation      *RevocationInfo          `json:"revocation,omitempty"`
}

// RevocationInfo captures the status of OCSP/CRL checks.
type RevocationInfo struct {
	OCSPChecked     bool     `json:"ocsp_checked"`
	OCSPReachable   bool     `json:"ocsp_reachable"`
	OCSPServers     []string `json:"ocsp_servers,omitempty"`
	CRLDistribution []string `json:"crl_distribution,omitempty"`
	CRLReachable    bool     `json:"crl_reachable"`
	Message         string   `json:"message,omitempty"`
}

// RenderOptions configures visual display formatting.
type RenderOptions struct {
	ColorMode ColorMode
}

// Colors holds ANSI formatting helpers.
type Colors struct {
	enabled bool
}

func newColors(mode ColorMode, w io.Writer) Colors {
	enabled := false
	switch mode {
	case ColorAlways:
		enabled = true
	case ColorNever:
		enabled = false
	default:
		// Auto: check NO_COLOR env, then check if w is terminal
		if os.Getenv("NO_COLOR") == "" {
			if f, ok := w.(*os.File); ok {
				// Simple heuristic: file descriptor 1 is stdout
				stat, err := f.Stat()
				if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
					enabled = true
				}
			}
		}
	}
	return Colors{enabled: enabled}
}

func (c Colors) Red(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}

func (c Colors) Green(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

func (c Colors) Yellow(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

func (c Colors) Cyan(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[36m" + s + "\033[0m"
}

func (c Colors) Bold(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func (c Colors) BoldRed(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[1;31m" + s + "\033[0m"
}

func (c Colors) BoldGreen(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[1;32m" + s + "\033[0m"
}

func (c Colors) BoldYellow(s string) string {
	if !c.enabled {
		return s
	}
	return "\033[1;33m" + s + "\033[0m"
}

// RenderJSON writes the formatted JSON structure to w.
func RenderJSON(w io.Writer, data OutputData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// RenderText writes the human-friendly ASCII tree diagram and diagnosis report to w.
func RenderText(w io.Writer, data OutputData, opts ...RenderOptions) {
	colorMode := ColorAuto
	if len(opts) > 0 && opts[0].ColorMode != "" {
		colorMode = opts[0].ColorMode
	}
	c := newColors(colorMode, w)

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "              %s\n", c.Bold("CERT CHAIN DOCTOR - TLS & CHAIN DIAGNOSTIC"))
	fmt.Fprintln(w, "================================================================================")

	// 1. Connection / File summary
	if data.Handshake != nil {
		if data.Handshake.IsFileProbe {
			fmt.Fprintf(w, "Source: %s\n", c.Cyan("Local PEM File ("+data.Target+")"))
		} else {
			fmt.Fprintf(w, "Target:     %s\n", c.Bold(data.Target))
			if data.Handshake.ServerName != "" {
				fmt.Fprintf(w, "SNI:        %s\n", data.Handshake.ServerName)
			}
			if data.Handshake.RemoteAddr != "" {
				fmt.Fprintf(w, "Remote IP:  %s\n", data.Handshake.RemoteAddr)
			}
			fmt.Fprintf(w, "TLS Conn:   %s | %s", c.Cyan(data.Handshake.TLSVersion), c.Cyan(data.Handshake.CipherSuite))
			if data.Handshake.NegotiatedALPN != "" {
				fmt.Fprintf(w, " | ALPN: %s", data.Handshake.NegotiatedALPN)
			}
			stapleStr := "No"
			if data.Handshake.OCSPStapled {
				stapleStr = c.Green("Yes")
			}
			fmt.Fprintf(w, " | OCSP Stapled: %s", stapleStr)
			if data.Handshake.HandshakeDuration > 0 {
				fmt.Fprintf(w, " | Handshake: %v", data.Handshake.HandshakeDuration.Round(time.Millisecond))
			}
			fmt.Fprintln(w)
		}
	} else if data.Target != "" {
		fmt.Fprintf(w, "Target: %s\n", data.Target)
	}
	fmt.Fprintln(w)

	// 2. Visual Certificate Chain Tree
	fmt.Fprintln(w, c.Bold("CERTIFICATE CHAIN TREE:"))
	certs := data.Analysis.Certificates
	totalCerts := len(certs)

	if totalCerts == 0 {
		fmt.Fprintln(w, "  (No certificates discovered)")
	} else {
		for i, cert := range certs {
			isLast := (i == totalCerts-1)
			prefix := "├──"
			subPrefix := "│  "
			if isLast && data.RepairResult == nil {
				prefix = "└──"
				subPrefix = "   "
			}

			// Tag description
			roleTag := "Leaf"
			if cert.IsRoot {
				roleTag = "Root CA"
			} else if cert.IsCA {
				roleTag = "Intermediate CA"
			}

			var statusBadges []string
			if cert.IsRoot && i == totalCerts-1 && totalCerts > 1 {
				statusBadges = append(statusBadges, c.Yellow("REDUNDANT ROOT - Wastes Bytes"))
			}
			if cert.DaysUntilExpiry < 0 {
				statusBadges = append(statusBadges, c.BoldRed("EXPIRED"))
			} else if cert.DaysUntilExpiry <= 14 {
				statusBadges = append(statusBadges, c.BoldYellow(fmt.Sprintf("EXPIRING SOON (%dd)", cert.DaysUntilExpiry)))
			}

			badgeStr := ""
			if len(statusBadges) > 0 {
				badgeStr = " [" + strings.Join(statusBadges, ", ") + "]"
			}

			fmt.Fprintf(w, "%s [%d] %s: %s%s\n", prefix, i, roleTag, c.Bold(cert.CommonName), badgeStr)
			fmt.Fprintf(w, "%s ├── Subject:  %s\n", subPrefix, cert.Subject)
			fmt.Fprintf(w, "%s ├── Issuer:   %s\n", subPrefix, cert.Issuer)
			fmt.Fprintf(w, "%s ├── Validity: %s to %s (%d days left)\n",
				subPrefix,
				cert.NotBefore.Format("2006-01-02"),
				cert.NotAfter.Format("2006-01-02"),
				cert.DaysUntilExpiry,
			)
			fmt.Fprintf(w, "%s ├── Key:      %s %d-bit | Sig: %s\n",
				subPrefix,
				cert.KeyAlgorithm,
				cert.KeySize,
				cert.SignatureAlgorithm,
			)

			if len(cert.DNSNames) > 0 {
				sanLimit := 4
				sanDisplay := cert.DNSNames
				more := ""
				if len(cert.DNSNames) > sanLimit {
					sanDisplay = cert.DNSNames[:sanLimit]
					more = fmt.Sprintf(" (+%d more)", len(cert.DNSNames)-sanLimit)
				}
				fmt.Fprintf(w, "%s ├── SANs:     %s%s\n", subPrefix, strings.Join(sanDisplay, ", "), more)
			}

			if cert.SubjectKeyID != "" {
				fmt.Fprintf(w, "%s ├── SKI:      %s\n", subPrefix, truncateID(cert.SubjectKeyID))
			}

			// Show AKI link pointing to next cert or missing
			if cert.AuthorityKeyID != "" {
				linkTarget := "Unknown"
				if i+1 < totalCerts && matchKeyID(cert.AuthorityKeyID, certs[i+1].SubjectKeyID) {
					linkTarget = c.Green(fmt.Sprintf("[%d]", i+1))
				} else if cert.IsSelfSigned {
					linkTarget = c.Green("Self")
				} else if data.Analysis.HasMissingInter && i == totalCerts-1 {
					linkTarget = c.BoldRed("MISSING INTERMEDIATE")
				}
				fmt.Fprintf(w, "%s ├── AKI:      %s -> %s\n", subPrefix, truncateID(cert.AuthorityKeyID), linkTarget)
			}

			if len(cert.AIAIssuers) > 0 {
				fmt.Fprintf(w, "%s └── AIA URL:  %s\n", subPrefix, c.Cyan(strings.Join(cert.AIAIssuers, ", ")))
			} else {
				fmt.Fprintf(w, "%s └── AIA:      None\n", subPrefix)
			}

			if !isLast {
				fmt.Fprintln(w, "│")
			}
		}

		// If intermediate was missing and fetched via repair, show in tree
		if data.RepairResult != nil && len(data.RepairResult.FetchedCerts) > 0 {
			fmt.Fprintln(w, "│")
			for j, fetched := range data.RepairResult.FetchedCerts {
				isLastFetched := (j == len(data.RepairResult.FetchedCerts)-1)
				prefix := "├──"
				subPrefix := "│  "
				if isLastFetched {
					prefix = "└──"
					subPrefix = "   "
				}
				idx := totalCerts + j
				daysLeft := int(fetched.NotAfter.Sub(time.Now()).Hours() / 24)
				fmt.Fprintf(w, "%s [%d] %s: %s\n", prefix, idx, c.BoldGreen("Intermediate (RESOLVED VIA AIA)"), c.Bold(fetched.Subject.CommonName))
				fmt.Fprintf(w, "%s ├── Subject:  %s\n", subPrefix, fetched.Subject.String())
				fmt.Fprintf(w, "%s ├── Issuer:   %s\n", subPrefix, fetched.Issuer.String())
				fmt.Fprintf(w, "%s ├── Validity: %s to %s (%d days left)\n",
					subPrefix,
					fetched.NotBefore.Format("2006-01-02"),
					fetched.NotAfter.Format("2006-01-02"),
					daysLeft,
				)
				if len(data.RepairResult.FetchedFromURLs) > j {
					fmt.Fprintf(w, "%s └── Fetched:  %s\n", subPrefix, c.Cyan(data.RepairResult.FetchedFromURLs[j]))
				}
			}
		}
	}
	fmt.Fprintln(w)

	// 3. Findings & Issues
	fmt.Fprintln(w, c.Bold("FINDINGS & DIAGNOSIS:"))
	if len(data.Analysis.Issues) == 0 {
		fmt.Fprintf(w, "  %s No issues detected. Chain structure is optimal.\n", c.BoldGreen("[OK]"))
	} else {
		for _, iss := range data.Analysis.Issues {
			var tag string
			switch iss.Severity {
			case analyzer.SeverityError:
				tag = c.BoldRed(fmt.Sprintf("[%-7s]", iss.Severity))
			case analyzer.SeverityWarning:
				tag = c.BoldYellow(fmt.Sprintf("[%-7s]", iss.Severity))
			default:
				tag = c.Cyan(fmt.Sprintf("[%-7s]", iss.Severity))
			}

			fmt.Fprintf(w, "  %s %s\n", tag, c.Bold(iss.Code))
			fmt.Fprintf(w, "            %s\n", iss.Message)
			if iss.Remediation != "" {
				fmt.Fprintf(w, "            -> Remediation: %s\n", c.Cyan(iss.Remediation))
			}
			fmt.Fprintln(w)
		}
	}

	// 4. Bundle Repair summary if requested
	if data.FixBundlePath != "" && data.RepairResult != nil {
		fmt.Fprintln(w, c.Bold("AIA CHAIN REPAIR:"))
		fmt.Fprintf(w, "  Output File:        %s\n", c.Cyan(data.FixBundlePath))
		fmt.Fprintf(w, "  Total Chain Certs:  %d\n", len(data.RepairResult.RepairedChain))
		fmt.Fprintf(w, "  Intermediates Added: %d\n", len(data.RepairResult.FetchedCerts))
		if data.RepairResult.StrippedRedundantRoot {
			fmt.Fprintf(w, "  Redundant Root:     %s\n", c.Yellow("Stripped from bundle"))
		}
		if data.RepairResult.Reordered {
			fmt.Fprintf(w, "  Chain Order:        %s\n", c.Green("Corrected (Leaf -> Intermediate)"))
		}
		if data.RepairResult.VerifiedAgainstRoots {
			fmt.Fprintf(w, "  Root Verification:  %s\n", c.BoldGreen("SUCCESSFUL (chain trusted by root store)"))
		}
		fmt.Fprintln(w)
	}

	// 5. Revocation & OCSP Status if requested
	if data.Revocation != nil && (data.Revocation.OCSPChecked || len(data.Revocation.CRLDistribution) > 0) {
		fmt.Fprintln(w, c.Bold("REVOCATION ENDPOINTS:"))
		if data.Revocation.OCSPChecked {
			statusTag := c.Red("UNREACHABLE")
			if data.Revocation.OCSPReachable {
				statusTag = c.Green("REACHABLE")
			}
			fmt.Fprintf(w, "  OCSP Responder:     %s (%s)\n", statusTag, data.Revocation.Message)
		}
		if len(data.Revocation.CRLDistribution) > 0 {
			crlTag := c.Yellow("UNCHECKED")
			if data.Revocation.CRLReachable {
				crlTag = c.Green("REACHABLE")
			}
			fmt.Fprintf(w, "  CRL Distribution:   %s (%s)\n", crlTag, strings.Join(data.Revocation.CRLDistribution, ", "))
		}
		fmt.Fprintln(w)
	}

	// 5. Kubernetes Secret Manifest if requested
	if data.K8sSecretName != "" && data.RepairResult != nil {
		fmt.Fprintln(w, c.Bold("KUBERNETES TLS SECRET MANIFEST:"))
		secretYAML := GenerateK8sSecret(data.K8sSecretName, data.K8sNamespace, data.RepairResult.PEMBundle)
		for _, line := range strings.Split(secretYAML, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
		fmt.Fprintln(w)
	}

	// 6. Overall Verdict Banner
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
	if strings.HasPrefix(data.Analysis.SummaryVerdict, "HEALTHY") {
		fmt.Fprintf(w, "VERDICT: %s\n", c.BoldGreen(data.Analysis.SummaryVerdict))
	} else if strings.HasPrefix(data.Analysis.SummaryVerdict, "WARNINGS") {
		fmt.Fprintf(w, "VERDICT: %s\n", c.BoldYellow(data.Analysis.SummaryVerdict))
	} else {
		fmt.Fprintf(w, "VERDICT: %s\n", c.BoldRed(data.Analysis.SummaryVerdict))
	}
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
}

// BatchSummaryItem represents an individual target in a batch scan.
type BatchSummaryItem struct {
	Target     string   `json:"target"`
	TLSVersion string   `json:"tls_version"`
	Status     string   `json:"status"`
	DaysLeft   int      `json:"days_left"`
	Issues     []string `json:"issues,omitempty"`
}

// RenderBatchTable outputs an aligned ASCII table summarizing batch audit results.
func RenderBatchTable(w io.Writer, items []BatchSummaryItem, colorMode ColorMode) {
	c := newColors(colorMode, w)

	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "                   %s\n", c.Bold("CERT CHAIN DOCTOR - BATCH AUDIT SUMMARY"))
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintf(w, "%-32s %-10s %-12s %-8s %s\n", "TARGET", "TLS", "STATUS", "EXPIRY", "FINDINGS")
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")

	for _, item := range items {
		var statusStr string
		switch item.Status {
		case "HEALTHY":
			statusStr = c.BoldGreen("HEALTHY")
		case "WARNING":
			statusStr = c.BoldYellow("WARNING")
		default:
			statusStr = c.BoldRed("BROKEN")
		}

		issuesStr := "None"
		if len(item.Issues) > 0 {
			issuesStr = strings.Join(item.Issues, ", ")
		}

		expiryStr := fmt.Sprintf("%dd", item.DaysLeft)
		if item.DaysLeft < 0 {
			expiryStr = c.BoldRed("EXPIRED")
		}

		fmt.Fprintf(w, "%-32s %-10s %-12s %-8s %s\n",
			truncateString(item.Target, 31),
			item.TLSVersion,
			statusStr,
			expiryStr,
			truncateString(issuesStr, 25),
		)
	}
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// GenerateK8sSecret formats a Kubernetes TLS secret manifest embedding the PEM certificate bundle.
func GenerateK8sSecret(name, namespace string, pemBundle []byte) string {
	if namespace == "" {
		namespace = "default"
	}
	b64Cert := base64.StdEncoding.EncodeToString(pemBundle)

	var sb strings.Builder
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Secret\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("type: kubernetes.io/tls\n")
	sb.WriteString("data:\n")
	sb.WriteString(fmt.Sprintf("  tls.crt: %s\n", b64Cert))
	sb.WriteString("  tls.key: \"\" # Optional: base64 encoded private key\n")
	return strings.TrimSpace(sb.String())
}

func truncateID(id string) string {
	if len(id) <= 23 {
		return id
	}
	return id[:11] + "..." + id[len(id)-8:]
}

func matchKeyID(aki, ski string) bool {
	return aki != "" && ski != "" && strings.EqualFold(aki, ski)
}
