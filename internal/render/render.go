package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/probe"
)

// OutputData packages all diagnosis results for rendering.
type OutputData struct {
	Target       string                   `json:"target,omitempty"`
	Handshake    *probe.HandshakeDetails  `json:"handshake,omitempty"`
	Analysis     *analyzer.AnalysisResult `json:"analysis"`
	RepairResult *aia.RepairResult        `json:"repair,omitempty"`
	FixBundlePath string                  `json:"fix_bundle_path,omitempty"`
}

// RenderJSON writes the formatted JSON structure to w.
func RenderJSON(w io.Writer, data OutputData) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// RenderText writes the human-friendly ASCII tree diagram and diagnosis report to w.
func RenderText(w io.Writer, data OutputData) {
	fmt.Fprintln(w, "================================================================================")
	fmt.Fprintln(w, "                     CERT CHAIN DOCTOR - TLS & CHAIN DIAGNOSTIC                 ")
	fmt.Fprintln(w, "================================================================================")

	// 1. Connection / File summary
	if data.Handshake != nil {
		if data.Handshake.IsFileProbe {
			fmt.Fprintf(w, "Source: Local PEM File (%s)\n", data.Target)
		} else {
			fmt.Fprintf(w, "Target:     %s\n", data.Target)
			if data.Handshake.ServerName != "" {
				fmt.Fprintf(w, "SNI:        %s\n", data.Handshake.ServerName)
			}
			if data.Handshake.RemoteAddr != "" {
				fmt.Fprintf(w, "Remote IP:  %s\n", data.Handshake.RemoteAddr)
			}
			fmt.Fprintf(w, "TLS Conn:   %s | %s", data.Handshake.TLSVersion, data.Handshake.CipherSuite)
			if data.Handshake.NegotiatedALPN != "" {
				fmt.Fprintf(w, " | ALPN: %s", data.Handshake.NegotiatedALPN)
			}
			stapleStr := "No"
			if data.Handshake.OCSPStapled {
				stapleStr = "Yes"
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
	fmt.Fprintln(w, "CERTIFICATE CHAIN TREE:")
	certs := data.Analysis.Certificates
	totalCerts := len(certs)

	if totalCerts == 0 {
		fmt.Fprintln(w, "  (No certificates discovered)")
	} else {
		for i, c := range certs {
			isLast := (i == totalCerts-1)
			prefix := "├──"
			subPrefix := "│  "
			if isLast && data.RepairResult == nil {
				prefix = "└──"
				subPrefix = "   "
			}

			// Tag description
			roleTag := "Leaf"
			if c.IsRoot {
				roleTag = "Root CA"
			} else if c.IsCA {
				roleTag = "Intermediate CA"
			}

			var statusBadges []string
			if c.IsRoot && i == totalCerts-1 && totalCerts > 1 {
				statusBadges = append(statusBadges, "REDUNDANT ROOT - Wastes Bytes")
			}
			if c.DaysUntilExpiry < 0 {
				statusBadges = append(statusBadges, "EXPIRED")
			} else if c.DaysUntilExpiry <= 14 {
				statusBadges = append(statusBadges, fmt.Sprintf("EXPIRING SOON (%dd)", c.DaysUntilExpiry))
			}

			badgeStr := ""
			if len(statusBadges) > 0 {
				badgeStr = " [" + strings.Join(statusBadges, ", ") + "]"
			}

			fmt.Fprintf(w, "%s [%d] %s: %s%s\n", prefix, i, roleTag, c.CommonName, badgeStr)
			fmt.Fprintf(w, "%s ├── Subject:  %s\n", subPrefix, c.Subject)
			fmt.Fprintf(w, "%s ├── Issuer:   %s\n", subPrefix, c.Issuer)
			fmt.Fprintf(w, "%s ├── Validity: %s to %s (%d days left)\n",
				subPrefix,
				c.NotBefore.Format("2006-01-02"),
				c.NotAfter.Format("2006-01-02"),
				c.DaysUntilExpiry,
			)
			fmt.Fprintf(w, "%s ├── Key:      %s %d-bit | Sig: %s\n",
				subPrefix,
				c.KeyAlgorithm,
				c.KeySize,
				c.SignatureAlgorithm,
			)

			if len(c.DNSNames) > 0 {
				sanLimit := 4
				sanDisplay := c.DNSNames
				more := ""
				if len(c.DNSNames) > sanLimit {
					sanDisplay = c.DNSNames[:sanLimit]
					more = fmt.Sprintf(" (+%d more)", len(c.DNSNames)-sanLimit)
				}
				fmt.Fprintf(w, "%s ├── SANs:     %s%s\n", subPrefix, strings.Join(sanDisplay, ", "), more)
			}

			if c.SubjectKeyID != "" {
				fmt.Fprintf(w, "%s ├── SKI:      %s\n", subPrefix, truncateID(c.SubjectKeyID))
			}

			// Show AKI link pointing to next cert or missing
			if c.AuthorityKeyID != "" {
				linkTarget := "Unknown"
				if i+1 < totalCerts && matchKeyID(c.AuthorityKeyID, certs[i+1].SubjectKeyID) {
					linkTarget = fmt.Sprintf("[%d]", i+1)
				} else if c.IsSelfSigned {
					linkTarget = "Self"
				} else if data.Analysis.HasMissingInter && i == totalCerts-1 {
					linkTarget = "MISSING INTERMEDIATE"
				}
				fmt.Fprintf(w, "%s ├── AKI:      %s -> %s\n", subPrefix, truncateID(c.AuthorityKeyID), linkTarget)
			}

			if len(c.AIAIssuers) > 0 {
				fmt.Fprintf(w, "%s └── AIA URL:  %s\n", subPrefix, strings.Join(c.AIAIssuers, ", "))
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
				fmt.Fprintf(w, "%s [%d] Intermediate (RESOLVED VIA AIA): %s\n", prefix, idx, fetched.Subject.CommonName)
				fmt.Fprintf(w, "%s ├── Subject:  %s\n", subPrefix, fetched.Subject.String())
				fmt.Fprintf(w, "%s ├── Issuer:   %s\n", subPrefix, fetched.Issuer.String())
				fmt.Fprintf(w, "%s ├── Validity: %s to %s (%d days left)\n",
					subPrefix,
					fetched.NotBefore.Format("2006-01-02"),
					fetched.NotAfter.Format("2006-01-02"),
					daysLeft,
				)
				if len(data.RepairResult.FetchedFromURLs) > j {
					fmt.Fprintf(w, "%s └── Fetched:  %s\n", subPrefix, data.RepairResult.FetchedFromURLs[j])
				}
			}
		}
	}
	fmt.Fprintln(w)

	// 3. Findings & Issues
	fmt.Fprintln(w, "FINDINGS & DIAGNOSIS:")
	if len(data.Analysis.Issues) == 0 {
		fmt.Fprintln(w, "  [OK] No issues detected. Chain structure is optimal.")
	} else {
		for _, iss := range data.Analysis.Issues {
			tag := fmt.Sprintf("[%s]", iss.Severity)
			fmt.Fprintf(w, "  %-9s %s\n", tag, iss.Code)
			fmt.Fprintf(w, "            %s\n", iss.Message)
			if iss.Remediation != "" {
				fmt.Fprintf(w, "            -> Remediation: %s\n", iss.Remediation)
			}
			fmt.Fprintln(w)
		}
	}

	// 4. Bundle Repair summary if requested
	if data.FixBundlePath != "" && data.RepairResult != nil {
		fmt.Fprintln(w, "AIA CHAIN REPAIR:")
		fmt.Fprintf(w, "  Output File:        %s\n", data.FixBundlePath)
		fmt.Fprintf(w, "  Total Chain Certs:  %d\n", len(data.RepairResult.RepairedChain))
		fmt.Fprintf(w, "  Intermediates Added: %d\n", len(data.RepairResult.FetchedCerts))
		if data.RepairResult.StrippedRedundantRoot {
			fmt.Fprintf(w, "  Redundant Root:     Stripped from bundle\n")
		}
		if data.RepairResult.Reordered {
			fmt.Fprintf(w, "  Chain Order:        Corrected (Leaf -> Intermediate)\n")
		}
		if data.RepairResult.VerifiedAgainstRoots {
			fmt.Fprintf(w, "  Root Verification:  SUCCESSFUL (chain trusted by root store)\n")
		}
		fmt.Fprintln(w)
	}

	// 5. Overall Verdict Banner
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
	fmt.Fprintf(w, "VERDICT: %s\n", data.Analysis.SummaryVerdict)
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
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
