package revocation

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// RevocationStatus captures the result of OCSP and CRL checking.
type RevocationStatus struct {
	OCSPChecked     bool     `json:"ocsp_checked"`
	OCSPReachable   bool     `json:"ocsp_reachable"`
	OCSPServers     []string `json:"ocsp_servers,omitempty"`
	CRLDistribution []string `json:"crl_distribution,omitempty"`
	CRLReachable    bool     `json:"crl_reachable"`
	Message         string   `json:"message,omitempty"`
}

// CheckRevocationEndpoints verifies whether the certificate's OCSP or CRL endpoints are reachable.
func CheckRevocationEndpoints(ctx context.Context, cert *x509.Certificate, client *http.Client) RevocationStatus {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	status := RevocationStatus{
		OCSPServers:     cert.OCSPServer,
		CRLDistribution: cert.CRLDistributionPoints,
	}

	if len(cert.OCSPServer) == 0 && len(cert.CRLDistributionPoints) == 0 {
		status.Message = "No OCSP or CRL distribution endpoints defined in certificate"
		return status
	}

	// 1. Check OCSP Reachability
	if len(cert.OCSPServer) > 0 {
		status.OCSPChecked = true
		for _, server := range cert.OCSPServer {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "cert-chain-doctor/1.0")

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				// Any HTTP response (including 200, 400, 405) means server is network reachable
				if resp.StatusCode >= 200 && resp.StatusCode < 500 {
					status.OCSPReachable = true
					break
				}
			}
		}
	}

	// 2. Check CRL Reachability
	if len(cert.CRLDistributionPoints) > 0 {
		for _, crlURL := range cert.CRLDistributionPoints {
			req, err := http.NewRequestWithContext(ctx, http.MethodHead, crlURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "cert-chain-doctor/1.0")

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					status.CRLReachable = true
					break
				}
			}
		}
	}

	if status.OCSPReachable {
		status.Message = fmt.Sprintf("OCSP responder reachable (%s)", cert.OCSPServer[0])
	} else if status.OCSPChecked {
		status.Message = "OCSP responder unreachable or timed out"
	}

	return status
}
