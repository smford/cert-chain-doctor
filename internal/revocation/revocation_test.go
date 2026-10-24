package revocation_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smford/cert-chain-doctor/internal/revocation"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestCheckRevocationEndpoints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate suite: %v", err)
	}
	defer suite.Close()

	suite.LeafCert.OCSPServer = []string{ts.URL + "/ocsp"}
	suite.LeafCert.CRLDistributionPoints = []string{ts.URL + "/crl.crl"}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status := revocation.CheckRevocationEndpoints(ctx, suite.LeafCert, ts.Client())
	if !status.OCSPChecked {
		t.Errorf("Expected OCSPChecked = true")
	}
	if !status.OCSPReachable {
		t.Errorf("Expected OCSPReachable = true")
	}
	if !status.CRLReachable {
		t.Errorf("Expected CRLReachable = true")
	}
}

func TestCheckRevocationEndpoints_NoEndpoints(t *testing.T) {
	cert := &x509.Certificate{}
	status := revocation.CheckRevocationEndpoints(context.Background(), cert, nil)
	if status.OCSPChecked {
		t.Errorf("Expected OCSPChecked = false for empty cert")
	}
}
