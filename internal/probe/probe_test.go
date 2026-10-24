package probe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smford/cert-chain-doctor/internal/probe"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestProbe_NetworkBrokenChain(t *testing.T) {
	suite, err := testpki.GenerateSuite("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Configure TLS server with Leaf ONLY (missing intermediate CA)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	ts.TLS = suite.TLSConfig(suite.LeafCert) // Only Leaf presented!
	ts.StartTLS()
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := probe.Probe(ctx, probe.ProbeOptions{
		TargetHost: ts.Listener.Addr().String(),
		SNI:        "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("ProbeNetwork failed: %v", err)
	}

	if len(res.Certificates) != 1 {
		t.Fatalf("Expected 1 captured peer certificate, got %d", len(res.Certificates))
	}
	if res.Certificates[0].Subject.CommonName != "127.0.0.1" {
		t.Errorf("Expected CN 127.0.0.1, got %s", res.Certificates[0].Subject.CommonName)
	}
	if res.Details.TLSVersion == "" {
		t.Errorf("Expected TLS version to be populated, got empty")
	}
	if res.Details.CipherSuite == "" {
		t.Errorf("Expected cipher suite to be populated, got empty")
	}
}

func TestProbe_File(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	tmpDir := t.TempDir()
	bundleFile := filepath.Join(tmpDir, "chain.pem")
	fullPEM := append(suite.LeafPEM, suite.IntermediatePEM...)
	if err := os.WriteFile(bundleFile, fullPEM, 0644); err != nil {
		t.Fatalf("Failed to write bundle file: %v", err)
	}

	res, err := probe.Probe(context.Background(), probe.ProbeOptions{
		FilePath: bundleFile,
	})
	if err != nil {
		t.Fatalf("ProbeFile failed: %v", err)
	}

	if len(res.Certificates) != 2 {
		t.Fatalf("Expected 2 certs loaded from file, got %d", len(res.Certificates))
	}
	if !res.Details.IsFileProbe {
		t.Errorf("Expected IsFileProbe = true, got false")
	}
}

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		input       string
		defaultPort int
		expected    string
	}{
		{"example.com", 443, "example.com:443"},
		{"example.com:8443", 443, "example.com:8443"},
		{"https://api.example.com/v1", 443, "api.example.com:443"},
		{"http://localhost:8080/", 443, "localhost:8080"},
		{"127.0.0.1", 443, "127.0.0.1:443"},
	}

	for _, tt := range tests {
		got := probe.NormalizeHostPort(tt.input, tt.defaultPort)
		if got != tt.expected {
			t.Errorf("NormalizeHostPort(%q, %d) = %q, want %q", tt.input, tt.defaultPort, got, tt.expected)
		}
	}
}
