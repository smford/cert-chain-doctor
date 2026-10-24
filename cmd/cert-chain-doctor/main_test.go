package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestCLI_EndToEnd_BrokenServerRepair(t *testing.T) {
	suite, err := testpki.GenerateSuite("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Create TLS server presenting ONLY the Leaf certificate (broken intermediate chain)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	ts.TLS = suite.TLSConfig(suite.LeafCert)
	ts.StartTLS()
	defer ts.Close()

	tmpDir := t.TempDir()
	caFilePath := filepath.Join(tmpDir, "root-ca.pem")
	if err := os.WriteFile(caFilePath, suite.RootPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	fixedBundlePath := filepath.Join(tmpDir, "repaired-bundle.pem")

	// 1. Run without --fix-bundle: should fail with exit code 1 because intermediate is missing
	exitCode := run([]string{
		ts.Listener.Addr().String(),
		"--sni", "127.0.0.1",
		"--ca-file", caFilePath,
		"--format", "text",
	})
	if exitCode != 1 {
		t.Errorf("Expected exit code 1 for broken server chain, got %d", exitCode)
	}

	// 2. Run with --fix-bundle: should fetch intermediate via AIA, repair bundle, and return exit code 0
	exitCode = run([]string{
		ts.Listener.Addr().String(),
		"--sni", "127.0.0.1",
		"--ca-file", caFilePath,
		"--fix-bundle", fixedBundlePath,
		"--format", "json",
	})
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 when --fix-bundle repairs chain, got %d", exitCode)
	}

	// 3. Inspect the written repaired bundle file
	repairedData, err := os.ReadFile(fixedBundlePath)
	if err != nil {
		t.Fatalf("Failed to read repaired bundle: %v", err)
	}

	repairedCerts, err := aia.ParseCertificatesFromBytes(repairedData)
	if err != nil {
		t.Fatalf("Failed to parse repaired bundle: %v", err)
	}
	if len(repairedCerts) != 2 {
		t.Fatalf("Expected 2 certificates in repaired bundle (Leaf + Intermediate), got %d", len(repairedCerts))
	}

	// 4. Run cert-chain-doctor on the repaired bundle file directly: should succeed with exit code 0
	exitCode = run([]string{
		"--file", fixedBundlePath,
		"--ca-file", caFilePath,
		"--format", "text",
	})
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 when analyzing repaired bundle file, got %d", exitCode)
	}
}

func TestCLI_ExpiringSoonWarningExitCode(t *testing.T) {
	cert, pemData, _, err := testpki.CreateExpiringSoonCert("expiring.example.com", 5)
	if err != nil {
		t.Fatalf("Failed to generate expiring cert: %v", err)
	}
	_ = cert

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "expiring.pem")
	if err := os.WriteFile(certFile, pemData, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	// Warning threshold 14 days, cert expires in 5 days -> exit code 2
	// But self-signed might fail root verification if not added as root, let's pass it as ca-file too
	exitCode := run([]string{
		"--file", certFile,
		"--ca-file", certFile,
		"--expiry-warn", "14",
	})

	if exitCode != 2 {
		t.Errorf("Expected exit code 2 for expiring cert, got %d", exitCode)
	}
}

func TestCLI_InvalidArguments(t *testing.T) {
	exitCode := run([]string{})
	if exitCode != 1 {
		t.Errorf("Expected exit code 1 when no arguments provided, got %d", exitCode)
	}

	exitCode = run([]string{"--version"})
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for --version, got %d", exitCode)
	}

	exitCode = run([]string{"version"})
	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for 'version', got %d", exitCode)
	}
}

func TestCLI_ServeEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(formatVersion()))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("Failed to GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 on /healthz, got %d", resp.StatusCode)
	}

	respV, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("Failed to GET /version: %v", err)
	}
	defer respV.Body.Close()
	if respV.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 on /version, got %d", respV.StatusCode)
	}
}

func TestCLI_K8sSecretGeneration(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate suite: %v", err)
	}
	defer suite.Close()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "server.pem")
	_ = os.WriteFile(certFile, suite.LeafPEM, 0644)
	caFile := filepath.Join(tmpDir, "ca.pem")
	_ = os.WriteFile(caFile, suite.RootPEM, 0644)

	exitCode := run([]string{
		"--file", certFile,
		"--ca-file", caFile,
		"--k8s-secret", "my-tls-secret",
		"--k8s-namespace", "production",
	})

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for k8s secret generation, got %d", exitCode)
	}
}

func TestCLI_BatchAudit(t *testing.T) {
	suite, err := testpki.GenerateSuite("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to generate suite: %v", err)
	}
	defer suite.Close()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	ts.TLS = suite.TLSConfig(suite.LeafCert, suite.IntermediateCert)
	ts.StartTLS()
	defer ts.Close()

	tmpDir := t.TempDir()
	hostsPath := filepath.Join(tmpDir, "hosts.txt")
	content := "# comment line\n" + ts.Listener.Addr().String() + "\n"
	_ = os.WriteFile(hostsPath, []byte(content), 0644)

	caFile := filepath.Join(tmpDir, "ca.pem")
	_ = os.WriteFile(caFile, suite.RootPEM, 0644)

	exitCode := run([]string{
		"--hosts-file", hostsPath,
		"--ca-file", caFile,
		"--format", "text",
	})

	if exitCode != 0 {
		t.Errorf("Expected exit code 0 for batch audit, got %d", exitCode)
	}
}
