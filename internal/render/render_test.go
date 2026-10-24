package render_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/probe"
	"github.com/smford/cert-chain-doctor/internal/render"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestRenderTextAndJSON(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	analysis := analyzer.Analyze(
		suite.LeafCertAndIntermediate(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	data := render.OutputData{
		Target: "api.example.com:443",
		Handshake: &probe.HandshakeDetails{
			ServerName:        "api.example.com",
			TLSVersion:        "TLS 1.3",
			CipherSuite:       "TLS_AES_128_GCM_SHA256",
			NegotiatedALPN:    "h2",
			HandshakeDuration: 15 * time.Millisecond,
		},
		Analysis: analysis,
	}

	// Test Text output
	var textBuf bytes.Buffer
	render.RenderText(&textBuf, data)
	textOutput := textBuf.String()

	if !strings.Contains(textOutput, "CERT CHAIN DOCTOR") {
		t.Errorf("Expected banner in text output")
	}
	if !strings.Contains(textOutput, "api.example.com") {
		t.Errorf("Expected hostname in text output")
	}
	if !strings.Contains(textOutput, "TLS 1.3") {
		t.Errorf("Expected TLS version in text output")
	}
	if !strings.Contains(textOutput, "HEALTHY") {
		t.Errorf("Expected HEALTHY verdict in text output")
	}

	// Test JSON output
	var jsonBuf bytes.Buffer
	err = render.RenderJSON(&jsonBuf, data)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("RenderJSON produced invalid JSON: %v", err)
	}
	if parsed["target"] != "api.example.com:443" {
		t.Errorf("JSON output missing target: %v", parsed["target"])
	}
}

func TestRenderColors(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	analysis := analyzer.Analyze(
		suite.LeafCertAndIntermediate(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	data := render.OutputData{
		Target: "api.example.com:443",
		Analysis: analysis,
	}

	var buf bytes.Buffer
	render.RenderText(&buf, data, render.RenderOptions{ColorMode: render.ColorAlways})
	out := buf.String()

	if !strings.Contains(out, "\033[") {
		t.Errorf("Expected ANSI escape codes when ColorAlways is set")
	}
}

func TestGenerateK8sSecret(t *testing.T) {
	secret := render.GenerateK8sSecret("my-tls-secret", "prod", []byte("CERTIFICATE DATA"))
	if !strings.Contains(secret, "name: my-tls-secret") {
		t.Errorf("Secret missing expected name")
	}
	if !strings.Contains(secret, "namespace: prod") {
		t.Errorf("Secret missing expected namespace")
	}
	if !strings.Contains(secret, "type: kubernetes.io/tls") {
		t.Errorf("Secret missing type kubernetes.io/tls")
	}
}
