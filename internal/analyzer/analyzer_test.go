package analyzer_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestAnalyzer_ValidChain(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	res := analyzer.Analyze(
		suite.LeafCertAndIntermediate(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	if !res.IsValid {
		t.Errorf("Expected valid chain, got verification error: %v", res.VerificationError)
	}
	if res.HasMissingInter {
		t.Errorf("Expected HasMissingInter = false, got true")
	}
	if res.HasRedundantRoot {
		t.Errorf("Expected HasRedundantRoot = false, got true")
	}
	if len(res.Issues) != 0 {
		t.Errorf("Expected 0 issues for healthy chain, got %d: %+v", len(res.Issues), res.Issues)
	}
}

func TestAnalyzer_MissingIntermediateWithAIA(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Only provide Leaf, omitting Intermediate
	res := analyzer.Analyze(
		suite.LeafOnly(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	if res.IsValid {
		t.Errorf("Expected invalid chain due to missing intermediate, got valid")
	}
	if !res.HasMissingInter {
		t.Errorf("Expected HasMissingInter = true, got false")
	}
	if !res.CanFixViaAIA {
		t.Errorf("Expected CanFixViaAIA = true, got false")
	}
	if len(res.CandidateAIAURLs) == 0 {
		t.Errorf("Expected candidate AIA URLs, got none")
	}

	foundAIAIssue := false
	for _, iss := range res.Issues {
		if iss.Code == "MISSING_INTERMEDIATE_AIA_AVAILABLE" {
			foundAIAIssue = true
			break
		}
	}
	if !foundAIAIssue {
		t.Errorf("Expected MISSING_INTERMEDIATE_AIA_AVAILABLE issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_MisorderedChain(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Intermediate first, Leaf second
	res := analyzer.Analyze(
		suite.ReversedChain(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	if !res.IsMisordered {
		t.Errorf("Expected IsMisordered = true, got false")
	}

	foundOrderIssue := false
	for _, iss := range res.Issues {
		if iss.Code == "MISORDERED_CHAIN_LEAF_NOT_FIRST" || iss.Code == "MISORDERED_CHAIN_REVERSED" {
			foundOrderIssue = true
			break
		}
	}
	if !foundOrderIssue {
		t.Errorf("Expected misordered chain issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_RedundantRoot(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Leaf -> Intermediate -> Root CA
	res := analyzer.Analyze(
		suite.FullChainWithRoot(),
		analyzer.AnalyzeOptions{
			Hostname: "api.example.com",
			RootPool: suite.RootCertPool,
		},
	)

	if !res.HasRedundantRoot {
		t.Errorf("Expected HasRedundantRoot = true, got false")
	}

	foundRedundantIssue := false
	for _, iss := range res.Issues {
		if iss.Code == "REDUNDANT_ROOT_IN_HANDSHAKE" {
			foundRedundantIssue = true
			if iss.Severity != analyzer.SeverityWarning {
				t.Errorf("Expected severity WARNING for redundant root, got %s", iss.Severity)
			}
			break
		}
	}
	if !foundRedundantIssue {
		t.Errorf("Expected REDUNDANT_ROOT_IN_HANDSHAKE issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_HostnameMismatch(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	res := analyzer.Analyze(
		suite.LeafCertAndIntermediate(),
		analyzer.AnalyzeOptions{
			Hostname: "wrong.attacker.com",
			RootPool: suite.RootCertPool,
		},
	)

	if res.IsValid {
		t.Errorf("Expected verification failure due to hostname mismatch, got valid")
	}

	foundHostIssue := false
	for _, iss := range res.Issues {
		if iss.Code == "HOSTNAME_MISMATCH" {
			foundHostIssue = true
			break
		}
	}
	if !foundHostIssue {
		t.Errorf("Expected HOSTNAME_MISMATCH issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_ExpiredCert(t *testing.T) {
	cert, _, _, err := testpki.CreateExpiredCert("expired.example.com")
	if err != nil {
		t.Fatalf("Failed to create expired cert: %v", err)
	}

	res := analyzer.Analyze(
		[]*x509.Certificate{cert},
		analyzer.AnalyzeOptions{
			Hostname: "expired.example.com",
		},
	)

	foundExpired := false
	for _, iss := range res.Issues {
		if iss.Code == "CERT_EXPIRED" {
			foundExpired = true
			break
		}
	}
	if !foundExpired {
		t.Errorf("Expected CERT_EXPIRED issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_ExpiringSoon(t *testing.T) {
	cert, _, _, err := testpki.CreateExpiringSoonCert("expiring.example.com", 7)
	if err != nil {
		t.Fatalf("Failed to create expiring cert: %v", err)
	}

	res := analyzer.Analyze(
		[]*x509.Certificate{cert},
		analyzer.AnalyzeOptions{
			Hostname:       "expiring.example.com",
			WarnExpiryDays: 14,
		},
	)

	foundExpiringSoon := false
	for _, iss := range res.Issues {
		if iss.Code == "CERT_EXPIRING_SOON" {
			foundExpiringSoon = true
			if iss.Severity != analyzer.SeverityWarning {
				t.Errorf("Expected WARNING severity, got %v", iss.Severity)
			}
			break
		}
	}
	if !foundExpiringSoon {
		t.Errorf("Expected CERT_EXPIRING_SOON issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_WeakRSAKey(t *testing.T) {
	cert, _, _, err := testpki.CreateWeakRSACert("weak-rsa.example.com")
	if err != nil {
		t.Fatalf("Failed to create weak RSA cert: %v", err)
	}

	res := analyzer.Analyze(
		[]*x509.Certificate{cert},
		analyzer.AnalyzeOptions{
			Hostname: "weak-rsa.example.com",
		},
	)

	foundWeakRSA := false
	for _, iss := range res.Issues {
		if iss.Code == "INSECURE_RSA_KEY_SIZE" {
			foundWeakRSA = true
			break
		}
	}
	if !foundWeakRSA {
		t.Errorf("Expected INSECURE_RSA_KEY_SIZE issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_EmptyChain(t *testing.T) {
	res := analyzer.Analyze(
		[]*x509.Certificate{},
		analyzer.AnalyzeOptions{},
	)
	if res.IsValid {
		t.Errorf("Expected empty chain to be invalid")
	}
	if len(res.Issues) == 0 || res.Issues[0].Code != "NO_CERTIFICATES" {
		t.Errorf("Expected NO_CERTIFICATES issue, got: %+v", res.Issues)
	}
}

func TestAnalyzer_CustomTime(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Analyze at a time 20 years in the future -> all certs should be expired
	futureTime := time.Now().Add(20 * 365 * 24 * time.Hour)
	res := analyzer.Analyze(
		suite.LeafCertAndIntermediate(),
		analyzer.AnalyzeOptions{
			Hostname:    "api.example.com",
			RootPool:    suite.RootCertPool,
			CurrentTime: futureTime,
		},
	)

	if res.IsValid {
		t.Errorf("Expected future time to fail verification")
	}
	foundExpired := false
	for _, iss := range res.Issues {
		if iss.Code == "CERT_EXPIRED" {
			foundExpired = true
			break
		}
	}
	if !foundExpired {
		t.Errorf("Expected CERT_EXPIRED issue for future check, got: %+v", res.Issues)
	}
}
