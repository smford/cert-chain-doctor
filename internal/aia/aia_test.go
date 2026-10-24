package aia_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/testpki"
)

func TestRepairChain_MissingIntermediate_DER(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Initially we only have Leaf cert; Intermediate is missing from the server
	brokenChain := suite.LeafOnly()

	cfg := aia.DefaultFetcherConfig()
	res, err := aia.RepairChain(brokenChain, suite.RootCertPool, cfg)
	if err != nil {
		t.Fatalf("RepairChain returned unexpected error: %v", err)
	}

	if len(res.RepairedChain) != 2 {
		t.Fatalf("Expected repaired chain length 2, got %d", len(res.RepairedChain))
	}

	// Verify cryptographic signature: Leaf signed by Intermediate
	leaf := res.RepairedChain[0]
	inter := res.RepairedChain[1]
	if err := leaf.CheckSignatureFrom(inter); err != nil {
		t.Errorf("Leaf is not cryptographically signed by fetched Intermediate: %v", err)
	}

	if len(res.FetchedCerts) != 1 {
		t.Errorf("Expected 1 fetched intermediate, got %d", len(res.FetchedCerts))
	}
	if len(res.FetchedFromURLs) != 1 || res.FetchedFromURLs[0] != suite.AIAURL {
		t.Errorf("Expected fetched URL %s, got %+v", suite.AIAURL, res.FetchedFromURLs)
	}
	if !res.VerifiedAgainstRoots {
		t.Errorf("Expected RepairedChain to verify against RootCertPool, but it did not")
	}

	// Verify PEM bundle parses back to 2 certs
	parsed, err := aia.ParseCertificatesFromBytes(res.PEMBundle)
	if err != nil {
		t.Fatalf("Failed to parse output PEM bundle: %v", err)
	}
	if len(parsed) != 2 {
		t.Errorf("Expected 2 certificates in parsed PEM bundle, got %d", len(parsed))
	}
}

func TestRepairChain_MissingIntermediate_PEM(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Override Leaf's IssuingCertificateURL to point to PEM endpoint
	suite.LeafCert.IssuingCertificateURL = []string{suite.AIAServer.URL + "/intermediate.pem"}

	brokenChain := suite.LeafOnly()
	cfg := aia.DefaultFetcherConfig()
	res, err := aia.RepairChain(brokenChain, suite.RootCertPool, cfg)
	if err != nil {
		t.Fatalf("RepairChain failed: %v", err)
	}

	if len(res.RepairedChain) != 2 {
		t.Fatalf("Expected repaired chain length 2, got %d", len(res.RepairedChain))
	}
	if !res.VerifiedAgainstRoots {
		t.Errorf("Expected chain to verify against roots")
	}
}

func TestRepairChain_RedundantRootStripping(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Handshake includes Leaf -> Intermediate -> Root CA
	chainWithRoot := suite.FullChainWithRoot()

	cfg := aia.DefaultFetcherConfig()
	res, err := aia.RepairChain(chainWithRoot, suite.RootCertPool, cfg)
	if err != nil {
		t.Fatalf("RepairChain failed: %v", err)
	}

	if !res.StrippedRedundantRoot {
		t.Errorf("Expected StrippedRedundantRoot = true, got false")
	}
	if len(res.RepairedChain) != 2 {
		t.Fatalf("Expected repaired chain length 2 (Leaf + Inter), got %d", len(res.RepairedChain))
	}
	if aia.IsSelfSigned(res.RepairedChain[len(res.RepairedChain)-1]) {
		t.Errorf("Root CA was not stripped from repaired chain")
	}
}

func TestRepairChain_ReorderMisordered(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Chain is reversed: Intermediate first, Leaf second
	reversedChain := suite.ReversedChain()

	cfg := aia.DefaultFetcherConfig()
	res, err := aia.RepairChain(reversedChain, suite.RootCertPool, cfg)
	if err != nil {
		t.Fatalf("RepairChain failed: %v", err)
	}

	if !res.Reordered {
		t.Errorf("Expected Reordered = true, got false")
	}
	if len(res.RepairedChain) != 2 {
		t.Fatalf("Expected repaired chain length 2, got %d", len(res.RepairedChain))
	}
	if res.RepairedChain[0].IsCA {
		t.Errorf("Expected Leaf cert at index 0, but found CA cert")
	}
	if !res.RepairedChain[1].IsCA {
		t.Errorf("Expected Intermediate CA at index 1, but found non-CA")
	}
}

func TestRepairChain_WriteToFile(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	res, err := aia.RepairChain(suite.LeafOnly(), suite.RootCertPool, aia.DefaultFetcherConfig())
	if err != nil {
		t.Fatalf("RepairChain failed: %v", err)
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "fixed-bundle.pem")

	err = aia.WriteBundleToFile(outPath, res.PEMBundle)
	if err != nil {
		t.Fatalf("WriteBundleToFile failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read back written bundle: %v", err)
	}

	certs, err := aia.ParseCertificatesFromBytes(data)
	if err != nil {
		t.Fatalf("Failed to parse written bundle: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("Expected 2 certs in written bundle, got %d", len(certs))
	}
}

func TestRepairChain_UnreachableAIA(t *testing.T) {
	suite, err := testpki.GenerateSuite("api.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test PKI suite: %v", err)
	}
	defer suite.Close()

	// Bad URL that returns 404
	suite.LeafCert.IssuingCertificateURL = []string{suite.AIAServer.URL + "/non-existent.cer"}

	cfg := aia.DefaultFetcherConfig()
	res, err := aia.RepairChain(suite.LeafOnly(), suite.RootCertPool, cfg)
	if err != nil {
		t.Fatalf("RepairChain should not crash on unreachable AIA URL, got err: %v", err)
	}
	// Chain should remain 1 cert since intermediate couldn't be fetched
	if len(res.RepairedChain) != 1 {
		t.Errorf("Expected 1 cert in chain, got %d", len(res.RepairedChain))
	}
}

func TestRepairChain_Empty(t *testing.T) {
	_, err := aia.RepairChain([]*x509.Certificate{}, nil, aia.DefaultFetcherConfig())
	if err == nil {
		t.Errorf("Expected error repairing empty chain, got nil")
	}
}
