package aia

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// FetcherConfig configures the AIA certificate fetcher.
type FetcherConfig struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	MaxHops    int
}

// RepairResult represents the outcome of chain repair and AIA chasing.
type RepairResult struct {
	OriginalChain       []*x509.Certificate `json:"-"`
	RepairedChain       []*x509.Certificate `json:"-"`
	FetchedCerts        []*x509.Certificate `json:"-"`
	FetchedFromURLs     []string            `json:"fetched_from_urls"`
	StrippedRedundantRoot bool              `json:"stripped_redundant_root"`
	Reordered           bool                `json:"reordered"`
	PEMBundle           []byte              `json:"-"`
	VerifiedAgainstRoots bool               `json:"verified_against_roots"`
}

// DefaultFetcherConfig returns default settings with 10s timeout and 5 hops max.
func DefaultFetcherConfig() FetcherConfig {
	return FetcherConfig{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Timeout: 10 * time.Second,
		MaxHops: 5,
	}
}

// RepairChain takes an initial set of certificates, reorders them, chases missing intermediates
// via AIA URLs, strips redundant Root CAs, and constructs a pristine PEM bundle.
func RepairChain(certs []*x509.Certificate, roots *x509.CertPool, cfg FetcherConfig) (*RepairResult, error) {
	if len(certs) == 0 {
		return nil, errors.New("cannot repair empty certificate chain")
	}

	if cfg.HTTPClient == nil {
		cfg = DefaultFetcherConfig()
	}
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 5
	}

	res := &RepairResult{
		OriginalChain: certs,
	}

	// 1. Reorder initial chain if needed
	ordered, reordered := ReorderChain(certs)
	res.Reordered = reordered
	chain := ordered

	// 2. Chase AIA URLs starting from the terminal certificate in the chain
	hops := 0
	visitedURLs := make(map[string]bool)

	for hops < cfg.MaxHops {
		terminalCert := chain[len(chain)-1]

		// Check if terminal cert is already self-signed (Root CA)
		if IsSelfSigned(terminalCert) {
			break
		}

		// Check if terminal cert already verifies against roots
		if roots != nil {
			vOpts := x509.VerifyOptions{
				Roots: roots,
			}
			if _, err := terminalCert.Verify(vOpts); err == nil {
				// Terminal cert is signed directly by a trusted root
				break
			}
		}

		// Terminal cert needs an issuer. Check AIA URLs
		aiaURLs := terminalCert.IssuingCertificateURL
		if len(aiaURLs) == 0 {
			break
		}

		var fetchedParent *x509.Certificate
		var successfulURL string

		for _, url := range aiaURLs {
			if visitedURLs[url] {
				continue
			}
			visitedURLs[url] = true

			candidates, err := FetchCertificatesFromURL(url, cfg.HTTPClient)
			if err != nil {
				continue
			}

			// Find candidate that signed terminalCert
			for _, candidate := range candidates {
				if err := terminalCert.CheckSignatureFrom(candidate); err == nil {
					fetchedParent = candidate
					successfulURL = url
					break
				}
			}

			if fetchedParent != nil {
				break
			}
		}

		if fetchedParent == nil {
			// Could not fetch or verify a valid parent intermediate
			break
		}

		// Append fetched parent to chain
		chain = append(chain, fetchedParent)
		res.FetchedCerts = append(res.FetchedCerts, fetchedParent)
		res.FetchedFromURLs = append(res.FetchedFromURLs, successfulURL)
		hops++
	}

	// 3. Strip redundant Root CA at the end of the server chain if present
	finalChain := make([]*x509.Certificate, 0, len(chain))
	for i, cert := range chain {
		if i == len(chain)-1 && len(chain) > 1 && IsSelfSigned(cert) && cert.IsCA {
			res.StrippedRedundantRoot = true
			continue // Do not include root CA in server chain bundle
		}
		finalChain = append(finalChain, cert)
	}

	res.RepairedChain = finalChain

	// 4. Check if final chain verifies against roots
	if roots != nil && len(finalChain) > 0 {
		leaf := finalChain[0]
		interPool := x509.NewCertPool()
		for _, c := range finalChain[1:] {
			interPool.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: interPool}); err == nil {
			res.VerifiedAgainstRoots = true
		}
	}

	// 5. Generate PEM bundle
	res.PEMBundle = EncodeCertificatesToPEM(finalChain)

	return res, nil
}

// FetchCertificatesFromURL downloads certificates in DER or PEM format from an AIA URL.
func FetchCertificatesFromURL(url string, client *http.Client) ([]*x509.Certificate, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for AIA URL %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "cert-chain-doctor/1.0")
	req.Header.Set("Accept", "application/pkix-cert, application/x-x509-ca-cert, application/x-pem-file, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AIA URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AIA URL %s returned HTTP status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read AIA response from %s: %w", url, err)
	}

	return ParseCertificatesFromBytes(body)
}

// ParseCertificatesFromBytes parses raw bytes that could be either PEM or DER encoded certificates.
func ParseCertificatesFromBytes(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// First attempt PEM decoding
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, c)
			}
		}
	}

	if len(certs) > 0 {
		return certs, nil
	}

	// If no PEM blocks found, attempt DER decoding
	// Single DER certificate
	single, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{single}, nil
	}

	// Multiple DER certificates concatenated
	multi, err := x509.ParseCertificates(data)
	if err == nil && len(multi) > 0 {
		return multi, nil
	}

	// Attempt PKCS#7 (.p7b/.p7c) SignedData certificate bundle decoding
	if p7Certs, p7Err := parsePKCS7Certificates(data); p7Err == nil && len(p7Certs) > 0 {
		return p7Certs, nil
	}

	return nil, fmt.Errorf("unable to parse certificate data as PEM, DER, or PKCS#7")
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

func parsePKCS7Certificates(data []byte) ([]*x509.Certificate, error) {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, err
	}
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not pkcs7 signedData")
	}

	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}

	if len(sd.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates found in pkcs7 signedData")
	}

	return x509.ParseCertificates(sd.Certificates.Bytes)
}

// EncodeCertificatesToPEM converts a slice of certificates to a concatenated PEM byte slice.
func EncodeCertificatesToPEM(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
	return buf.Bytes()
}

// WriteBundleToFile writes the PEM certificate bundle to a file on disk.
func WriteBundleToFile(path string, pemData []byte) error {
	return os.WriteFile(path, pemData, 0644)
}

// ReorderChain attempts to order certificates from Leaf -> Intermediate(s).
func ReorderChain(certs []*x509.Certificate) ([]*x509.Certificate, bool) {
	if len(certs) <= 1 {
		return certs, false
	}

	// 1. Identify leaf certificate (not an issuer of any cert in the set, and preferably !IsCA)
	leafIdx := -1
	for i, candidate := range certs {
		isIssuerOfAny := false
		for j, other := range certs {
			if i != j && other.CheckSignatureFrom(candidate) == nil {
				isIssuerOfAny = true
				break
			}
		}
		if !isIssuerOfAny {
			leafIdx = i
			break
		}
	}

	// Fallback: first non-CA cert
	if leafIdx == -1 {
		for i, c := range certs {
			if !c.IsCA {
				leafIdx = i
				break
			}
		}
	}
	if leafIdx == -1 {
		leafIdx = 0
	}

	// 2. Build ordered chain starting from leaf
	ordered := make([]*x509.Certificate, 0, len(certs))
	used := make(map[int]bool)

	current := certs[leafIdx]
	ordered = append(ordered, current)
	used[leafIdx] = true

	for len(ordered) < len(certs) {
		foundParent := false
		for i, candidate := range certs {
			if !used[i] && current.CheckSignatureFrom(candidate) == nil {
				ordered = append(ordered, candidate)
				used[i] = true
				current = candidate
				foundParent = true
				break
			}
		}
		if !foundParent {
			// Remaining unlinked certs, append them
			for i, c := range certs {
				if !used[i] {
					ordered = append(ordered, c)
					used[i] = true
				}
			}
			break
		}
	}

	// Check if order changed
	changed := false
	for i := range certs {
		if !bytes.Equal(certs[i].Raw, ordered[i].Raw) {
			changed = true
			break
		}
	}

	return ordered, changed
}

// IsSelfSigned returns true if the certificate was signed by itself.
func IsSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return cert.CheckSignatureFrom(cert) == nil
	}
	return false
}
