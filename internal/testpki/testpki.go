package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

// PKISuite holds the in-memory generated certificates and keys.
type PKISuite struct {
	RootCert     *x509.Certificate
	RootKey      crypto.Signer
	RootPEM      []byte
	RootCertPool *x509.CertPool

	IntermediateCert *x509.Certificate
	IntermediateKey  crypto.Signer
	IntermediatePEM  []byte
	IntermediateDER  []byte

	LeafCert *x509.Certificate
	LeafKey  crypto.Signer
	LeafPEM  []byte

	// AIAServer serves the intermediate cert
	AIAServer *httptest.Server
	AIAURL    string
}

// ComputeSKI computes the RFC 5280 160-bit SHA-1 Subject Key Identifier.
func ComputeSKI(pub crypto.PublicKey) []byte {
	var pubBytes []byte
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		pubBytes = elliptic.Marshal(k.Curve, k.X, k.Y)
	case *rsa.PublicKey:
		b, err := asn1.Marshal(*k)
		if err == nil {
			pubBytes = b
		}
	}
	h := sha1.Sum(pubBytes)
	return h[:]
}

// GenerateSuite creates an in-memory Root -> Intermediate -> Leaf hierarchy with AIA support.
func GenerateSuite(hostname string) (*PKISuite, error) {
	suite := &PKISuite{}

	// 1. Root CA Key & Cert
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	suite.RootKey = rootKey
	rootSKI := ComputeSKI(&rootKey.PublicKey)

	rootSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Cert Chain Doctor Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          rootSKI,
		AuthorityKeyId:        rootSKI,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	suite.RootCert, _ = x509.ParseCertificate(rootDER)
	suite.RootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	suite.RootCertPool = x509.NewCertPool()
	suite.RootCertPool.AddCert(suite.RootCert)

	// 2. Intermediate CA Key & Cert
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	suite.IntermediateKey = interKey
	interSKI := ComputeSKI(&interKey.PublicKey)

	interSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	interTemplate := &x509.Certificate{
		SerialNumber: interSerial,
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Cert Chain Doctor Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          interSKI,
		AuthorityKeyId:        rootSKI,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, suite.RootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	suite.IntermediateCert, _ = x509.ParseCertificate(interDER)
	suite.IntermediateDER = interDER
	suite.IntermediatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})

	// 3. AIA HTTP Server for serving Intermediate CA
	var aiaURL string
	aiaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/intermediate.cer" || r.URL.Path == "/intermediate.der" {
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Write(suite.IntermediateDER)
			return
		}
		if r.URL.Path == "/intermediate.pem" || r.URL.Path == "/intermediate.crt" {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(suite.IntermediatePEM)
			return
		}
		http.NotFound(w, r)
	}))
	suite.AIAServer = aiaServer
	aiaURL = aiaServer.URL + "/intermediate.cer"
	suite.AIAURL = aiaURL

	// 4. Leaf Cert Key & Cert
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	suite.LeafKey = leafKey
	leafSKI := ComputeSKI(&leafKey.PublicKey)

	var dnsNames []string
	var ipAddresses []net.IP
	if ip := net.ParseIP(hostname); ip != nil {
		ipAddresses = append(ipAddresses, ip)
	} else {
		dnsNames = append(dnsNames, hostname, "sub."+hostname)
	}

	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Cert Chain Doctor Test App"},
		},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          leafSKI,
		AuthorityKeyId:        interSKI,
		IssuingCertificateURL: []string{aiaURL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, suite.IntermediateCert, &leafKey.PublicKey, interKey)
	if err != nil {
		return nil, err
	}
	suite.LeafCert, _ = x509.ParseCertificate(leafDER)
	suite.LeafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	return suite, nil
}

// Close tears down any background test servers.
func (s *PKISuite) Close() {
	if s.AIAServer != nil {
		s.AIAServer.Close()
	}
}

// LeafOnly returns a slice with only the leaf certificate.
func (s *PKISuite) LeafOnly() []*x509.Certificate {
	return []*x509.Certificate{s.LeafCert}
}

// LeafCertAndIntermediate returns leaf followed by intermediate.
func (s *PKISuite) LeafCertAndIntermediate() []*x509.Certificate {
	return []*x509.Certificate{s.LeafCert, s.IntermediateCert}
}

// FullChainWithRoot returns leaf, intermediate, and root certificate.
func (s *PKISuite) FullChainWithRoot() []*x509.Certificate {
	return []*x509.Certificate{s.LeafCert, s.IntermediateCert, s.RootCert}
}

// ReversedChain returns intermediate followed by leaf certificate.
func (s *PKISuite) ReversedChain() []*x509.Certificate {
	return []*x509.Certificate{s.IntermediateCert, s.LeafCert}
}

// TLSConfig creates a tls.Certificate using the provided chain certificates and leaf private key.
func (s *PKISuite) TLSConfig(chain ...*x509.Certificate) *tls.Config {
	var certBytes [][]byte
	for _, c := range chain {
		certBytes = append(certBytes, c.Raw)
	}

	tlsCert := tls.Certificate{
		Certificate: certBytes,
		PrivateKey:  s.LeafKey,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
}

// CreateWeakRSACert generates a certificate with an insecure 1024-bit RSA key.
func CreateWeakRSACert(cn string) (*x509.Certificate, []byte, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes, key, err
}

// CreateExpiredCert generates an expired certificate.
func CreateExpiredCert(cn string) (*x509.Certificate, []byte, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-1 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes, key, err
}

// CreateExpiringSoonCert generates a certificate expiring in specified days.
func CreateExpiringSoonCert(cn string, daysLeft int) (*x509.Certificate, []byte, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:     time.Now().Add(time.Duration(daysLeft) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes, key, err
}
