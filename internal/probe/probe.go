package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/smford/cert-chain-doctor/internal/aia"
)

// ProbeOptions configures the TLS network probe or local file reader.
type ProbeOptions struct {
	TargetHost  string        // host or host:port
	SNI         string        // SNI override
	ALPN        []string      // ALPN protocol list (e.g. ["h2", "http/1.1"])
	StartTLS    string        // Protocol for STARTTLS: "smtp", "imap", "pop3", "postgres", "mysql"
	Timeout     time.Duration // Dial & handshake timeout
	FilePath    string        // Optional local PEM bundle file path
}

// HandshakeDetails captures TLS connection metadata.
type HandshakeDetails struct {
	RemoteAddr        string        `json:"remote_addr,omitempty"`
	ServerName        string        `json:"server_name,omitempty"`
	TLSVersion        string        `json:"tls_version,omitempty"`
	CipherSuite       string        `json:"cipher_suite,omitempty"`
	NegotiatedALPN    string        `json:"negotiated_alpn,omitempty"`
	OCSPStapled       bool          `json:"ocsp_stapled"`
	HandshakeDuration time.Duration `json:"handshake_duration_ms,omitempty"`
	IsFileProbe       bool          `json:"is_file_probe"`
}

// ProbeResult holds the retrieved certificates and connection metadata.
type ProbeResult struct {
	Certificates []*x509.Certificate `json:"-"`
	Details      HandshakeDetails    `json:"handshake_details"`
}

// DefaultProbeOptions returns default dial settings.
func DefaultProbeOptions() ProbeOptions {
	return ProbeOptions{
		Timeout: 10 * time.Second,
	}
}

// Probe runs the certificate probe against either a network host or a local PEM file.
func Probe(ctx context.Context, opts ProbeOptions) (*ProbeResult, error) {
	if opts.FilePath != "" {
		return ProbeFile(opts.FilePath)
	}
	return ProbeNetwork(ctx, opts)
}

// ProbeFile reads certificates from a local PEM file.
func ProbeFile(path string) (*ProbeResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	certs, err := aia.ParseCertificatesFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificates from %s: %w", path, err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in file %s", path)
	}

	return &ProbeResult{
		Certificates: certs,
		Details: HandshakeDetails{
			IsFileProbe: true,
		},
	}, nil
}

// ProbeNetwork dials the remote host, executes TLS handshake capturing raw peer certificates.
func ProbeNetwork(ctx context.Context, opts ProbeOptions) (*ProbeResult, error) {
	if opts.TargetHost == "" {
		return nil, errors.New("target host is required")
	}

	addr := NormalizeHostPort(opts.TargetHost, 443)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port %s: %w", addr, err)
	}

	sni := opts.SNI
	if sni == "" {
		sni = host
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	start := time.Now()

	var capturedCerts []*x509.Certificate
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         opts.ALPN,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err == nil {
					capturedCerts = append(capturedCerts, cert)
				}
			}
			return nil
		},
	}

	var conn net.Conn
	if opts.StartTLS != "" {
		rawConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
		}
		defer rawConn.Close()

		if err := performStartTLS(rawConn, opts.StartTLS, host); err != nil {
			return nil, fmt.Errorf("STARTTLS handshake failed for %s: %w", opts.StartTLS, err)
		}

		tlsConn := tls.Client(rawConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// Even if handshake fails, check if we captured certificates
			if len(capturedCerts) == 0 {
				return nil, fmt.Errorf("TLS handshake failed with %s: %w", addr, err)
			}
		}
		conn = tlsConn
	} else {
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			// Check if certificates were captured during a partial failure
			if len(capturedCerts) == 0 {
				return nil, fmt.Errorf("failed to establish TLS connection to %s: %w", addr, err)
			}
		} else {
			conn = tlsConn
		}
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	handshakeDuration := time.Since(start)

	var cs tls.ConnectionState
	var remoteAddr string
	if tlsConn, ok := conn.(*tls.Conn); ok {
		cs = tlsConn.ConnectionState()
		remoteAddr = tlsConn.RemoteAddr().String()
		if len(capturedCerts) == 0 && len(cs.PeerCertificates) > 0 {
			capturedCerts = cs.PeerCertificates
		}
	}

	if len(capturedCerts) == 0 {
		return nil, fmt.Errorf("no peer certificates presented by %s", addr)
	}

	details := HandshakeDetails{
		RemoteAddr:        remoteAddr,
		ServerName:        sni,
		TLSVersion:        tls.VersionName(cs.Version),
		CipherSuite:       tls.CipherSuiteName(cs.CipherSuite),
		NegotiatedALPN:    cs.NegotiatedProtocol,
		OCSPStapled:       len(cs.OCSPResponse) > 0,
		HandshakeDuration: handshakeDuration,
		IsFileProbe:       false,
	}

	return &ProbeResult{
		Certificates: capturedCerts,
		Details:      details,
	}, nil
}

// NormalizeHostPort adds the default port if omitted.
func NormalizeHostPort(target string, defaultPort int) string {
	target = strings.TrimSpace(target)
	// Strip scheme if user provided e.g. https://
	if idx := strings.Index(target, "://"); idx != -1 {
		target = target[idx+3:]
	}
	// Strip trailing slash or path if user provided e.g. api.example.com/v1
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	if strings.Contains(target, ":") {
		// Could be host:port or IPv6
		_, _, err := net.SplitHostPort(target)
		if err == nil {
			return target
		}
	}
	return fmt.Sprintf("%s:%d", target, defaultPort)
}

func performStartTLS(conn net.Conn, proto, host string) error {
	proto = strings.ToLower(strings.TrimSpace(proto))
	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)

	switch proto {
	case "smtp":
		// Read 220 banner
		code, _, err := tp.ReadCodeLine(220)
		if err != nil {
			return fmt.Errorf("SMTP banner read failed: %w", err)
		}
		_ = code

		// Send EHLO
		fmt.Fprintf(conn, "EHLO cert-chain-doctor\r\n")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return fmt.Errorf("SMTP EHLO response error: %w", err)
			}
			if len(line) >= 4 && line[3] == ' ' {
				break
			}
		}

		// Send STARTTLS
		fmt.Fprintf(conn, "STARTTLS\r\n")
		code, _, err = tp.ReadCodeLine(220)
		if err != nil {
			return fmt.Errorf("SMTP STARTTLS command rejected (code %d): %w", code, err)
		}
		return nil

	case "imap":
		// Read greeting banner (* OK ...)
		_, err := tp.ReadLine()
		if err != nil {
			return fmt.Errorf("IMAP greeting read error: %w", err)
		}

		// Send STARTTLS command
		fmt.Fprintf(conn, "a001 STARTTLS\r\n")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return fmt.Errorf("IMAP STARTTLS response error: %w", err)
			}
			if strings.HasPrefix(line, "a001 ") {
				if strings.Contains(line, "OK") {
					return nil
				}
				return fmt.Errorf("IMAP STARTTLS not supported or rejected: %s", line)
			}
		}

	case "pop3":
		// Read greeting (+OK ...)
		line, err := tp.ReadLine()
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("POP3 greeting error: %v", err)
		}

		// Send STLS
		fmt.Fprintf(conn, "STLS\r\n")
		line, err = tp.ReadLine()
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("POP3 STLS command rejected: %s", line)
		}
		return nil

	case "postgres":
		// PostgreSQL SSLRequest: 8 bytes total
		// Length: int32(8)
		// Code: int32(80877103) = 0x04D2162F
		buf := make([]byte, 8)
		binary.BigEndian.PutUint32(buf[0:4], 8)
		binary.BigEndian.PutUint32(buf[4:8], 80877103)
		if _, err := conn.Write(buf); err != nil {
			return fmt.Errorf("Postgres SSLRequest write error: %w", err)
		}

		reply := make([]byte, 1)
		if _, err := conn.Read(reply); err != nil {
			return fmt.Errorf("Postgres SSLRequest read response error: %w", err)
		}
		if reply[0] != 'S' {
			return fmt.Errorf("PostgreSQL server does not support SSL (response '%c')", reply[0])
		}
		return nil

	case "mysql":
		// Read Initial Handshake Packet
		header := make([]byte, 4)
		if _, err := ioReadFull(conn, header); err != nil {
			return fmt.Errorf("MySQL initial handshake packet read failed: %w", err)
		}
		payloadLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
		payload := make([]byte, payloadLen)
		if _, err := ioReadFull(conn, payload); err != nil {
			return fmt.Errorf("MySQL payload read failed: %w", err)
		}

		// Send SSL Request packet (32 bytes payload: client flags with CLIENT_SSL 0x00000800)
		sslPacket := make([]byte, 36)
		binary.LittleEndian.PutUint32(sslPacket[0:4], uint32(32)) // length = 32, seq = 1
		sslPacket[3] = 1                                         // sequence id 1
		binary.LittleEndian.PutUint32(sslPacket[4:8], 0x00000800|0x00000200) // CLIENT_SSL | CLIENT_PROTOCOL_41
		binary.LittleEndian.PutUint32(sslPacket[8:12], 16777216)             // max packet size 16MB
		sslPacket[12] = 33                                                   // utf8_general_ci
		if _, err := conn.Write(sslPacket); err != nil {
			return fmt.Errorf("MySQL SSL request write failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported STARTTLS protocol: %s", proto)
	}
}

func ioReadFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
