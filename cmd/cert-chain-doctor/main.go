package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/probe"
	"github.com/smford/cert-chain-doctor/internal/render"
)

var (
	version = "1.0.0"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	args = reorderArgs(args)
	fs := flag.NewFlagSet("cert-chain-doctor", flag.ContinueOnError)

	filePath := fs.String("file", "", "Analyze a local PEM certificate file/bundle offline instead of dialing a network host")
	sni := fs.String("sni", "", "Override TLS Server Name Indication (SNI)")
	alpnStr := fs.String("alpn", "", "Comma-separated list of ALPN protocols (e.g. 'h2,http/1.1')")
	startTLS := fs.String("starttls", "", "STARTTLS protocol (smtp, imap, pop3, postgres, mysql)")
	fixBundlePath := fs.String("fix-bundle", "", "Automatically chase AIA URLs, verify signatures, and write clean fullchain PEM bundle to this path")
	expiryWarnDays := fs.Int("expiry-warn", 14, "Warning threshold in days for certificate expiration")
	format := fs.String("format", "text", "Output format: 'text' (default) or 'json'")
	caFile := fs.String("ca-file", "", "Path to custom CA root certificate(s) PEM file for verification")
	timeoutSec := fs.Int("timeout", 10, "Network dial and handshake timeout in seconds")
	showVersion := fs.Bool("version", false, "Print version information and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "cert-chain-doctor v%s — Visual TLS Handshake & Intermediate Cert Debugger\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor [flags] <host[:port]>\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor --file <bundle.pem> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor api.example.com\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor 192.0.2.1:443 --sni api.example.com\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor smtp.example.com:587 --starttls smtp\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor api.example.com --fix-bundle /etc/ssl/repaired-bundle.pem\n")
		fmt.Fprintf(os.Stderr, "  cert-chain-doctor --file server.pem --format json\n")
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *showVersion {
		fmt.Printf("cert-chain-doctor version %s\n", version)
		return 0
	}

	target := ""
	remaining := fs.Args()
	if len(remaining) > 0 {
		target = remaining[0]
	}

	if *filePath == "" && target == "" {
		fs.Usage()
		return 1
	}

	// 1. Prepare Root CA pool
	var rootPool *x509.CertPool
	if *caFile != "" {
		caData, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA file %s: %v\n", *caFile, err)
			return 1
		}
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(caData) {
			fmt.Fprintf(os.Stderr, "Error: no valid certificates found in CA file %s\n", *caFile)
			return 1
		}
	} else {
		var err error
		rootPool, err = x509.SystemCertPool()
		if err != nil {
			rootPool = x509.NewCertPool()
		}
	}

	// 2. Parse ALPN
	var alpn []string
	if *alpnStr != "" {
		for _, p := range strings.Split(*alpnStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				alpn = append(alpn, p)
			}
		}
	}

	// 3. Execute Probe
	probeOpts := probe.ProbeOptions{
		TargetHost: target,
		SNI:        *sni,
		ALPN:       alpn,
		StartTLS:   *startTLS,
		Timeout:    time.Duration(*timeoutSec) * time.Second,
		FilePath:   *filePath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec+5)*time.Second)
	defer cancel()

	probeRes, err := probe.Probe(ctx, probeOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error probing target: %v\n", err)
		return 1
	}

	// Determine effective hostname for SAN validation
	effectiveHostname := *sni
	if effectiveHostname == "" && target != "" {
		h := target
		if hostOnly, _, err := net.SplitHostPort(target); err == nil {
			h = hostOnly
		}
		if idx := strings.Index(h, "://"); idx != -1 {
			h = h[idx+3:]
		}
		if idx := strings.Index(h, "/"); idx != -1 {
			h = h[:idx]
		}
		effectiveHostname = h
	}

	// 4. Analyze Raw Chain
	analysisOpts := analyzer.AnalyzeOptions{
		Hostname:       effectiveHostname,
		RootPool:       rootPool,
		WarnExpiryDays: *expiryWarnDays,
	}
	analysisRes := analyzer.Analyze(probeRes.Certificates, analysisOpts)

	// 5. AIA Chain Repair if requested
	var repairRes *aia.RepairResult
	if *fixBundlePath != "" {
		var repairErr error
		repairRes, repairErr = aia.RepairChain(probeRes.Certificates, rootPool, aia.DefaultFetcherConfig())
		if repairErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Chain repair encountered error: %v\n", repairErr)
		} else {
			if err := aia.WriteBundleToFile(*fixBundlePath, repairRes.PEMBundle); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing repaired bundle to %s: %v\n", *fixBundlePath, err)
				return 1
			}
		}
	}

	// 6. Render Output
	displayTarget := target
	if *filePath != "" {
		displayTarget = *filePath
	}

	outputData := render.OutputData{
		Target:        displayTarget,
		Handshake:     &probeRes.Details,
		Analysis:      analysisRes,
		RepairResult:  repairRes,
		FixBundlePath: *fixBundlePath,
	}

	if strings.ToLower(*format) == "json" {
		if err := render.RenderJSON(os.Stdout, outputData); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON: %v\n", err)
			return 1
		}
	} else {
		render.RenderText(os.Stdout, outputData)
	}

	// 7. Compute Exit Code
	// If fix-bundle was specified and successfully repaired and verified the chain:
	repairedAndTrusted := (repairRes != nil && repairRes.VerifiedAgainstRoots)

	hasFatalErrors := false
	hasExpiryWarning := false

	for _, iss := range analysisRes.Issues {
		if iss.Severity == analyzer.SeverityError {
			hasFatalErrors = true
		} else if iss.Code == "CERT_EXPIRING_SOON" {
			hasExpiryWarning = true
		}
	}

	if hasFatalErrors {
		// If user requested --fix-bundle and it successfully repaired the chain:
		if *fixBundlePath != "" && repairedAndTrusted {
			if hasExpiryWarning {
				return 2
			}
			return 0
		}
		return 1
	}

	if hasExpiryWarning {
		return 2
	}

	return 0
}

// reorderArgs places non-flag arguments at the end so that flag.Parse handles flags
// appearing after the host parameter (e.g. `cert-chain-doctor host:443 --fix-bundle out.pem`).
func reorderArgs(args []string) []string {
	var flags []string
	var positionals []string

	boolFlags := map[string]bool{
		"-version":  true,
		"--version": true,
		"-h":        true,
		"--help":    true,
	}

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") || boolFlags[arg] {
				flags = append(flags, arg)
				i++
			} else {
				flags = append(flags, arg)
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					flags = append(flags, args[i+1])
					i += 2
				} else {
					i++
				}
			}
		} else {
			positionals = append(positionals, arg)
			i++
		}
	}

	return append(flags, positionals...)
}
