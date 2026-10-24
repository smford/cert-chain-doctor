package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/smford/cert-chain-doctor/internal/aia"
	"github.com/smford/cert-chain-doctor/internal/analyzer"
	"github.com/smford/cert-chain-doctor/internal/probe"
	"github.com/smford/cert-chain-doctor/internal/render"
	"github.com/smford/cert-chain-doctor/internal/revocation"
)

var (
	version = "0.1.0"
	commit  = "dev"
	date    = "unknown"
)

func formatVersion() string {
	v := version
	c := commit
	d := date

	if info, ok := debug.ReadBuildInfo(); ok {
		if (v == "" || v == "dev") && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && (c == "dev" || c == "") {
				c = setting.Value
			}
			if setting.Key == "vcs.time" && (d == "unknown" || d == "") {
				d = setting.Value
			}
		}
	}

	return fmt.Sprintf("cert-chain-doctor %s (commit: %s, date: %s)\nCopyright (c) 2026 smford\nLicensed under the MIT License", v, c, d)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "serve" {
		return runServer(args[1:])
	}

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
	colorStr := fs.String("color", "auto", "ANSI color output: 'auto', 'always', or 'never'")
	k8sSecret := fs.String("k8s-secret", "", "Generate a Kubernetes TLS Secret YAML manifest with the repaired bundle")
	k8sNamespace := fs.String("k8s-namespace", "default", "Kubernetes namespace for generated TLS secret")
	hostsFile := fs.String("hosts-file", "", "Batch audit multiple endpoints from a newline-delimited text file")
	checkRevocation := fs.Bool("check-revocation", false, "Actively check reachability of OCSP and CRL distribution endpoints")
	showVersion := fs.Bool("version", false, "Print version information and exit")
	fs.BoolVar(showVersion, "v", false, "Print version information and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", formatVersion())
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

	remaining := fs.Args()
	if *showVersion || (len(remaining) == 1 && (remaining[0] == "version" || remaining[0] == "-v")) {
		fmt.Println(formatVersion())
		return 0
	}

	target := ""
	if len(remaining) > 0 {
		target = remaining[0]
	}

	if *filePath == "" && target == "" && *hostsFile == "" {
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

	// 2. Handle batch audit if --hosts-file is provided
	if *hostsFile != "" {
		return runBatchAudit(*hostsFile, time.Duration(*timeoutSec)*time.Second, rootPool, *expiryWarnDays, *format, render.ColorMode(*colorStr))
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

	// 5. AIA Chain Repair if requested or required for K8s secret
	var repairRes *aia.RepairResult
	if *fixBundlePath != "" || *k8sSecret != "" {
		var repairErr error
		repairRes, repairErr = aia.RepairChain(probeRes.Certificates, rootPool, aia.DefaultFetcherConfig())
		if repairErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Chain repair encountered error: %v\n", repairErr)
		} else if *fixBundlePath != "" {
			if err := aia.WriteBundleToFile(*fixBundlePath, repairRes.PEMBundle); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing repaired bundle to %s: %v\n", *fixBundlePath, err)
				return 1
			}
		}
	}

	// 6. Check Revocation if requested
	var revocInfo *render.RevocationInfo
	if *checkRevocation && len(probeRes.Certificates) > 0 {
		revocCtx, cancelRevoc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelRevoc()
		status := revocation.CheckRevocationEndpoints(revocCtx, probeRes.Certificates[0], nil)
		revocInfo = &render.RevocationInfo{
			OCSPChecked:     status.OCSPChecked,
			OCSPReachable:   status.OCSPReachable,
			OCSPServers:     status.OCSPServers,
			CRLDistribution: status.CRLDistribution,
			CRLReachable:    status.CRLReachable,
			Message:         status.Message,
		}
	}

	// 7. Render Output
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
		K8sSecretName: *k8sSecret,
		K8sNamespace:  *k8sNamespace,
		Revocation:    revocInfo,
	}

	if strings.ToLower(*format) == "json" {
		if err := render.RenderJSON(os.Stdout, outputData); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering JSON: %v\n", err)
			return 1
		}
	} else {
		render.RenderText(os.Stdout, outputData, render.RenderOptions{ColorMode: render.ColorMode(*colorStr)})
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
		// If user requested --fix-bundle or --k8s-secret and it successfully repaired the chain:
		if (*fixBundlePath != "" || *k8sSecret != "") && repairedAndTrusted {
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
		"-v":        true,
		"--v":       true,
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

func runServer(args []string) int {
	sfs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := sfs.String("addr", ":8080", "HTTP server listen address")
	if err := sfs.Parse(args); err != nil {
		return 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"status":"ok","version":"%s"}`, version)))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(formatVersion()))
	})
	mux.HandleFunc("/diagnose", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, `{"error":"missing 'target' parameter"}`, http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		probeRes, err := probe.Probe(ctx, probe.ProbeOptions{
			TargetHost: target,
			Timeout:    10 * time.Second,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"probe failed: %s"}`, err.Error()), http.StatusBadGateway)
			return
		}

		roots, _ := x509.SystemCertPool()
		analysis := analyzer.Analyze(probeRes.Certificates, analyzer.AnalyzeOptions{
			Hostname: probeRes.Details.ServerName,
			RootPool: roots,
		})

		out := render.OutputData{
			Target:    target,
			Handshake: &probeRes.Details,
			Analysis:  analysis,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = render.RenderJSON(w, out)
	})

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	fmt.Printf("cert-chain-doctor HTTP diagnostic server listening on %s\n", *addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		return 1
	}
	return 0
}

func runBatchAudit(path string, timeout time.Duration, roots *x509.CertPool, warnDays int, format string, colorMode render.ColorMode) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading hosts file %s: %v\n", path, err)
		return 1
	}

	var targets []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "No valid targets found in %s\n", path)
		return 1
	}

	var items []render.BatchSummaryItem
	hasErrors := false
	hasWarnings := false

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(targets)+1))
	defer cancel()

	for _, t := range targets {
		probeRes, err := probe.Probe(ctx, probe.ProbeOptions{
			TargetHost: t,
			Timeout:    timeout,
		})
		if err != nil {
			hasErrors = true
			items = append(items, render.BatchSummaryItem{
				Target:     t,
				TLSVersion: "-",
				Status:     "ERROR",
				DaysLeft:   0,
				Issues:     []string{"CONNECT_FAILED"},
			})
			continue
		}

		res := analyzer.Analyze(probeRes.Certificates, analyzer.AnalyzeOptions{
			Hostname:       probeRes.Details.ServerName,
			RootPool:       roots,
			WarnExpiryDays: warnDays,
		})

		var issueCodes []string
		itemStatus := "HEALTHY"
		for _, iss := range res.Issues {
			if iss.Severity == analyzer.SeverityError {
				itemStatus = "BROKEN"
				hasErrors = true
			} else if iss.Severity == analyzer.SeverityWarning && itemStatus != "BROKEN" {
				itemStatus = "WARNING"
				hasWarnings = true
			}
			issueCodes = append(issueCodes, iss.Code)
		}

		daysLeft := 0
		if len(res.Certificates) > 0 {
			daysLeft = res.Certificates[0].DaysUntilExpiry
		}

		items = append(items, render.BatchSummaryItem{
			Target:     t,
			TLSVersion: probeRes.Details.TLSVersion,
			Status:     itemStatus,
			DaysLeft:   daysLeft,
			Issues:     issueCodes,
		})
	}

	if strings.ToLower(format) == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
	} else {
		render.RenderBatchTable(os.Stdout, items, colorMode)
	}

	if hasErrors {
		return 1
	}
	if hasWarnings {
		return 2
	}
	return 0
}
