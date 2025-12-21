package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

type AssessmentResult struct {
	Target     string    `json:"target"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Findings   []Finding `json:"findings"`
	APIVersion string    `json:"api_version,omitempty"`
}

func runAssess(args []string) error {
	if containsHelp(args) {
		printAssessHelp()
		return nil
	}

	opts, _, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	ctx, cancel := createContext(opts)
	defer cancel()

	printf(opts, "[*] Starting security assessment of %s\n", opts.Target)

	result := &AssessmentResult{
		Target:    opts.Target,
		StartTime: time.Now(),
	}

	// Run all checks
	checkAnonymousAccess(ctx, opts, result)
	checkAuthMethods(ctx, opts, result)
	checkTLS(ctx, opts, result)
	checkNTLMRelay(ctx, opts, result)
	checkInfoDisclosure(ctx, opts, result)
	checkCORS(ctx, opts, result)
	checkSwagger(ctx, opts, result)

	result.EndTime = time.Now()

	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	if opts.JSON {
		return writeJSON(output, result)
	}

	// Pretty print results
	printAssessmentResults(output, result)
	return nil
}

func checkAnonymousAccess(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking anonymous access")

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	endpoints := []struct {
		path string
		name string
	}{
		{"/Orchestrator2012/Orchestrator.svc/", "Legacy OData Root"},
		{"/Orchestrator2012/Orchestrator.svc/Runbooks", "Runbooks Endpoint"},
		{"/api/", "Modern API Root"},
		{"/api/runbooks", "Modern Runbooks"},
	}

	for _, ep := range endpoints {
		url := opts.BaseURL() + ep.path
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-ANON-001",
				Title:       fmt.Sprintf("Anonymous Access: %s", ep.name),
				Severity:    "CRITICAL",
				Description: fmt.Sprintf("The %s is accessible without authentication", ep.name),
				Evidence:    fmt.Sprintf("GET %s returned HTTP %d", ep.path, resp.StatusCode),
				Remediation: "Enable Windows Authentication and disable Anonymous in IIS",
			})
		}
	}
}

func checkAuthMethods(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking authentication methods")

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	url := opts.BaseURL() + "/Orchestrator2012/Orchestrator.svc/"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	for _, header := range resp.Header.Values("WWW-Authenticate") {
		lower := strings.ToLower(header)

		if strings.HasPrefix(lower, "ntlm") {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-AUTH-001",
				Title:       "NTLM Authentication Enabled",
				Severity:    "MEDIUM",
				Description: "NTLM is enabled and may be vulnerable to relay attacks if EPA is not configured",
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", header),
				Remediation: "Enable Extended Protection for Authentication (EPA) or use Kerberos-only",
				References:  []string{"https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks"},
			})
		}

		if strings.HasPrefix(lower, "basic") {
			sev := "HIGH"
			if opts.TLS {
				sev = "MEDIUM"
			}
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-AUTH-002",
				Title:       "Basic Authentication Enabled",
				Severity:    sev,
				Description: "Basic auth transmits credentials in base64 (essentially cleartext)",
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", header),
				Remediation: "Disable Basic auth, use Windows Integrated with HTTPS",
			})
		}
	}
}

func checkTLS(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking TLS configuration")

	if !opts.TLS {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-TLS-001",
			Title:       "HTTP (Unencrypted) Access",
			Severity:    "HIGH",
			Description: "The SCORCH web service is accessible over unencrypted HTTP",
			Evidence:    fmt.Sprintf("Connected to %s:%d over HTTP", opts.Target, opts.Port),
			Remediation: "Enable HTTPS and disable HTTP access",
		})
		return
	}

	// Check TLS version
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: opts.Timeout},
		"tcp",
		fmt.Sprintf("%s:%d", opts.Target, opts.Port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	switch state.Version {
	case tls.VersionTLS10:
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-TLS-002",
			Title:       "Weak TLS Version (1.0)",
			Severity:    "HIGH",
			Description: "TLS 1.0 is deprecated and vulnerable to BEAST, POODLE attacks",
			Evidence:    "Negotiated TLS 1.0",
			Remediation: "Disable TLS 1.0/1.1, enforce TLS 1.2+",
		})
	case tls.VersionTLS11:
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-TLS-003",
			Title:       "Deprecated TLS Version (1.1)",
			Severity:    "MEDIUM",
			Description: "TLS 1.1 is deprecated",
			Evidence:    "Negotiated TLS 1.1",
			Remediation: "Disable TLS 1.1, enforce TLS 1.2+",
		})
	}
}

func checkNTLMRelay(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking NTLM relay attack surface")

	if opts.TLS {
		return // Relay much harder over HTTPS with proper certs
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	url := opts.BaseURL() + "/Orchestrator2012/Orchestrator.svc/"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	authHeader := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(strings.ToLower(authHeader), "ntlm") {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-RELAY-001",
			Title:       "NTLM Relay Attack Surface",
			Severity:    "HIGH",
			Description: "NTLM over HTTP allows credential relay attacks from MITM position",
			Evidence:    "NTLM auth over HTTP without EPA",
			Remediation: "Enable HTTPS with EPA, or switch to Kerberos-only",
			References: []string{
				"https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks",
				"https://attack.mitre.org/techniques/T1557/001/",
			},
		})
	}
}

func checkInfoDisclosure(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking information disclosure")

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	url := opts.BaseURL() + "/"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if server := resp.Header.Get("Server"); server != "" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-INFO-001",
			Title:       "Server Header Disclosure",
			Severity:    "LOW",
			Description: "Server header reveals version information",
			Evidence:    fmt.Sprintf("Server: %s", server),
			Remediation: "Configure IIS to suppress Server header",
		})
	}

	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-INFO-002",
			Title:       "X-Powered-By Header",
			Severity:    "LOW",
			Description: "X-Powered-By header reveals technology stack",
			Evidence:    fmt.Sprintf("X-Powered-By: %s", xpb),
			Remediation: "Remove X-Powered-By header in IIS",
		})
	}
}

func checkCORS(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking CORS configuration")

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	url := opts.BaseURL() + "/api/runbooks"
	req, _ := http.NewRequestWithContext(ctx, "OPTIONS", url, nil)
	req.Header.Set("Origin", "https://evil.attacker.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

	if allowOrigin == "*" || allowOrigin == "https://evil.attacker.com" {
		sev := "MEDIUM"
		if allowCreds == "true" {
			sev = "HIGH"
		}
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-CORS-001",
			Title:       "Permissive CORS Policy",
			Severity:    sev,
			Description: "CORS allows requests from arbitrary origins",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin),
			Remediation: "Restrict CORS to trusted origins only",
		})
	}
}

func checkSwagger(ctx context.Context, opts *CommonOpts, result *AssessmentResult) {
	debugf(opts, "Checking Swagger exposure")

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
		},
	}

	endpoints := []string{"/swagger", "/swagger/index.html", "/api/swagger.json"}
	for _, ep := range endpoints {
		url := opts.BaseURL() + ep
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-API-001",
				Title:       "Swagger Documentation Exposed",
				Severity:    "LOW",
				Description: fmt.Sprintf("API documentation accessible at %s", ep),
				Remediation: "Restrict Swagger access in production",
			})
			break
		}
	}
}

func printAssessmentResults(w io.Writer, result *AssessmentResult) {
	fmt.Fprintf(w, "\n[+] Security Assessment: %s\n", result.Target)
	fmt.Fprintf(w, "    Duration: %s\n", result.EndTime.Sub(result.StartTime))
	fmt.Fprintln(w, strings.Repeat("=", 60))

	// Count by severity
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	fmt.Fprintf(w, "\nSummary: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW\n",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])

	// Print by severity
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		var sevFindings []Finding
		for _, f := range result.Findings {
			if f.Severity == sev {
				sevFindings = append(sevFindings, f)
			}
		}

		if len(sevFindings) == 0 {
			continue
		}

		fmt.Fprintf(w, "\n[%s]\n", sev)
		for _, f := range sevFindings {
			fmt.Fprintf(w, "  %s: %s\n", f.ID, f.Title)
			fmt.Fprintf(w, "    %s\n", f.Description)
			if f.Evidence != "" {
				fmt.Fprintf(w, "    Evidence: %s\n", f.Evidence)
			}
		}
	}

	fmt.Fprintln(w)
}

func printAssessHelp() {
	fmt.Print(`
scorch assess - Security assessment of SCORCH deployment

Usage: scorch assess [options]

Target Options:
  -target, -t    Target SCORCH server (required)
  -port, -P      Web service port (default: 81)
  -tls           Use HTTPS
  -k             Skip TLS certificate verification

Output:
  -json          JSON output
  -o, -output    Write to file
  -debug         Debug output

Checks Performed:
  - Anonymous API access
  - Authentication methods (NTLM, Basic, Negotiate)
  - NTLM relay attack surface
  - TLS configuration
  - Information disclosure headers
  - CORS misconfiguration
  - Swagger/API documentation exposure

Examples:
  # Basic security scan
  scorch assess -t scorch.corp.local

  # HTTPS with JSON output
  scorch assess -t scorch.corp.local -tls -json -o findings.json

`)
}
