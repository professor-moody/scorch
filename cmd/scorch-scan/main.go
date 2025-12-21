package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"scorch-tools/pkg/security"
)

var (
	// Target
	target     = flag.String("target", "", "SCORCH server hostname or IP")
	port       = flag.Int("port", 81, "SCORCH web service port")
	useTLS     = flag.Bool("tls", false, "Use HTTPS")
	skipVerify = flag.Bool("skip-verify", false, "Skip TLS certificate verification")
	timeout    = flag.Duration("timeout", 30*time.Second, "Request timeout")

	// Authentication (for authenticated scans)
	username = flag.String("username", "", "Username for authenticated scanning")
	password = flag.String("password", "", "Password for authentication")
	domain   = flag.String("domain", "", "Domain for NTLM authentication")
	hash     = flag.String("hash", "", "NT hash for Pass-the-Hash")

	// Scan options
	fullScan      = flag.Bool("full", false, "Run all security checks")
	checkAnon     = flag.Bool("check-anon", true, "Check for anonymous access")
	checkRelay    = flag.Bool("check-relay", true, "Check NTLM relay conditions")
	checkSwagger  = flag.Bool("check-swagger", true, "Check for exposed Swagger")
	checkCreds    = flag.Bool("check-creds", false, "Check for credential exposure in job outputs")
	enumRunbooks  = flag.Bool("enum-runbooks", false, "Enumerate runbooks during scan")

	// Output
	jsonOutput  = flag.Bool("json", false, "Output in JSON format")
	outputFile  = flag.String("output", "", "Write output to file")
	minSeverity = flag.String("min-severity", "info", "Minimum severity to report (info, low, medium, high, critical)")
	debug       = flag.Bool("debug", false, "Enable debug output")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SCORCH-Scan - System Center Orchestrator Security Scanner

Performs security assessment of SCORCH deployments including:
- Authentication configuration analysis
- Anonymous access detection
- NTLM relay attack conditions
- Swagger/API exposure
- Information disclosure
- Certificate validation

Usage: scorch-scan [options]

Target Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Basic unauthenticated scan
  scorch-scan -target scorch.domain.local

  # Full scan with authentication
  scorch-scan -target scorch.domain.local -full -username admin -password secret -domain CORP

  # Pass-the-Hash authenticated scan
  scorch-scan -target scorch.domain.local -username admin -hash aad3b435b51404eeaad3b435b51404ee -domain CORP

  # HTTPS with certificate validation skip
  scorch-scan -target scorch.domain.local -tls -skip-verify

  # Export to JSON file
  scorch-scan -target scorch.domain.local -full -json -output findings.json

Severity Levels:
  CRITICAL - Immediate exploitation possible (e.g., anonymous access with execution)
  HIGH     - Serious security issues (e.g., NTLM relay, credential exposure)
  MEDIUM   - Moderate risk issues (e.g., information disclosure)
  LOW      - Minor issues (e.g., verbose headers)
  INFO     - Informational findings

`)
	}

	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse minimum severity
	minSev := parseSeverity(*minSeverity)

	// Create scanner
	scanner, err := security.NewScanner(security.ScanConfig{
		Target:       *target,
		Port:         *port,
		UseTLS:       *useTLS,
		SkipVerify:   *skipVerify,
		Timeout:      *timeout,
		Username:     *username,
		Password:     *password,
		Domain:       *domain,
		NTHash:       *hash,
		Debug:        *debug,
		CheckAnon:    *checkAnon,
		CheckRelay:   *checkRelay,
		CheckSwagger: *checkSwagger,
		CheckCreds:   *checkCreds,
		FullScan:     *fullScan,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scanner: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*10)
	defer cancel()

	if !*jsonOutput {
		printBanner()
		fmt.Printf("[*] Target: %s:%d\n", *target, *port)
		fmt.Printf("[*] TLS: %v, Skip Verify: %v\n", *useTLS, *skipVerify)
		fmt.Println("[*] Starting security assessment...")
		fmt.Println()
	}

	// Run assessment
	assessment, err := scanner.RunAssessment(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during assessment: %v\n", err)
		os.Exit(1)
	}

	// Filter by severity
	filteredFindings := make([]security.Finding, 0)
	for _, f := range assessment.Findings {
		if f.Severity >= minSev {
			filteredFindings = append(filteredFindings, f)
		}
	}
	assessment.Findings = filteredFindings

	// Recalculate summary
	assessment.Summary = security.AssessmentSummary{}
	for _, f := range assessment.Findings {
		assessment.Summary.TotalFindings++
		switch f.Severity {
		case security.SeverityCritical:
			assessment.Summary.CriticalCount++
		case security.SeverityHigh:
			assessment.Summary.HighCount++
		case security.SeverityMedium:
			assessment.Summary.MediumCount++
		case security.SeverityLow:
			assessment.Summary.LowCount++
		case security.SeverityInfo:
			assessment.Summary.InfoCount++
		}
	}

	// Output results
	if *jsonOutput {
		outputJSON(assessment)
	} else {
		printAssessment(assessment)
	}

	// Write to file if specified
	if *outputFile != "" {
		writeToFile(assessment, *outputFile)
	}

	// Exit with appropriate code
	if assessment.Summary.CriticalCount > 0 {
		os.Exit(2)
	}
	if assessment.Summary.HighCount > 0 {
		os.Exit(1)
	}
}

func printBanner() {
	banner := `
   _____ __________  ____  ________  __         _____                 
  / ___// ____/ __ \/ __ \/ ____/ / / /        / ___/_________ _____  
  \__ \/ /   / / / / /_/ / /   / /_/ /  ______ \__ \/ ___/ __ '/ __ \ 
 ___/ / /___/ /_/ / _, _/ /___/ __  /  /_____/___/ / /__/ /_/ / / / / 
/____/\____/\____/_/ |_|\____/_/ /_/         /____/\___/\__,_/_/ /_/  
                                                                       
System Center Orchestrator Security Scanner v1.0
`
	fmt.Println(banner)
}

func printAssessment(a *security.SecurityAssessment) {
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("                     SECURITY ASSESSMENT REPORT")
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Printf("\n  Target:     %s\n", a.Target)
	fmt.Printf("  Start Time: %s\n", a.StartTime.Format(time.RFC3339))
	fmt.Printf("  End Time:   %s\n", a.EndTime.Format(time.RFC3339))
	fmt.Printf("  Duration:   %s\n", a.EndTime.Sub(a.StartTime).Round(time.Millisecond))

	// API Info
	if a.APIInfo != nil {
		fmt.Println("\n─── API Configuration ─────────────────────────────────────────────")
		fmt.Printf("  API Version:    %s\n", a.APIInfo.Version)
		fmt.Printf("  Uses HTTPS:     %v\n", a.APIInfo.UsesHTTPS)
		if a.APIInfo.UsesHTTPS {
			fmt.Printf("  Certificate:    %s\n", boolToStatus(!a.APIInfo.SelfSignedCert, "Valid", "Self-Signed"))
		}
		fmt.Printf("  Anonymous:      %v\n", a.APIInfo.AnonymousAccess)
		fmt.Printf("  Swagger:        %v\n", a.APIInfo.SwaggerExposed)
		if a.APIInfo.SwaggerURL != "" {
			fmt.Printf("  Swagger URL:    %s\n", a.APIInfo.SwaggerURL)
		}
	}

	// Auth Info
	if a.AuthInfo != nil {
		fmt.Println("\n─── Authentication ────────────────────────────────────────────────")
		fmt.Printf("  Windows Auth:   %v\n", a.AuthInfo.WindowsAuthEnabled)
		fmt.Printf("  Basic Auth:     %v\n", a.AuthInfo.BasicAuthEnabled)
		fmt.Printf("  NTLM:           %v\n", a.AuthInfo.NTLMEnabled)
		fmt.Printf("  Negotiate:      %v\n", a.AuthInfo.NegotiateEnabled)
		fmt.Printf("  Providers:      %s\n", strings.Join(a.AuthInfo.SupportedProviders, ", "))
	}

	// Findings Summary
	fmt.Println("\n─── Findings Summary ──────────────────────────────────────────────")
	fmt.Printf("  Total:    %d\n", a.Summary.TotalFindings)
	if a.Summary.CriticalCount > 0 {
		fmt.Printf("  \033[1;31mCRITICAL: %d\033[0m\n", a.Summary.CriticalCount)
	}
	if a.Summary.HighCount > 0 {
		fmt.Printf("  \033[1;33mHIGH:     %d\033[0m\n", a.Summary.HighCount)
	}
	if a.Summary.MediumCount > 0 {
		fmt.Printf("  MEDIUM:  %d\n", a.Summary.MediumCount)
	}
	if a.Summary.LowCount > 0 {
		fmt.Printf("  LOW:     %d\n", a.Summary.LowCount)
	}
	if a.Summary.InfoCount > 0 {
		fmt.Printf("  INFO:    %d\n", a.Summary.InfoCount)
	}

	// Detailed Findings
	if len(a.Findings) > 0 {
		fmt.Println("\n─── Detailed Findings ─────────────────────────────────────────────")
		for i, f := range a.Findings {
			fmt.Printf("\n[%d] %s\n", i+1, formatSeverity(f.Severity, f.Title))
			fmt.Printf("    ID:          %s\n", f.ID)
			fmt.Printf("    Category:    %s\n", f.Category)
			fmt.Printf("    Description: %s\n", wrapText(f.Description, 60, "                 "))
			if f.Evidence != "" {
				fmt.Printf("    Evidence:    %s\n", wrapText(f.Evidence, 60, "                 "))
			}
			if f.Remediation != "" {
				fmt.Printf("    Remediation: %s\n", wrapText(f.Remediation, 60, "                 "))
			}
			if f.CVSS > 0 {
				fmt.Printf("    CVSS:        %.1f\n", f.CVSS)
			}
			if f.CWE != "" {
				fmt.Printf("    CWE:         %s\n", f.CWE)
			}
		}
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════════")
	
	// Risk Summary
	if a.Summary.CriticalCount > 0 {
		fmt.Println("\n\033[1;31m⚠ CRITICAL VULNERABILITIES FOUND - IMMEDIATE ACTION REQUIRED\033[0m")
	} else if a.Summary.HighCount > 0 {
		fmt.Println("\n\033[1;33m⚠ HIGH SEVERITY ISSUES FOUND - REMEDIATION RECOMMENDED\033[0m")
	} else if a.Summary.TotalFindings == 0 {
		fmt.Println("\n\033[1;32m✓ No significant security issues detected\033[0m")
	}
	fmt.Println()
}

func formatSeverity(sev security.Severity, title string) string {
	switch sev {
	case security.SeverityCritical:
		return fmt.Sprintf("\033[1;31m[CRITICAL]\033[0m %s", title)
	case security.SeverityHigh:
		return fmt.Sprintf("\033[1;33m[HIGH]\033[0m %s", title)
	case security.SeverityMedium:
		return fmt.Sprintf("\033[1;36m[MEDIUM]\033[0m %s", title)
	case security.SeverityLow:
		return fmt.Sprintf("[LOW] %s", title)
	case security.SeverityInfo:
		return fmt.Sprintf("\033[2m[INFO]\033[0m %s", title)
	default:
		return title
	}
}

func boolToStatus(b bool, trueStr, falseStr string) string {
	if b {
		return trueStr
	}
	return falseStr
}

func wrapText(text string, width int, indent string) string {
	if len(text) <= width {
		return text
	}
	
	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0
	
	for i, word := range words {
		if lineLen+len(word)+1 > width && i > 0 {
			result.WriteString("\n")
			result.WriteString(indent)
			lineLen = len(indent)
		} else if i > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
	}
	
	return result.String()
}

func parseSeverity(s string) security.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return security.SeverityCritical
	case "high":
		return security.SeverityHigh
	case "medium":
		return security.SeverityMedium
	case "low":
		return security.SeverityLow
	case "info":
		return security.SeverityInfo
	default:
		return security.SeverityInfo
	}
}

func outputJSON(a *security.SecurityAssessment) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(a)
}

func writeToFile(a *security.SecurityAssessment, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[+] Results written to %s\n", filename)
	}
}
