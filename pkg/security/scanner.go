package security

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Scanner performs security assessments against SCORCH instances
type Scanner struct {
	target      string
	client      *http.Client
	debug       bool
	findings    []Finding
	apiInfo     *APISecurityInfo
	authInfo    *AuthInfo
	serviceInfo *ServiceInfo
}

// ScanConfig holds scanner configuration
type ScanConfig struct {
	Target        string
	Port          int
	UseTLS        bool
	SkipVerify    bool
	Timeout       time.Duration
	Username      string
	Password      string
	Domain        string
	NTHash        string
	Debug         bool
	CheckAnon     bool // Check for anonymous access
	CheckRelay    bool // Check NTLM relay conditions
	CheckSwagger  bool // Check for exposed Swagger
	CheckCreds    bool // Check for credential exposure
	FullScan      bool // Run all checks
}

// NewScanner creates a new security scanner
func NewScanner(cfg ScanConfig) (*Scanner, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target is required")
	}
	
	if cfg.Port == 0 {
		cfg.Port = 81
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	
	target := fmt.Sprintf("%s://%s:%d", scheme, cfg.Target, cfg.Port)
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
	
	return &Scanner{
		target:   target,
		client:   client,
		debug:    cfg.Debug,
		findings: make([]Finding, 0),
		apiInfo:  &APISecurityInfo{BaseURL: target},
		authInfo: &AuthInfo{},
	}, nil
}

// RunAssessment performs a complete security assessment
func (s *Scanner) RunAssessment(ctx context.Context) (*SecurityAssessment, error) {
	assessment := &SecurityAssessment{
		Target:    s.target,
		StartTime: time.Now(),
		Findings:  make([]Finding, 0),
	}
	
	if s.debug {
		fmt.Printf("[*] Starting security assessment of %s\n", s.target)
	}
	
	// Run all checks
	checks := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"HTTP/HTTPS Configuration", s.checkHTTPConfig},
		{"Anonymous Access", s.checkAnonymousAccess},
		{"Authentication Methods", s.checkAuthMethods},
		{"Swagger/API Documentation", s.checkSwaggerExposure},
		{"NTLM Relay Conditions", s.checkNTLMRelay},
		{"Error Handling", s.checkVerboseErrors},
		{"CORS Configuration", s.checkCORS},
		{"Server Information Disclosure", s.checkServerHeaders},
		{"API Version Detection", s.checkAPIVersion},
	}
	
	for _, check := range checks {
		if s.debug {
			fmt.Printf("[*] Running check: %s\n", check.name)
		}
		if err := check.fn(ctx); err != nil {
			if s.debug {
				fmt.Printf("[!] Check failed: %s - %v\n", check.name, err)
			}
		}
	}
	
	assessment.EndTime = time.Now()
	assessment.Findings = s.findings
	assessment.APIInfo = s.apiInfo
	assessment.AuthInfo = s.authInfo
	assessment.ServiceInfo = s.serviceInfo
	
	// Calculate summary
	for _, f := range s.findings {
		assessment.Summary.TotalFindings++
		switch f.Severity {
		case SeverityCritical:
			assessment.Summary.CriticalCount++
		case SeverityHigh:
			assessment.Summary.HighCount++
		case SeverityMedium:
			assessment.Summary.MediumCount++
		case SeverityLow:
			assessment.Summary.LowCount++
		case SeverityInfo:
			assessment.Summary.InfoCount++
		}
	}
	
	return assessment, nil
}

// checkHTTPConfig checks if HTTPS is being used
func (s *Scanner) checkHTTPConfig(ctx context.Context) error {
	s.apiInfo.UsesHTTPS = strings.HasPrefix(s.target, "https://")
	
	if !s.apiInfo.UsesHTTPS {
		finding := FindingTemplates[VulnHTTPCleartext]
		finding.Timestamp = time.Now()
		finding.Evidence = fmt.Sprintf("API accessible at %s (unencrypted HTTP)", s.target)
		s.findings = append(s.findings, finding)
	} else {
		// Check certificate validity
		if err := s.checkCertificate(ctx); err != nil {
			if s.debug {
				fmt.Printf("[!] Certificate check failed: %v\n", err)
			}
		}
	}
	
	return nil
}

// checkCertificate checks TLS certificate configuration
func (s *Scanner) checkCertificate(ctx context.Context) error {
	// Create a client that doesn't skip verification
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.target, nil)
	if err != nil {
		return err
	}
	
	_, err = client.Do(req)
	if err != nil {
		// Certificate validation failed - likely self-signed
		if strings.Contains(err.Error(), "certificate") {
			s.apiInfo.SelfSignedCert = true
			s.apiInfo.CertificateValid = false
			
			finding := FindingTemplates[VulnSelfSignedCertificate]
			finding.Timestamp = time.Now()
			finding.Evidence = err.Error()
			s.findings = append(s.findings, finding)
		}
	} else {
		s.apiInfo.CertificateValid = true
	}
	
	return nil
}

// checkAnonymousAccess tests if API is accessible without authentication
func (s *Scanner) checkAnonymousAccess(ctx context.Context) error {
	endpoints := []string{
		"/api/runbooks",
		"/Orchestrator2012/Orchestrator.svc/Runbooks",
		"/api/jobs",
		"/Orchestrator2012/Orchestrator.svc/Jobs",
	}
	
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.target+endpoint, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == http.StatusOK {
			s.apiInfo.AnonymousAccess = true
			s.authInfo.AnonymousEnabled = true
			
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			finding := FindingTemplates[VulnAnonymousAPIAccess]
			finding.Timestamp = time.Now()
			finding.Evidence = fmt.Sprintf("Endpoint %s accessible without authentication. Response: %s",
				endpoint, truncate(string(body), 200))
			s.findings = append(s.findings, finding)
			
			return nil // Found anonymous access, no need to check more
		}
		resp.Body.Close()
	}
	
	return nil
}

// checkAuthMethods probes for supported authentication methods
func (s *Scanner) checkAuthMethods(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.target+"/api/runbooks", nil)
	if err != nil {
		return err
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusUnauthorized {
		return nil // Either accessible or error
	}
	
	// Parse WWW-Authenticate headers
	authHeaders := resp.Header.Values("Www-Authenticate")
	for _, header := range authHeaders {
		headerLower := strings.ToLower(header)
		
		if strings.HasPrefix(headerLower, "negotiate") {
			s.authInfo.NegotiateEnabled = true
			s.authInfo.SupportedProviders = append(s.authInfo.SupportedProviders, "Negotiate")
		}
		if strings.HasPrefix(headerLower, "ntlm") {
			s.authInfo.NTLMEnabled = true
			s.authInfo.SupportedProviders = append(s.authInfo.SupportedProviders, "NTLM")
		}
		if strings.HasPrefix(headerLower, "basic") {
			s.authInfo.BasicAuthEnabled = true
			s.authInfo.SupportedProviders = append(s.authInfo.SupportedProviders, "Basic")
			s.apiInfo.AuthMethods = append(s.apiInfo.AuthMethods, "Basic")
		}
		if strings.HasPrefix(headerLower, "kerberos") {
			s.authInfo.KerberosEnabled = true
			s.authInfo.SupportedProviders = append(s.authInfo.SupportedProviders, "Kerberos")
		}
	}
	
	// If Negotiate or NTLM is enabled, check for EPA
	if s.authInfo.NegotiateEnabled || s.authInfo.NTLMEnabled {
		s.authInfo.WindowsAuthEnabled = true
		s.apiInfo.AuthMethods = append(s.apiInfo.AuthMethods, "Windows")
		
		// EPA check would require actual NTLM exchange to detect
		// For now, assume missing EPA if NTLM is available (common default)
		finding := FindingTemplates[VulnMissingEPA]
		finding.Timestamp = time.Now()
		finding.Evidence = fmt.Sprintf("NTLM/Negotiate authentication enabled. Auth headers: %v",
			authHeaders)
		s.findings = append(s.findings, finding)
	}
	
	return nil
}

// checkSwaggerExposure checks for exposed API documentation
func (s *Scanner) checkSwaggerExposure(ctx context.Context) error {
	swaggerEndpoints := []string{
		"/swagger",
		"/swagger/index.html",
		"/swagger/v1/swagger.json",
		"/api/swagger",
		"/api-docs",
	}
	
	for _, endpoint := range swaggerEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.target+endpoint, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == http.StatusOK {
			contentType := resp.Header.Get("Content-Type")
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			// Verify it's actually Swagger
			if strings.Contains(string(body), "swagger") ||
				strings.Contains(string(body), "openapi") ||
				strings.Contains(contentType, "json") {
				
				s.apiInfo.SwaggerExposed = true
				s.apiInfo.SwaggerURL = s.target + endpoint
				
				finding := FindingTemplates[VulnSwaggerExposed]
				finding.Timestamp = time.Now()
				finding.Evidence = fmt.Sprintf("Swagger UI accessible at %s", s.target+endpoint)
				s.findings = append(s.findings, finding)
				
				return nil
			}
		}
		resp.Body.Close()
	}
	
	return nil
}

// checkNTLMRelay evaluates NTLM relay attack conditions
func (s *Scanner) checkNTLMRelay(ctx context.Context) error {
	if !s.authInfo.NTLMEnabled && !s.authInfo.NegotiateEnabled {
		return nil // NTLM not enabled
	}
	
	// Check conditions that make relay more likely:
	// 1. HTTP (not HTTPS) - no channel binding possible
	// 2. No Extended Protection for Authentication
	// 3. SMB signing not required (can't check from here)
	
	isRelayable := false
	evidence := []string{}
	
	if !s.apiInfo.UsesHTTPS {
		isRelayable = true
		evidence = append(evidence, "HTTP used (no TLS channel binding)")
	}
	
	// EPA is typically disabled by default
	if s.authInfo.NTLMEnabled {
		isRelayable = true
		evidence = append(evidence, "NTLM authentication enabled")
	}
	
	if isRelayable {
		finding := FindingTemplates[VulnNTLMRelayable]
		finding.Timestamp = time.Now()
		finding.Evidence = fmt.Sprintf("Conditions favorable for NTLM relay: %s",
			strings.Join(evidence, "; "))
		s.findings = append(s.findings, finding)
	}
	
	return nil
}

// checkVerboseErrors tests for detailed error messages
func (s *Scanner) checkVerboseErrors(ctx context.Context) error {
	// Request an invalid endpoint to trigger error
	testEndpoints := []string{
		"/api/nonexistent",
		"/api/runbooks('invalid-guid')",
		"/Orchestrator2012/Orchestrator.svc/Invalid",
	}
	
	for _, endpoint := range testEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.target+endpoint, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		bodyStr := string(body)
		
		// Look for verbose error indicators
		verboseIndicators := []string{
			"StackTrace",
			"Exception",
			"System.Web",
			"at System.",
			"line number",
			"\\Program Files",
			"\\inetpub",
			"Microsoft.SystemCenter",
			"SqlException",
			"connection string",
		}
		
		for _, indicator := range verboseIndicators {
			if strings.Contains(bodyStr, indicator) {
				s.apiInfo.VerboseErrors = true
				
				finding := FindingTemplates[VulnVerboseErrors]
				finding.Timestamp = time.Now()
				finding.Evidence = fmt.Sprintf("Endpoint %s returned detailed error: %s",
					endpoint, truncate(bodyStr, 500))
				s.findings = append(s.findings, finding)
				
				return nil
			}
		}
	}
	
	return nil
}

// checkCORS tests CORS configuration
func (s *Scanner) checkCORS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", s.target+"/api/runbooks", nil)
	if err != nil {
		return err
	}
	
	// Set Origin header to test CORS
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin != "" {
		s.apiInfo.CORSEnabled = true
		s.apiInfo.CORSAllowOrigin = allowOrigin
		
		// Check for dangerous CORS config
		if allowOrigin == "*" || allowOrigin == "https://evil.com" {
			finding := Finding{
				ID:          VulnCORSMisconfiguration,
				Title:       "Permissive CORS Configuration",
				Description: "The API allows cross-origin requests from arbitrary origins, potentially enabling credential theft via malicious websites.",
				Category:    CategoryConfiguration,
				Severity:    SeverityMedium,
				Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin),
				Remediation: "Configure CORS to only allow trusted origins.",
				CWE:         "CWE-942",
				CVSS:        5.3,
				Timestamp:   time.Now(),
			}
			s.findings = append(s.findings, finding)
		}
	}
	
	return nil
}

// checkServerHeaders checks for information disclosure in headers
func (s *Scanner) checkServerHeaders(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.target+"/", nil)
	if err != nil {
		return err
	}
	
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Check various headers
	s.apiInfo.ServerHeader = resp.Header.Get("Server")
	s.apiInfo.PoweredByHeader = resp.Header.Get("X-Powered-By")
	
	// Extract version info if present
	if s.serviceInfo == nil {
		s.serviceInfo = &ServiceInfo{}
	}
	
	if server := s.apiInfo.ServerHeader; server != "" {
		if strings.Contains(server, "Microsoft-IIS") {
			parts := strings.Split(server, "/")
			if len(parts) > 1 {
				s.serviceInfo.IISVersion = parts[1]
			}
		}
	}
	
	if poweredBy := s.apiInfo.PoweredByHeader; poweredBy != "" {
		if strings.Contains(poweredBy, "ASP.NET") {
			s.serviceInfo.DotNetVersion = poweredBy
		}
	}
	
	// Info-level finding for header disclosure
	if s.apiInfo.ServerHeader != "" || s.apiInfo.PoweredByHeader != "" {
		finding := Finding{
			ID:          "SCORCH-INFO-001",
			Title:       "Server Version Information Disclosed",
			Description: "HTTP response headers reveal server software and version information.",
			Category:    CategoryInformationLeak,
			Severity:    SeverityInfo,
			Evidence: fmt.Sprintf("Server: %s, X-Powered-By: %s",
				s.apiInfo.ServerHeader, s.apiInfo.PoweredByHeader),
			Remediation: "Remove or obfuscate Server and X-Powered-By headers.",
			Timestamp:   time.Now(),
		}
		s.findings = append(s.findings, finding)
	}
	
	return nil
}

// checkAPIVersion detects the API version
func (s *Scanner) checkAPIVersion(ctx context.Context) error {
	// Try modern API
	req, err := http.NewRequestWithContext(ctx, "GET", s.target+"/api/runbooks", nil)
	if err != nil {
		return err
	}
	
	resp, err := s.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			s.apiInfo.Version = "Modern (2022+)"
			return nil
		}
	}
	
	// Try legacy API
	req, err = http.NewRequestWithContext(ctx, "GET",
		s.target+"/Orchestrator2012/Orchestrator.svc/", nil)
	if err != nil {
		return err
	}
	
	resp, err = s.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			s.apiInfo.Version = "Legacy (Pre-2022)"
		}
	}
	
	return nil
}

// GetFindings returns all collected findings
func (s *Scanner) GetFindings() []Finding {
	return s.findings
}

// ExportJSON exports findings as JSON
func (s *Scanner) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(s.findings, "", "  ")
}

// truncate limits string length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
