package discovery

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// VulnSeverity represents vulnerability severity
type VulnSeverity int

const (
	SeverityInfo VulnSeverity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s VulnSeverity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Finding represents a security finding
type Finding struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Severity    VulnSeverity `json:"severity"`
	Description string       `json:"description"`
	Evidence    string       `json:"evidence,omitempty"`
	Remediation string       `json:"remediation,omitempty"`
	References  []string     `json:"references,omitempty"`
}

// AssessmentResult holds all findings from a security assessment
type AssessmentResult struct {
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Findings    []Finding `json:"findings"`
	Errors      []string  `json:"errors,omitempty"`
	APIVersion  string    `json:"api_version,omitempty"`
	ServerInfo  string    `json:"server_info,omitempty"`
}

// SecurityAssessor performs security assessments on SCORCH
type SecurityAssessor struct {
	target     string
	port       int
	useTLS     bool
	skipVerify bool
	timeout    time.Duration
	httpClient *http.Client
	debug      bool
}

// NewSecurityAssessor creates a new security assessor
func NewSecurityAssessor(target string, port int, useTLS, skipVerify bool, timeout time.Duration) *SecurityAssessor {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}
	
	return &SecurityAssessor{
		target:     target,
		port:       port,
		useTLS:     useTLS,
		skipVerify: skipVerify,
		timeout:    timeout,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SetDebug enables debug output
func (s *SecurityAssessor) SetDebug(debug bool) {
	s.debug = debug
}

// baseURL returns the base URL for the target
func (s *SecurityAssessor) baseURL() string {
	scheme := "http"
	if s.useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, s.target, s.port)
}

// RunFullAssessment runs all security checks
func (s *SecurityAssessor) RunFullAssessment(ctx context.Context) (*AssessmentResult, error) {
	result := &AssessmentResult{
		Target:    s.target,
		StartTime: time.Now(),
	}
	
	// Run all checks
	checks := []func(context.Context, *AssessmentResult){
		s.checkAnonymousAccess,
		s.checkAuthenticationMethods,
		s.checkAPIExposure,
		s.checkSwaggerExposure,
		s.checkTLSConfiguration,
		s.checkNTLMRelay,
		s.checkInformationDisclosure,
		s.checkRunbookExposure,
		s.checkCORS,
		s.checkHTTPMethods,
		s.checkServerHeaders,
		s.checkDefaultCredentials,
	}
	
	for _, check := range checks {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "assessment cancelled")
			result.EndTime = time.Now()
			return result, ctx.Err()
		default:
			check(ctx, result)
		}
	}
	
	result.EndTime = time.Now()
	return result, nil
}

// checkAnonymousAccess tests for unauthenticated access
func (s *SecurityAssessor) checkAnonymousAccess(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking anonymous access...")
	}
	
	endpoints := []struct {
		path string
		name string
	}{
		{"/Orchestrator2012/Orchestrator.svc/", "Legacy OData Service Root"},
		{"/Orchestrator2012/Orchestrator.svc/Runbooks", "Legacy Runbooks Endpoint"},
		{"/Orchestrator2012/Orchestrator.svc/RunbookServers", "Legacy Runbook Servers"},
		{"/api/runbooks", "Modern API Runbooks"},
		{"/api/", "Modern API Root"},
		{"/", "Web Console Root"},
	}
	
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+ep.path, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-ANON-001",
				Title:       fmt.Sprintf("Anonymous Access to %s", ep.name),
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("The endpoint %s is accessible without authentication", ep.path),
				Evidence:    fmt.Sprintf("HTTP %d - %s", resp.StatusCode, truncate(string(body), 200)),
				Remediation: "Enable Windows Authentication and disable Anonymous Authentication in IIS",
				References: []string{
					"https://learn.microsoft.com/en-us/system-center/orchestrator/install",
				},
			})
		}
	}
}

// checkAuthenticationMethods checks what auth methods are enabled
func (s *SecurityAssessor) checkAuthenticationMethods(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking authentication methods...")
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/Orchestrator2012/Orchestrator.svc/", nil)
	if err != nil {
		return
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	authHeaders := resp.Header.Values("WWW-Authenticate")
	
	for _, header := range authHeaders {
		lowerHeader := strings.ToLower(header)
		
		// Check for NTLM without Extended Protection
		if strings.HasPrefix(lowerHeader, "ntlm") {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-AUTH-001",
				Title:       "NTLM Authentication Enabled",
				Severity:    SeverityMedium,
				Description: "NTLM authentication is enabled on the web service. NTLM is vulnerable to relay attacks if EPA is not configured.",
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", header),
				Remediation: "Enable Extended Protection for Authentication (EPA) in IIS, or switch to Kerberos-only authentication",
				References: []string{
					"https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks",
					"https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know",
				},
			})
		}
		
		// Check for Negotiate (could be NTLM fallback)
		if strings.HasPrefix(lowerHeader, "negotiate") {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-AUTH-002",
				Title:       "Negotiate Authentication Enabled",
				Severity:    SeverityInfo,
				Description: "Negotiate (SPNEGO) authentication is enabled, which may fall back to NTLM if Kerberos fails",
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", header),
				Remediation: "Consider enforcing Kerberos-only authentication to prevent NTLM downgrade",
			})
		}
		
		// Check for Basic Auth (credentials in cleartext)
		if strings.HasPrefix(lowerHeader, "basic") {
			severity := SeverityHigh
			if s.useTLS {
				severity = SeverityMedium
			}
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-AUTH-003",
				Title:       "Basic Authentication Enabled",
				Severity:    severity,
				Description: "Basic authentication transmits credentials in Base64 encoding (essentially cleartext)",
				Evidence:    fmt.Sprintf("WWW-Authenticate: %s", header),
				Remediation: "Disable Basic authentication and use Windows Integrated Authentication with HTTPS",
			})
		}
	}
}

// checkAPIExposure checks API endpoints for sensitive information
func (s *SecurityAssessor) checkAPIExposure(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking API exposure...")
	}
	
	// Check for OData $metadata exposure
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/Orchestrator2012/Orchestrator.svc/$metadata", nil)
	if err != nil {
		return
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		
		// Check if it's actual EDMX schema
		if strings.Contains(string(body), "edmx") || strings.Contains(string(body), "EntitySet") {
			result.APIVersion = "Legacy OData"
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-API-001",
				Title:       "OData Metadata Exposed",
				Severity:    SeverityLow,
				Description: "The OData $metadata endpoint is accessible, exposing the API schema",
				Evidence:    truncate(string(body), 300),
				Remediation: "This is expected behavior but ensure authentication is properly enforced",
			})
		}
	}
	
	// Check for modern API swagger
	swaggerEndpoints := []string{"/swagger", "/swagger/index.html", "/api/swagger.json"}
	for _, ep := range swaggerEndpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+ep, nil)
		if err != nil {
			continue
		}
		
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			result.APIVersion = "Modern JSON API"
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-API-002",
				Title:       "Swagger/OpenAPI Specification Exposed",
				Severity:    SeverityLow,
				Description: fmt.Sprintf("The Swagger documentation is accessible at %s", ep),
				Evidence:    truncate(string(body), 200),
				Remediation: "Consider restricting Swagger access in production environments",
			})
			break
		}
	}
}

// checkSwaggerExposure is covered by checkAPIExposure
func (s *SecurityAssessor) checkSwaggerExposure(ctx context.Context, result *AssessmentResult) {
	// Covered by checkAPIExposure
}

// checkTLSConfiguration checks TLS settings
func (s *SecurityAssessor) checkTLSConfiguration(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking TLS configuration...")
	}
	
	// Check if HTTPS is available
	if !s.useTLS {
		// Try HTTPS on standard ports
		httpsURL := fmt.Sprintf("https://%s:%d/", s.target, s.port)
		req, err := http.NewRequestWithContext(ctx, "GET", httpsURL, nil)
		if err == nil {
			resp, err := s.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
				// HTTPS is available but we're using HTTP
				result.Findings = append(result.Findings, Finding{
					ID:          "SCORCH-TLS-001",
					Title:       "HTTPS Available but HTTP in Use",
					Severity:    SeverityMedium,
					Description: "HTTPS is available on the target but the service is accessible over HTTP",
					Remediation: "Redirect all HTTP traffic to HTTPS",
				})
			}
		}
		
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-TLS-002",
			Title:       "HTTP (Unencrypted) Access",
			Severity:    SeverityHigh,
			Description: "The SCORCH web service is accessible over unencrypted HTTP",
			Remediation: "Enable HTTPS and disable HTTP access. Ensure HSTS is configured.",
		})
	} else {
		// Check TLS version
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: s.timeout},
			"tcp",
			fmt.Sprintf("%s:%d", s.target, s.port),
			&tls.Config{InsecureSkipVerify: true},
		)
		if err == nil {
			defer conn.Close()
			state := conn.ConnectionState()
			
			tlsVersion := "Unknown"
			switch state.Version {
			case tls.VersionTLS10:
				tlsVersion = "TLS 1.0"
				result.Findings = append(result.Findings, Finding{
					ID:          "SCORCH-TLS-003",
					Title:       "Weak TLS Version (TLS 1.0)",
					Severity:    SeverityHigh,
					Description: "TLS 1.0 is deprecated and vulnerable to BEAST, POODLE, and other attacks",
					Evidence:    fmt.Sprintf("Negotiated: %s", tlsVersion),
					Remediation: "Disable TLS 1.0 and 1.1, enforce TLS 1.2 or higher",
				})
			case tls.VersionTLS11:
				tlsVersion = "TLS 1.1"
				result.Findings = append(result.Findings, Finding{
					ID:          "SCORCH-TLS-004",
					Title:       "Deprecated TLS Version (TLS 1.1)",
					Severity:    SeverityMedium,
					Description: "TLS 1.1 is deprecated and should be disabled",
					Evidence:    fmt.Sprintf("Negotiated: %s", tlsVersion),
					Remediation: "Disable TLS 1.1, enforce TLS 1.2 or higher",
				})
			case tls.VersionTLS12:
				tlsVersion = "TLS 1.2"
			case tls.VersionTLS13:
				tlsVersion = "TLS 1.3"
			}
			
			result.ServerInfo = fmt.Sprintf("TLS Version: %s, Cipher: 0x%04x", tlsVersion, state.CipherSuite)
		}
	}
}

// checkNTLMRelay checks for NTLM relay vulnerability indicators
func (s *SecurityAssessor) checkNTLMRelay(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking NTLM relay attack surface...")
	}
	
	// Check if EPA (Extended Protection for Authentication) is enabled
	// This is indicated by presence of CBT (Channel Binding Token) in NTLM response
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/Orchestrator2012/Orchestrator.svc/", nil)
	if err != nil {
		return
	}
	
	// Send NTLM Type 1 message to check for Type 2 response
	ntlmNegotiate := "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw==" // Basic Type 1
	req.Header.Set("Authorization", "NTLM "+ntlmNegotiate)
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusUnauthorized {
		authHeader := resp.Header.Get("WWW-Authenticate")
		if strings.HasPrefix(authHeader, "NTLM ") {
			// Got NTLM challenge - server accepts NTLM
			// Check if it's over HTTP (relay possible)
			if !s.useTLS {
				result.Findings = append(result.Findings, Finding{
					ID:          "SCORCH-RELAY-001",
					Title:       "Potential NTLM Relay Attack Surface",
					Severity:    SeverityHigh,
					Description: "NTLM authentication over HTTP allows credential relay attacks. An attacker in a man-in-the-middle position can relay captured credentials.",
					Evidence:    "NTLM negotiation successful over HTTP",
					Remediation: "Enable HTTPS with Extended Protection for Authentication (EPA), or switch to Kerberos-only authentication",
					References: []string{
						"https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know",
						"https://attack.mitre.org/techniques/T1557/001/",
					},
				})
			}
		}
	}
}

// checkInformationDisclosure checks for information leakage
func (s *SecurityAssessor) checkInformationDisclosure(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking information disclosure...")
	}
	
	// Check for version disclosure in headers
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/", nil)
	if err != nil {
		return
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Check Server header
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-INFO-001",
			Title:       "Server Version Disclosure",
			Severity:    SeverityLow,
			Description: "The Server header discloses version information",
			Evidence:    fmt.Sprintf("Server: %s", serverHeader),
			Remediation: "Configure IIS to suppress or customize the Server header",
		})
	}
	
	// Check X-Powered-By
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-INFO-002",
			Title:       "X-Powered-By Header Present",
			Severity:    SeverityLow,
			Description: "The X-Powered-By header discloses technology information",
			Evidence:    fmt.Sprintf("X-Powered-By: %s", poweredBy),
			Remediation: "Remove the X-Powered-By header in IIS configuration",
		})
	}
	
	// Check X-AspNet-Version
	aspNetVersion := resp.Header.Get("X-AspNet-Version")
	if aspNetVersion != "" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-INFO-003",
			Title:       "ASP.NET Version Disclosure",
			Severity:    SeverityLow,
			Description: "The X-AspNet-Version header discloses the ASP.NET version",
			Evidence:    fmt.Sprintf("X-AspNet-Version: %s", aspNetVersion),
			Remediation: "Add <httpRuntime enableVersionHeader=\"false\" /> to web.config",
		})
	}
}

// checkRunbookExposure checks if runbook details are exposed
func (s *SecurityAssessor) checkRunbookExposure(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking runbook exposure...")
	}
	
	// Try to enumerate runbooks without auth
	endpoints := []string{
		"/Orchestrator2012/Orchestrator.svc/Runbooks",
		"/api/runbooks",
	}
	
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+ep, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK && len(body) > 0 {
			// Count runbooks exposed
			runbookPattern := regexp.MustCompile(`(?i)"name"\s*:\s*"[^"]+"|<d:Name>([^<]+)</d:Name>`)
			matches := runbookPattern.FindAllString(string(body), -1)
			
			if len(matches) > 0 {
				result.Findings = append(result.Findings, Finding{
					ID:          "SCORCH-RUNBOOK-001",
					Title:       "Runbooks Enumerable Without Authentication",
					Severity:    SeverityCritical,
					Description: fmt.Sprintf("Runbooks can be enumerated without authentication. Found %d runbook references.", len(matches)),
					Evidence:    truncate(string(body), 500),
					Remediation: "Enable authentication on the Orchestrator web service",
				})
			}
		}
	}
}

// checkCORS checks for CORS misconfiguration
func (s *SecurityAssessor) checkCORS(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking CORS configuration...")
	}
	
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", s.baseURL()+"/api/runbooks", nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", "https://evil.attacker.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin == "*" || allowOrigin == "https://evil.attacker.com" {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-CORS-001",
			Title:       "Permissive CORS Configuration",
			Severity:    SeverityMedium,
			Description: "The CORS policy allows requests from arbitrary origins",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin),
			Remediation: "Restrict CORS to trusted origins only",
		})
	}
	
	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	if allowCreds == "true" && (allowOrigin == "*" || allowOrigin == "https://evil.attacker.com") {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-CORS-002",
			Title:       "CORS Allows Credentials with Permissive Origin",
			Severity:    SeverityHigh,
			Description: "CORS configuration allows credentials with a permissive or reflected origin, enabling credential theft via malicious sites",
			Evidence:    fmt.Sprintf("Allow-Origin: %s, Allow-Credentials: %s", allowOrigin, allowCreds),
			Remediation: "Never use Allow-Credentials: true with wildcard or reflected origins",
		})
	}
}

// checkHTTPMethods checks for dangerous HTTP methods
func (s *SecurityAssessor) checkHTTPMethods(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking HTTP methods...")
	}
	
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", s.baseURL()+"/", nil)
	if err != nil {
		return
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	allowMethods := resp.Header.Get("Allow")
	if allowMethods != "" {
		dangerousMethods := []string{"TRACE", "TRACK", "DEBUG", "PUT", "DELETE"}
		var foundDangerous []string
		
		for _, method := range dangerousMethods {
			if strings.Contains(strings.ToUpper(allowMethods), method) {
				foundDangerous = append(foundDangerous, method)
			}
		}
		
		if len(foundDangerous) > 0 {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-HTTP-001",
				Title:       "Dangerous HTTP Methods Enabled",
				Severity:    SeverityMedium,
				Description: fmt.Sprintf("Potentially dangerous HTTP methods are enabled: %s", strings.Join(foundDangerous, ", ")),
				Evidence:    fmt.Sprintf("Allow: %s", allowMethods),
				Remediation: "Disable unnecessary HTTP methods in IIS request filtering",
			})
		}
	}
}

// checkServerHeaders checks for missing security headers
func (s *SecurityAssessor) checkServerHeaders(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking security headers...")
	}
	
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/", nil)
	if err != nil {
		return
	}
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	securityHeaders := map[string]string{
		"X-Frame-Options":           "Prevents clickjacking attacks",
		"X-Content-Type-Options":    "Prevents MIME-type sniffing",
		"Strict-Transport-Security": "Enforces HTTPS (HSTS)",
		"Content-Security-Policy":   "Prevents XSS and injection attacks",
		"X-XSS-Protection":          "Legacy XSS protection",
	}
	
	var missing []string
	for header, desc := range securityHeaders {
		if resp.Header.Get(header) == "" {
			missing = append(missing, fmt.Sprintf("%s (%s)", header, desc))
		}
	}
	
	if len(missing) > 0 {
		result.Findings = append(result.Findings, Finding{
			ID:          "SCORCH-HEADER-001",
			Title:       "Missing Security Headers",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("The following security headers are missing: %s", strings.Join(missing, "; ")),
			Remediation: "Configure IIS or the application to include standard security headers",
		})
	}
}

// checkDefaultCredentials checks for default/common credentials
func (s *SecurityAssessor) checkDefaultCredentials(ctx context.Context, result *AssessmentResult) {
	if s.debug {
		fmt.Println("[*] Checking default credentials...")
	}
	
	// Common default/weak credentials to test
	// Be careful with this - only test in authorized assessments
	testCreds := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
		{"administrator", "administrator"},
		{"orchestrator", "orchestrator"},
		{"scorch", "scorch"},
	}
	
	for _, cred := range testCreds {
		req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL()+"/Orchestrator2012/Orchestrator.svc/", nil)
		if err != nil {
			continue
		}
		
		req.SetBasicAuth(cred.user, cred.pass)
		
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			result.Findings = append(result.Findings, Finding{
				ID:          "SCORCH-CRED-001",
				Title:       "Default Credentials Accepted",
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("Default credentials (%s:%s) are accepted", cred.user, "****"),
				Remediation: "Change default passwords immediately and implement strong password policies",
			})
			break // Don't continue testing after finding valid creds
		}
	}
}

// Helper function to truncate strings
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ODataServiceDocument represents the OData service document
type ODataServiceDocument struct {
	XMLName    xml.Name `xml:"service"`
	Workspaces []struct {
		Title       string `xml:"title"`
		Collections []struct {
			Href  string `xml:"href,attr"`
			Title string `xml:"title"`
		} `xml:"collection"`
	} `xml:"workspace"`
}

// ParseODataServiceDocument parses an OData service document
func ParseODataServiceDocument(data []byte) (*ODataServiceDocument, error) {
	var doc ODataServiceDocument
	err := xml.Unmarshal(data, &doc)
	return &doc, err
}
