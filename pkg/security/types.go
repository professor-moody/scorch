package security

import (
	"time"
)

// Severity levels for findings
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
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

// FindingCategory categorizes security findings
type FindingCategory string

const (
	CategoryAuthentication   FindingCategory = "AUTHENTICATION"
	CategoryAuthorization    FindingCategory = "AUTHORIZATION"
	CategoryConfiguration    FindingCategory = "CONFIGURATION"
	CategoryCryptography     FindingCategory = "CRYPTOGRAPHY"
	CategoryInformationLeak  FindingCategory = "INFORMATION_DISCLOSURE"
	CategoryInjection        FindingCategory = "INJECTION"
	CategoryMisconfiguration FindingCategory = "MISCONFIGURATION"
)

// Finding represents a security vulnerability or misconfiguration
type Finding struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    FindingCategory `json:"category"`
	Severity    Severity        `json:"severity"`
	Evidence    string          `json:"evidence,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	References  []string        `json:"references,omitempty"`
	CVSS        float64         `json:"cvss,omitempty"`
	CWE         string          `json:"cwe,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// SecurityAssessment holds the complete assessment results
type SecurityAssessment struct {
	Target            string           `json:"target"`
	StartTime         time.Time        `json:"start_time"`
	EndTime           time.Time        `json:"end_time"`
	Findings          []Finding        `json:"findings"`
	APIInfo           *APISecurityInfo `json:"api_info,omitempty"`
	AuthInfo          *AuthInfo        `json:"auth_info,omitempty"`
	ServiceInfo       *ServiceInfo     `json:"service_info,omitempty"`
	Summary           AssessmentSummary `json:"summary"`
}

// AssessmentSummary provides quick stats
type AssessmentSummary struct {
	TotalFindings   int `json:"total_findings"`
	CriticalCount   int `json:"critical_count"`
	HighCount       int `json:"high_count"`
	MediumCount     int `json:"medium_count"`
	LowCount        int `json:"low_count"`
	InfoCount       int `json:"info_count"`
}

// APISecurityInfo holds API-specific security information
type APISecurityInfo struct {
	Version              string   `json:"version"`
	BaseURL              string   `json:"base_url"`
	UsesHTTPS            bool     `json:"uses_https"`
	CertificateValid     bool     `json:"certificate_valid,omitempty"`
	CertificateIssuer    string   `json:"certificate_issuer,omitempty"`
	CertificateExpiry    string   `json:"certificate_expiry,omitempty"`
	SelfSignedCert       bool     `json:"self_signed_cert,omitempty"`
	AuthMethods          []string `json:"auth_methods"`
	AnonymousAccess      bool     `json:"anonymous_access"`
	SwaggerExposed       bool     `json:"swagger_exposed"`
	SwaggerURL           string   `json:"swagger_url,omitempty"`
	CORSEnabled          bool     `json:"cors_enabled"`
	CORSAllowOrigin      string   `json:"cors_allow_origin,omitempty"`
	ServerHeader         string   `json:"server_header,omitempty"`
	PoweredByHeader      string   `json:"powered_by_header,omitempty"`
	VerboseErrors        bool     `json:"verbose_errors"`
	ExtendedProtection   bool     `json:"extended_protection"`
}

// AuthInfo holds authentication-related security info
type AuthInfo struct {
	WindowsAuthEnabled   bool     `json:"windows_auth_enabled"`
	BasicAuthEnabled     bool     `json:"basic_auth_enabled"`
	AnonymousEnabled     bool     `json:"anonymous_enabled"`
	NTLMEnabled          bool     `json:"ntlm_enabled"`
	KerberosEnabled      bool     `json:"kerberos_enabled"`
	NegotiateEnabled     bool     `json:"negotiate_enabled"`
	ExtendedProtection   string   `json:"extended_protection"` // None, Allow, Require
	ChannelBinding       bool     `json:"channel_binding"`
	SupportedProviders   []string `json:"supported_providers"`
	RequiredPrivileges   []string `json:"required_privileges,omitempty"`
}

// ServiceInfo holds service-level information
type ServiceInfo struct {
	HostName              string    `json:"host_name"`
	OSVersion             string    `json:"os_version,omitempty"`
	IISVersion            string    `json:"iis_version,omitempty"`
	DotNetVersion         string    `json:"dotnet_version,omitempty"`
	SCORCHVersion         string    `json:"scorch_version,omitempty"`
	RunbookServers        []string  `json:"runbook_servers,omitempty"`
	DatabaseServer        string    `json:"database_server,omitempty"`
	ServiceAccount        string    `json:"service_account,omitempty"`
	LastHeartbeat         time.Time `json:"last_heartbeat,omitempty"`
}

// VulnerabilityCheck defines a security check to perform
type VulnerabilityCheck struct {
	ID          string
	Name        string
	Description string
	Category    FindingCategory
	CheckFunc   func(ctx interface{}) (*Finding, error)
}

// Predefined vulnerability IDs
const (
	VulnAnonymousAPIAccess      = "SCORCH-001"
	VulnHTTPCleartext           = "SCORCH-002"
	VulnSelfSignedCertificate   = "SCORCH-003"
	VulnSwaggerExposed          = "SCORCH-004"
	VulnVerboseErrors           = "SCORCH-005"
	VulnWeakAuthConfig          = "SCORCH-006"
	VulnMissingEPA              = "SCORCH-007"
	VulnNTLMRelayable           = "SCORCH-008"
	VulnCORSMisconfiguration    = "SCORCH-009"
	VulnDefaultCredentials      = "SCORCH-010"
	VulnSensitiveDataExposure   = "SCORCH-011"
	VulnExcessivePermissions    = "SCORCH-012"
	VulnJobOutputLeakage        = "SCORCH-013"
	VulnParameterInjection      = "SCORCH-014"
	VulnCredentialInRunbook     = "SCORCH-015"
	VulnUnencryptedDBConnection = "SCORCH-016"
	VulnWeakEncryptionKeys      = "SCORCH-017"
	VulnAuthCacheBypass         = "SCORCH-018"
	VulnServiceAccountOverpriv  = "SCORCH-019"
	VulnAuditLoggingDisabled    = "SCORCH-020"
)

// Predefined findings templates
var FindingTemplates = map[string]Finding{
	VulnAnonymousAPIAccess: {
		ID:          VulnAnonymousAPIAccess,
		Title:       "Anonymous API Access Enabled",
		Description: "The SCORCH web service API allows unauthenticated access. This permits any network user to enumerate runbooks, view job history, and potentially execute runbooks.",
		Category:    CategoryAuthentication,
		Severity:    SeverityCritical,
		Remediation: "Disable anonymous authentication in IIS and ensure Windows Authentication is required for all API endpoints.",
		CWE:         "CWE-306",
		CVSS:        9.8,
	},
	VulnHTTPCleartext: {
		ID:          VulnHTTPCleartext,
		Title:       "API Accessible Over Unencrypted HTTP",
		Description: "The SCORCH web service is accessible over unencrypted HTTP. Credentials and sensitive data transmitted to the API can be intercepted via network sniffing or man-in-the-middle attacks.",
		Category:    CategoryCryptography,
		Severity:    SeverityHigh,
		Remediation: "Configure IIS to require HTTPS and redirect all HTTP traffic to HTTPS. Install a valid TLS certificate.",
		CWE:         "CWE-319",
		CVSS:        7.5,
	},
	VulnSelfSignedCertificate: {
		ID:          VulnSelfSignedCertificate,
		Title:       "Self-Signed TLS Certificate in Use",
		Description: "The SCORCH web service uses a self-signed TLS certificate. This makes the service vulnerable to man-in-the-middle attacks as clients may ignore certificate warnings.",
		Category:    CategoryCryptography,
		Severity:    SeverityMedium,
		Remediation: "Replace the self-signed certificate with a certificate from a trusted Certificate Authority.",
		CWE:         "CWE-295",
		CVSS:        5.9,
	},
	VulnSwaggerExposed: {
		ID:          VulnSwaggerExposed,
		Title:       "Swagger/OpenAPI Documentation Exposed",
		Description: "The SCORCH API Swagger documentation is publicly accessible. This provides attackers with detailed API specifications including endpoints, parameters, and data models.",
		Category:    CategoryInformationLeak,
		Severity:    SeverityLow,
		Remediation: "Restrict access to /swagger endpoint or disable Swagger in production environments.",
		CWE:         "CWE-200",
		CVSS:        3.7,
	},
	VulnVerboseErrors: {
		ID:          VulnVerboseErrors,
		Title:       "Verbose Error Messages Enabled",
		Description: "The API returns detailed error messages including stack traces, internal paths, and database information. This aids attackers in understanding the system architecture.",
		Category:    CategoryInformationLeak,
		Severity:    SeverityMedium,
		Remediation: "Configure custom error pages and disable detailed error messages in production.",
		CWE:         "CWE-209",
		CVSS:        5.3,
	},
	VulnMissingEPA: {
		ID:          VulnMissingEPA,
		Title:       "Extended Protection for Authentication Not Configured",
		Description: "Extended Protection for Authentication (EPA) is not enabled on the IIS web service. This makes the service vulnerable to NTLM relay attacks.",
		Category:    CategoryAuthentication,
		Severity:    SeverityHigh,
		Remediation: "Enable Extended Protection for Authentication in IIS with 'Required' setting. Enable channel binding tokens.",
		CWE:         "CWE-294",
		CVSS:        8.1,
		References: []string{
			"https://support.microsoft.com/kb/5005413",
			"https://posts.specterops.io/the-renaissance-of-ntlm-relay-attacks",
		},
	},
	VulnNTLMRelayable: {
		ID:          VulnNTLMRelayable,
		Title:       "NTLM Authentication Vulnerable to Relay Attacks",
		Description: "The service accepts NTLM authentication without Extended Protection or channel binding. Captured NTLM authentication can be relayed to other services.",
		Category:    CategoryAuthentication,
		Severity:    SeverityHigh,
		Remediation: "Enable EPA, enforce SMB signing, and consider disabling NTLM in favor of Kerberos authentication.",
		CWE:         "CWE-294",
		CVSS:        8.1,
	},
	VulnCredentialInRunbook: {
		ID:          VulnCredentialInRunbook,
		Title:       "Hardcoded Credentials in Runbook Activities",
		Description: "Runbooks contain hardcoded credentials in activity configurations. These credentials can be extracted by users with runbook read access.",
		Category:    CategoryConfiguration,
		Severity:    SeverityHigh,
		Remediation: "Use encrypted global variables or credential store integration instead of hardcoding credentials in runbooks.",
		CWE:         "CWE-798",
		CVSS:        7.5,
	},
	VulnServiceAccountOverpriv: {
		ID:          VulnServiceAccountOverpriv,
		Title:       "SCORCH Service Account Has Excessive Privileges",
		Description: "The Orchestrator service account has Domain Admin or equivalent privileges. Compromise of SCORCH would provide full domain access.",
		Category:    CategoryAuthorization,
		Severity:    SeverityCritical,
		Remediation: "Apply principle of least privilege. Create dedicated service accounts with only required permissions.",
		CWE:         "CWE-250",
		CVSS:        9.0,
	},
	VulnJobOutputLeakage: {
		ID:          VulnJobOutputLeakage,
		Title:       "Sensitive Data Exposed in Job Output",
		Description: "Runbook job outputs contain sensitive information such as credentials, internal paths, or configuration data accessible to operators.",
		Category:    CategoryInformationLeak,
		Severity:    SeverityMedium,
		Remediation: "Sanitize job outputs. Use secure credential handling that doesn't log sensitive values.",
		CWE:         "CWE-532",
		CVSS:        5.3,
	},
}

// NTLMRelayTarget represents a potential relay target
type NTLMRelayTarget struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Service     string `json:"service"` // HTTP, LDAP, SMB, etc.
	EPAEnabled  bool   `json:"epa_enabled"`
	Signing     string `json:"signing"` // disabled, optional, required
	Relayable   bool   `json:"relayable"`
	Notes       string `json:"notes,omitempty"`
}

// CoercionVector represents an authentication coercion opportunity
type CoercionVector struct {
	Type        string `json:"type"` // WebDAV, Runbook, API
	Endpoint    string `json:"endpoint"`
	Description string `json:"description"`
	Exploitable bool   `json:"exploitable"`
}
