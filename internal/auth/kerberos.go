package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// KerberosConfig holds Kerberos authentication configuration
type KerberosConfig struct {
	Realm       string
	KDCAddress  string
	Username    string
	Password    string
	Keytab      string // Path to keytab file
	CCache      string // Path to credential cache file
	SPN         string // Service Principal Name for target service
}

// KerberosClient wraps gokrb5 client for HTTP authentication
type KerberosClient struct {
	client    *client.Client
	spnPrefix string
}

// NewKerberosClient creates a new Kerberos client
func NewKerberosClient(cfg *KerberosConfig) (*KerberosClient, error) {
	// Try to load krb5.conf
	krb5Cfg, err := loadKrb5Config(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load Kerberos config: %w", err)
	}

	var cl *client.Client

	// Priority: CCache > Keytab > Password
	if cfg.CCache != "" {
		// Load from credential cache (kinit'd ticket)
		ccache, err := credentials.LoadCCache(cfg.CCache)
		if err != nil {
			return nil, fmt.Errorf("failed to load ccache %s: %w", cfg.CCache, err)
		}
		cl, err = client.NewFromCCache(ccache, krb5Cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create client from ccache: %w", err)
		}
	} else if cfg.Keytab != "" {
		// Load from keytab file
		kt, err := loadKeytab(cfg.Keytab)
		if err != nil {
			return nil, fmt.Errorf("failed to load keytab %s: %w", cfg.Keytab, err)
		}
		cl = client.NewWithKeytab(cfg.Username, cfg.Realm, kt, krb5Cfg)
	} else if cfg.Password != "" {
		// Use password
		cl = client.NewWithPassword(cfg.Username, cfg.Realm, cfg.Password, krb5Cfg)
	} else {
		return nil, fmt.Errorf("no Kerberos credentials provided (password, keytab, or ccache required)")
	}

	// Login (get TGT)
	err = cl.Login()
	if err != nil {
		return nil, fmt.Errorf("Kerberos login failed: %w", err)
	}

	return &KerberosClient{
		client:    cl,
		spnPrefix: "HTTP",
	}, nil
}

// loadKrb5Config loads Kerberos configuration
func loadKrb5Config(cfg *KerberosConfig) (*config.Config, error) {
	// Try standard locations
	paths := []string{
		"/etc/krb5.conf",
		"/etc/krb5/krb5.conf",
		os.Getenv("KRB5_CONFIG"),
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return config.Load(path)
		}
	}

	// Generate minimal config from provided settings
	if cfg.Realm != "" && cfg.KDCAddress != "" {
		confStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  %s = {
    kdc = %s
    admin_server = %s
  }
`, cfg.Realm, cfg.Realm, cfg.KDCAddress, cfg.KDCAddress)

		return config.NewFromString(confStr)
	}

	return nil, fmt.Errorf("no krb5.conf found and no realm/KDC specified")
}

// loadKeytab loads a keytab file
func loadKeytab(path string) (*keytab.Keytab, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load keytab: %w", err)
	}
	return kt, nil
}

// GetSPNEGOToken gets a SPNEGO token for the target service
func (k *KerberosClient) GetSPNEGOToken(targetHost string) (string, error) {
	// Build SPN: HTTP/hostname
	spn := fmt.Sprintf("%s/%s", k.spnPrefix, targetHost)

	// Get service ticket
	ticket, key, err := k.client.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("failed to get service ticket for %s: %w", spn, err)
	}

	// Create SPNEGO token
	spnegoClient := spnego.SPNEGOClient(k.client, spn)
	_ = spnegoClient // Avoid unused variable

	// Build the AP-REQ
	apreq, err := spnego.NewKRB5TokenAPREQ(k.client, ticket, key, []int{}, []int{})
	if err != nil {
		return "", fmt.Errorf("failed to create AP-REQ: %w", err)
	}

	// Marshal and encode
	tokenBytes, err := apreq.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

// RoundTrip implements http.RoundTripper for Kerberos authentication
func (k *KerberosClient) RoundTrip(req *http.Request) (*http.Response, error) {
	// Extract hostname from request
	host := req.URL.Hostname()

	// Get SPNEGO token
	token, err := k.GetSPNEGOToken(host)
	if err != nil {
		return nil, err
	}

	// Set Authorization header
	req.Header.Set("Authorization", "Negotiate "+token)

	// Use default transport
	return http.DefaultTransport.RoundTrip(req)
}

// Close cleans up Kerberos resources
func (k *KerberosClient) Close() {
	if k.client != nil {
		k.client.Destroy()
	}
}
