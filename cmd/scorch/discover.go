package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// DiscoveryResult holds all discovery findings
type DiscoveryResult struct {
	Target      string         `json:"target"`
	Timestamp   string         `json:"timestamp"`
	OpenPorts   []PortResult   `json:"open_ports,omitempty"`
	LDAPResults *LDAPDiscovery `json:"ldap_results,omitempty"`
	SPNs        []SPNResult    `json:"spns,omitempty"`
	Errors      []string       `json:"errors,omitempty"`
}

// PortResult represents a discovered port
type PortResult struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	State      string `json:"state"`
	Banner     string `json:"banner,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
}

// LDAPDiscovery holds LDAP enumeration results
type LDAPDiscovery struct {
	BaseDN          string         `json:"base_dn,omitempty"`
	DomainName      string         `json:"domain_name,omitempty"`
	ServiceAccounts []LDAPAccount  `json:"service_accounts,omitempty"`
	Computers       []LDAPComputer `json:"computers,omitempty"`
	Groups          []LDAPGroup    `json:"groups,omitempty"`
}

// LDAPAccount represents a service account
type LDAPAccount struct {
	DN          string   `json:"dn"`
	SAMAccount  string   `json:"sam_account"`
	AccountType string   `json:"account_type,omitempty"` // user, gMSA, MSA
	DisplayName string   `json:"display_name,omitempty"`
	Description string   `json:"description,omitempty"`
	SPNs        []string `json:"spns,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
	LastLogon   string   `json:"last_logon,omitempty"`
	WhenCreated string   `json:"when_created,omitempty"`
}

// LDAPComputer represents a computer object
type LDAPComputer struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	DNSHostName string   `json:"dns_hostname,omitempty"`
	OS          string   `json:"os,omitempty"`
	OSVersion   string   `json:"os_version,omitempty"`
	Description string   `json:"description,omitempty"`
	SPNs        []string `json:"spns,omitempty"`
}

// LDAPGroup represents an AD group
type LDAPGroup struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
}

// SPNResult represents a discovered SPN
type SPNResult struct {
	SPN          string `json:"spn"`
	ServiceClass string `json:"service_class"`
	Host         string `json:"host"`
	Port         string `json:"port,omitempty"`
	AccountName  string `json:"account_name"`
	AccountType  string `json:"account_type"` // user or computer
}

func runDiscover(args []string) error {
	if containsHelp(args) {
		printDiscoverHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	// Parse discover-specific flags
	scanPorts, remaining := parseBoolFlag(remaining, "-ports", "--ports")
	scanLDAP, remaining := parseBoolFlag(remaining, "-ldap", "--ldap")
	scanSPN, remaining := parseBoolFlag(remaining, "-spn", "--spn")
	all, remaining := parseBoolFlag(remaining, "-all", "--all")
	ldapServer, remaining := parseFlag(remaining, "-dc", "-ldap-server", "--ldap-server")
	baseDN, _ := parseFlag(remaining, "-base-dn", "--base-dn")

	if all {
		scanPorts = true
		scanLDAP = true
		scanSPN = true
	}

	// Default to port scan if nothing specified
	if !scanPorts && !scanLDAP && !scanSPN {
		scanPorts = true
	}

	if opts.Target == "" {
		return fmt.Errorf("-target is required")
	}

	ctx, cancel := createContext(opts)
	defer cancel()

	printf(opts, "[*] Starting discovery for %s\n", opts.Target)

	result := &DiscoveryResult{
		Target:    opts.Target,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Port scanning
	if scanPorts {
		printf(opts, "[*] Scanning SCORCH-related ports...\n")
		result.OpenPorts = scanSCORCHPorts(ctx, opts)
		printf(opts, "[+] Found %d open ports\n", len(result.OpenPorts))
	}

	// LDAP enumeration
	if scanLDAP || scanSPN {
		if ldapServer == "" {
			ldapServer = opts.Target
		}

		if opts.Username == "" || (opts.Password == "" && opts.NTHash == "") {
			printf(opts, "[!] LDAP/SPN enumeration requires credentials (-u, -p or -H)\n")
		} else {
			if scanLDAP {
				printf(opts, "[*] Enumerating LDAP for SCORCH-related objects...\n")
				ldapResult, err := enumerateLDAP(ctx, opts, ldapServer, baseDN)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("LDAP: %v", err))
					debugf(opts, "LDAP error: %v", err)
				} else {
					result.LDAPResults = ldapResult
					printf(opts, "[+] Found %d service accounts, %d computers, %d groups\n",
						len(ldapResult.ServiceAccounts),
						len(ldapResult.Computers),
						len(ldapResult.Groups))
				}
			}

			if scanSPN {
				printf(opts, "[*] Discovering SCORCH-related SPNs...\n")
				spns, err := discoverSPNs(ctx, opts, ldapServer, baseDN)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("SPN: %v", err))
					debugf(opts, "SPN error: %v", err)
				} else {
					result.SPNs = spns
					printf(opts, "[+] Found %d SPNs\n", len(spns))
				}
			}
		}
	}

	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	if opts.JSON {
		return writeJSON(output, result)
	}

	printDiscoveryResults(output, result)
	return nil
}

// scanSCORCHPorts scans for SCORCH-related ports
func scanSCORCHPorts(ctx context.Context, opts *CommonOpts) []PortResult {
	ports := []struct {
		port    int
		service string
	}{
		{81, "SCORCH Web Service (OData/REST)"},
		{82, "SCORCH Web Console"},
		{443, "HTTPS"},
		{1433, "SQL Server"},
		{389, "LDAP"},
		{636, "LDAPS"},
		{88, "Kerberos"},
		{135, "RPC/DCOM"},
		{445, "SMB"},
		{5985, "WinRM HTTP"},
		{5986, "WinRM HTTPS"},
	}

	var results []PortResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 10) // Limit concurrent scans

	for _, p := range ports {
		wg.Add(1)
		go func(port int, service string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result := scanPort(ctx, opts.Target, port, service, opts.Timeout)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(p.port, p.service)
	}

	wg.Wait()
	return results
}

// scanPort scans a single port
func scanPort(ctx context.Context, host string, port int, service string, timeout time.Duration) *PortResult {
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}

	result := &PortResult{
		Port:    port,
		Service: service,
		State:   "open",
	}

	// Check for TLS on common HTTPS ports by upgrading the existing connection
	if port == 443 || port == 636 || port == 5986 {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := tlsConn.Handshake(); err == nil {
			state := tlsConn.ConnectionState()
			switch state.Version {
			case tls.VersionTLS10:
				result.TLSVersion = "TLS 1.0"
			case tls.VersionTLS11:
				result.TLSVersion = "TLS 1.1"
			case tls.VersionTLS12:
				result.TLSVersion = "TLS 1.2"
			case tls.VersionTLS13:
				result.TLSVersion = "TLS 1.3"
			}
		}
		tlsConn.Close()
		return result
	}

	// For non-TLS ports, try to grab banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := make([]byte, 256)
	n, err := conn.Read(banner)
	if err == nil && n > 0 {
		result.Banner = strings.TrimSpace(string(banner[:n]))
	}
	conn.Close()

	return result
}

// connectLDAP establishes an authenticated LDAP connection
func connectLDAP(opts *CommonOpts, ldapServer string) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:389", ldapServer)

	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", address))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Bind with credentials using UPN format (user@domain.fqdn)
	// LDAP simple bind requires UPN or full DN, not DOMAIN\user format
	bindDN := opts.Username

	// Determine the domain FQDN for UPN
	domainFQDN := ""
	if opts.Domain != "" {
		if strings.Contains(opts.Domain, ".") {
			// Already FQDN
			domainFQDN = opts.Domain
		} else {
			// NetBIOS name - use full ldapServer FQDN if available
			// Can't reliably derive FQDN from NetBIOS without DNS lookups
			if strings.Contains(ldapServer, ".") {
				domainFQDN = ldapServer
			} else {
				domainFQDN = opts.Domain
			}
		}
	} else if strings.Contains(ldapServer, ".") {
		// No domain specified, but server is FQDN
		// Use the full server name as domain - common when targeting a DC directly
		domainFQDN = ldapServer
	}

	if domainFQDN != "" {
		bindDN = fmt.Sprintf("%s@%s", opts.Username, domainFQDN)
	}

	debugf(opts, "LDAP bind DN: %s", bindDN)

	err = conn.Bind(bindDN, opts.Password)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	return conn, nil
}

// getDefaultNamingContext retrieves the default naming context from RootDSE
func getDefaultNamingContext(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(result.Entries) > 0 {
		return result.Entries[0].GetAttributeValue("defaultNamingContext"), nil
	}

	return "", fmt.Errorf("defaultNamingContext not found")
}

// enumerateLDAP performs LDAP enumeration for SCORCH-related objects
func enumerateLDAP(ctx context.Context, opts *CommonOpts, ldapServer, baseDN string) (*LDAPDiscovery, error) {
	conn, err := connectLDAP(opts, ldapServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	result := &LDAPDiscovery{}

	// Get base DN if not provided
	if baseDN == "" {
		baseDN, err = getDefaultNamingContext(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to get base DN: %w", err)
		}
	}
	result.BaseDN = baseDN

	// Extract domain name from base DN
	result.DomainName = baseDNToDomain(baseDN)

	// Search for SCORCH-related service accounts
	debugf(opts, "Searching for service accounts in %s", baseDN)
	accounts, err := searchLDAPUsers(conn, baseDN, opts)
	if err != nil {
		debugf(opts, "User search error: %v", err)
	} else {
		result.ServiceAccounts = accounts
	}

	// Search for SCORCH-related computers
	debugf(opts, "Searching for computers in %s", baseDN)
	computers, err := searchLDAPComputers(conn, baseDN, opts)
	if err != nil {
		debugf(opts, "Computer search error: %v", err)
	} else {
		result.Computers = computers
	}

	// Search for Orchestrator groups
	debugf(opts, "Searching for groups in %s", baseDN)
	groups, err := searchLDAPGroups(conn, baseDN, opts)
	if err != nil {
		debugf(opts, "Group search error: %v", err)
	} else {
		result.Groups = groups
	}

	return result, nil
}

// baseDNToDomain converts a base DN to domain format
func baseDNToDomain(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	var domains []string
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "dc=") {
			domains = append(domains, strings.TrimPrefix(strings.TrimPrefix(part, "DC="), "dc="))
		}
	}
	return strings.Join(domains, ".")
}

// searchLDAPUsers searches for SCORCH-related user accounts
func searchLDAPUsers(conn *ldap.Conn, baseDN string, opts *CommonOpts) ([]LDAPAccount, error) {
	// Search for accounts with SCORCH-related names, descriptions, or SPNs
	// Includes: regular users, service accounts, gMSA, MSA
	filter := `(&(|(objectClass=user)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))(|` +
		// Name patterns
		`(sAMAccountName=*orch*)(sAMAccountName=*scorch*)(sAMAccountName=*runbook*)` +
		`(sAMAccountName=sco_*)(sAMAccountName=svc_orch*)(sAMAccountName=svc_scorch*)` +
		// Description patterns
		`(description=*orchestrator*)(description=*scorch*)(description=*runbook*)` +
		// SPN patterns (HTTP on ports 81/82)
		`(servicePrincipalName=HTTP/*:81*)(servicePrincipalName=HTTP/*:82*)` +
		`))`

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName", "sAMAccountName", "displayName", "description", "servicePrincipalName", "memberOf", "whenCreated", "objectClass"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	var accounts []LDAPAccount
	for _, entry := range result.Entries {
		// Determine account type from objectClass
		accountType := "user"
		objectClasses := entry.GetAttributeValues("objectClass")
		for _, oc := range objectClasses {
			if strings.EqualFold(oc, "msDS-GroupManagedServiceAccount") {
				accountType = "gMSA"
				break
			} else if strings.EqualFold(oc, "msDS-ManagedServiceAccount") {
				accountType = "MSA"
				break
			}
		}

		acc := LDAPAccount{
			DN:          entry.DN,
			SAMAccount:  entry.GetAttributeValue("sAMAccountName"),
			AccountType: accountType,
			DisplayName: entry.GetAttributeValue("displayName"),
			Description: entry.GetAttributeValue("description"),
			SPNs:        entry.GetAttributeValues("servicePrincipalName"),
			MemberOf:    entry.GetAttributeValues("memberOf"),
			WhenCreated: entry.GetAttributeValue("whenCreated"),
		}
		accounts = append(accounts, acc)
	}

	return accounts, nil
}

// searchLDAPComputers searches for SCORCH-related computer objects
func searchLDAPComputers(conn *ldap.Conn, baseDN string, opts *CommonOpts) ([]LDAPComputer, error) {
	// Enhanced filter for computers with SCORCH patterns or relevant SPNs
	filter := `(&(objectClass=computer)(|` +
		// Name patterns
		`(name=*orch*)(name=*scorch*)(name=*runbook*)(name=*sco-*)(name=*sco_*)` +
		// Description patterns
		`(description=*orchestrator*)(description=*scorch*)(description=*runbook*)` +
		// SPN patterns (HTTP on ports 81/82, or MSSQLSvc for DB)
		`(servicePrincipalName=HTTP/*:81*)(servicePrincipalName=HTTP/*:82*)` +
		`))`

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName", "name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "description", "servicePrincipalName"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	var computers []LDAPComputer
	for _, entry := range result.Entries {
		comp := LDAPComputer{
			DN:          entry.DN,
			Name:        entry.GetAttributeValue("name"),
			DNSHostName: entry.GetAttributeValue("dNSHostName"),
			OS:          entry.GetAttributeValue("operatingSystem"),
			OSVersion:   entry.GetAttributeValue("operatingSystemVersion"),
			Description: entry.GetAttributeValue("description"),
			SPNs:        entry.GetAttributeValues("servicePrincipalName"),
		}
		computers = append(computers, comp)
	}

	return computers, nil
}

// searchLDAPGroups searches for Orchestrator groups
func searchLDAPGroups(conn *ldap.Conn, baseDN string, opts *CommonOpts) ([]LDAPGroup, error) {
	// Enhanced filter including built-in Orchestrator groups
	filter := `(&(objectClass=group)(|` +
		// Built-in Orchestrator groups
		`(name=OrchestratorSystemGroup)(name=OrchestratorUsersGroup)(name=OrchestratorRemoteConsoleUsers)` +
		`(name=Orchestrator Users)(name=Orchestrator Admins)(name=Orchestrator Operators)` +
		// Pattern-based matches
		`(name=*Orchestrator*)(name=*SCORCH*)(name=*Runbook*)` +
		// Description patterns
		`(description=*orchestrator*)(description=*scorch*)(description=*runbook*)` +
		`))`

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"distinguishedName", "name", "description", "member"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	var groups []LDAPGroup
	for _, entry := range result.Entries {
		grp := LDAPGroup{
			DN:          entry.DN,
			Name:        entry.GetAttributeValue("name"),
			Description: entry.GetAttributeValue("description"),
			Members:     entry.GetAttributeValues("member"),
		}
		groups = append(groups, grp)
	}

	return groups, nil
}

// discoverSPNs discovers SCORCH-related Service Principal Names
func discoverSPNs(ctx context.Context, opts *CommonOpts, ldapServer, baseDN string) ([]SPNResult, error) {
	conn, err := connectLDAP(opts, ldapServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get base DN if not provided
	if baseDN == "" {
		baseDN, err = getDefaultNamingContext(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to get base DN: %w", err)
		}
	}

	// Search for SPNs matching SCORCH patterns
	// HTTP/* - Web services
	// MSSQLSvc/* - SQL Server (Orchestrator database)
	filters := []struct {
		filter      string
		accountType string
	}{
		{"(&(objectClass=user)(servicePrincipalName=HTTP/*))", "user"},
		{"(&(objectClass=user)(servicePrincipalName=MSSQLSvc/*))", "user"},
		{"(&(objectClass=computer)(servicePrincipalName=HTTP/*))", "computer"},
	}

	var allSPNs []SPNResult

	for _, f := range filters {
		searchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			f.filter,
			[]string{"distinguishedName", "sAMAccountName", "servicePrincipalName"},
			nil,
		)

		result, err := conn.Search(searchRequest)
		if err != nil {
			debugf(opts, "SPN search error for %s: %v", f.filter, err)
			continue
		}

		for _, entry := range result.Entries {
			accountName := entry.GetAttributeValue("sAMAccountName")
			spns := entry.GetAttributeValues("servicePrincipalName")

			for _, spn := range spns {
				// Filter for SCORCH-relevant SPNs
				lowerSPN := strings.ToLower(spn)
				if strings.Contains(lowerSPN, "orch") ||
					strings.Contains(lowerSPN, "scorch") ||
					strings.Contains(lowerSPN, ":81") ||
					strings.Contains(lowerSPN, ":82") ||
					strings.HasPrefix(lowerSPN, "mssqlsvc/") {

					parsed := parseSPN(spn)
					parsed.AccountName = accountName
					parsed.AccountType = f.accountType
					allSPNs = append(allSPNs, parsed)
				}
			}
		}
	}

	return allSPNs, nil
}

// parseSPN parses an SPN string into components
func parseSPN(spn string) SPNResult {
	result := SPNResult{SPN: spn}

	// SPN format: serviceclass/host:port/servicename
	parts := strings.Split(spn, "/")
	if len(parts) >= 1 {
		result.ServiceClass = parts[0]
	}
	if len(parts) >= 2 {
		hostPort := parts[1]
		if idx := strings.Index(hostPort, ":"); idx != -1 {
			result.Host = hostPort[:idx]
			result.Port = hostPort[idx+1:]
		} else {
			result.Host = hostPort
		}
	}

	return result
}

func printDiscoveryResults(w io.Writer, result *DiscoveryResult) {
	fmt.Fprintf(w, "\n[+] Discovery Results for %s\n", result.Target)
	fmt.Fprintln(w, strings.Repeat("=", 60))

	if len(result.OpenPorts) > 0 {
		fmt.Fprintf(w, "\n[+] Open Ports (%d)\n", len(result.OpenPorts))
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for _, p := range result.OpenPorts {
			fmt.Fprintf(w, "  %d/tcp  %-30s", p.Port, p.Service)
			if p.TLSVersion != "" {
				fmt.Fprintf(w, " [%s]", p.TLSVersion)
			}
			fmt.Fprintln(w)
			if p.Banner != "" {
				fmt.Fprintf(w, "         Banner: %s\n", truncate(p.Banner, 50))
			}
		}
	}

	if result.LDAPResults != nil {
		ldapRes := result.LDAPResults

		if ldapRes.BaseDN != "" {
			fmt.Fprintf(w, "\n[+] Domain: %s (%s)\n", ldapRes.DomainName, ldapRes.BaseDN)
		}

		if len(ldapRes.ServiceAccounts) > 0 {
			fmt.Fprintf(w, "\n[+] Service Accounts (%d)\n", len(ldapRes.ServiceAccounts))
			fmt.Fprintln(w, strings.Repeat("-", 40))
			for _, acc := range ldapRes.ServiceAccounts {
				typeLabel := ""
				if acc.AccountType != "" && acc.AccountType != "user" {
					typeLabel = fmt.Sprintf(" [%s]", acc.AccountType)
				}
				fmt.Fprintf(w, "  %s%s\n", acc.SAMAccount, typeLabel)
				if acc.Description != "" {
					fmt.Fprintf(w, "    Description: %s\n", acc.Description)
				}
				if len(acc.SPNs) > 0 {
					fmt.Fprintf(w, "    SPNs: %s\n", strings.Join(acc.SPNs, ", "))
				}
			}
		}

		if len(ldapRes.Computers) > 0 {
			fmt.Fprintf(w, "\n[+] Computers (%d)\n", len(ldapRes.Computers))
			fmt.Fprintln(w, strings.Repeat("-", 40))
			for _, comp := range ldapRes.Computers {
				fmt.Fprintf(w, "  %s", comp.Name)
				if comp.DNSHostName != "" {
					fmt.Fprintf(w, " (%s)", comp.DNSHostName)
				}
				fmt.Fprintln(w)
				if comp.OS != "" {
					fmt.Fprintf(w, "    OS: %s %s\n", comp.OS, comp.OSVersion)
				}
			}
		}

		if len(ldapRes.Groups) > 0 {
			fmt.Fprintf(w, "\n[+] Groups (%d)\n", len(ldapRes.Groups))
			fmt.Fprintln(w, strings.Repeat("-", 40))
			for _, grp := range ldapRes.Groups {
				fmt.Fprintf(w, "  %s\n", grp.Name)
				if grp.Description != "" {
					fmt.Fprintf(w, "    Description: %s\n", grp.Description)
				}
				if len(grp.Members) > 0 {
					fmt.Fprintf(w, "    Members: %d\n", len(grp.Members))
				}
			}
		}
	}

	if len(result.SPNs) > 0 {
		fmt.Fprintf(w, "\n[+] Service Principal Names (%d)\n", len(result.SPNs))
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for _, spn := range result.SPNs {
			fmt.Fprintf(w, "  %s\n", spn.SPN)
			fmt.Fprintf(w, "    Account: %s (%s)\n", spn.AccountName, spn.AccountType)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "\n[!] Errors:\n")
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}

	fmt.Fprintln(w)
}

func printDiscoverHelp() {
	fmt.Print(`
scorch discover - Network discovery and AD enumeration for SCORCH

Usage: scorch discover [options]

Target Options:
  -target, -t    Target hostname or IP (required)
  -dc            Domain Controller for LDAP queries (default: target)
  -base-dn       LDAP base DN (default: auto-detect from RootDSE)

Discovery Options:
  -all           Run all discovery methods
  -ports         Scan SCORCH-related ports (default if no options)
  -ldap          Enumerate LDAP for SCORCH accounts and computers
  -spn           Discover SCORCH-related Service Principal Names

Authentication (required for LDAP/SPN):
  -u, -username  Username
  -p, -password  Password
  -d, -domain    Domain (FQDN like corp.local, or NetBIOS like CORP)
                 If omitted, domain is derived from target FQDN

Note: LDAP uses simple bind with UPN format (user@domain.fqdn).
Pass-the-hash (-H) is not supported for LDAP/SPN enumeration.

Output:
  -json          JSON output
  -o, -output    Write to file
  -debug         Debug output

Ports Scanned:
  81     - SCORCH Web Service (OData/REST API)
  82     - SCORCH Web Console
  443    - HTTPS
  1433   - SQL Server (Orchestrator database)
  389    - LDAP
  636    - LDAPS
  88     - Kerberos
  135    - RPC/DCOM
  445    - SMB
  5985/6 - WinRM

LDAP Searches:
  - Service accounts: *orch*, *scorch*, *runbook*, sco_*, svc_orch*, svc_scorch*
  - Account types: Users, gMSA, MSA (auto-detected)
  - Computers: *orch*, *scorch*, *runbook*, *sco-*, *sco_*
  - Groups: OrchestratorSystemGroup, OrchestratorUsersGroup, Orchestrator Users, etc.
  - SPN patterns: HTTP/*:81*, HTTP/*:82*

SPN Discovery:
  - HTTP/* SPNs (SCORCH web services)
  - MSSQLSvc/* SPNs (Orchestrator database)
  - SPNs on ports 81, 82

Examples:
  # Port scan only
  scorch discover -t scorch.corp.local -ports

  # Full discovery with domain credentials
  scorch discover -t dc01.corp.local -d CORP -u admin -p Pass123 -all

  # SPN enumeration for Kerberoasting targets
  scorch discover -t dc01.corp.local -d CORP -u admin -p Pass123 -spn -json

`)
}
