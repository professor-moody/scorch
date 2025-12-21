package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"scorch-tools/pkg/db"
)

var (
	// Connection flags
	server      = flag.String("server", "", "SQL Server hostname or IP (default: localhost)")
	port        = flag.Int("port", 1433, "SQL Server port")
	database    = flag.String("database", "Orchestrator", "SCORCH database name")
	username    = flag.String("username", "", "SQL username (empty for Windows auth)")
	password    = flag.String("password", "", "SQL password")
	trustedAuth = flag.Bool("trusted", true, "Use Windows/Trusted authentication")
	timeout     = flag.Duration("timeout", 30*time.Second, "Query timeout")

	// Action flags
	variables = flag.Bool("variables", false, "Extract global variables")
	runbooks  = flag.Bool("runbooks", false, "Extract runbook credentials")
	ips       = flag.Bool("ips", false, "Extract Integration Pack connections")
	allCreds  = flag.Bool("all", false, "Extract all credential types")
	info      = flag.Bool("info", false, "Show database info only")
	decrypt   = flag.Bool("decrypt", true, "Attempt to decrypt credentials")
	query     = flag.String("query", "", "Execute custom SQL query")

	// Output flags
	jsonOutput   = flag.Bool("json", false, "Output in JSON format")
	outputFile   = flag.String("output", "", "Write output to file")
	sensitive    = flag.Bool("sensitive", false, "Show decrypted passwords (default: masked)")
	debug        = flag.Bool("debug", false, "Enable debug output")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SCORCH-Dump - System Center Orchestrator Credential Extraction Tool

Usage: scorch-dump [options]

Database Connection:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Extract all credentials using Windows auth
  scorch-dump -server sqlserver.domain.local -all -decrypt

  # Extract only variables with JSON output
  scorch-dump -server sqlserver.domain.local -variables -json

  # Show database info only
  scorch-dump -server sqlserver.domain.local -info

  # Use SQL authentication
  scorch-dump -server sqlserver.domain.local -trusted=false -username sa -password secret -all

  # Execute custom query
  scorch-dump -server sqlserver.domain.local -query "SELECT * FROM dbo.POLICIES WHERE Deleted=0"

Note: This tool requires appropriate database permissions (db_datareader minimum,
      membership in Microsoft.SystemCenter.Orchestrator.Runtime or Admins role for decryption).
`)
	}

	flag.Parse()

	// Set server default
	if *server == "" {
		*server = "localhost"
	}

	// Determine authentication
	if *username != "" {
		*trustedAuth = false
	}

	// Create extractor
	extractor, err := db.NewExtractor(db.DatabaseConfig{
		Server:         *server,
		Port:           *port,
		Database:       *database,
		Username:       *username,
		Password:       *password,
		UseTrustedAuth: *trustedAuth,
		Timeout:        *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating extractor: %v\n", err)
		os.Exit(1)
	}
	extractor.SetDebug(*debug)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*10)
	defer cancel()

	// Connect to database
	if !*jsonOutput {
		fmt.Printf("[*] Connecting to %s:%d/%s...\n", *server, *port, *database)
	}

	if err := extractor.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer extractor.Close()

	if !*jsonOutput {
		fmt.Println("[+] Connected successfully")
	}

	// Execute custom query if specified
	if *query != "" {
		results, err := extractor.ExecuteQuery(ctx, *query)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error executing query: %v\n", err)
			os.Exit(1)
		}
		outputResults(results, "Query Results")
		return
	}

	// Get database info
	if *info || !*jsonOutput {
		dbInfo, err := extractor.GetDatabaseInfo(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting database info: %v\n", err)
			os.Exit(1)
		}

		if *info {
			printDatabaseInfo(dbInfo)
			return
		}

		if !*jsonOutput {
			fmt.Printf("[+] Database: %s on %s\n", dbInfo.DatabaseName, dbInfo.ServerName)
			fmt.Printf("[+] Version: %s\n", dbInfo.Version)
			fmt.Printf("[+] Encryption Keys: Symmetric=%v, Asymmetric=%v\n", 
				dbInfo.HasSymmetricKey, dbInfo.HasAsymmetricKey)
			fmt.Printf("[+] Variables: %d total, %d encrypted\n", 
				dbInfo.TotalVariables, dbInfo.EncryptedVariables)
			fmt.Printf("[+] Runbooks: %d, Connections: %d\n", 
				dbInfo.TotalRunbooks, dbInfo.TotalConnections)
		}
	}

	// Perform extraction
	if *allCreds {
		*variables = true
		*runbooks = true
		*ips = true
	}

	result, err := performExtraction(ctx, extractor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during extraction: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if *jsonOutput {
		output := result
		if !*sensitive {
			output = maskSensitiveData(result)
		}
		
		var outWriter *os.File = os.Stdout
		if *outputFile != "" {
			f, err := os.Create(*outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			outWriter = f
		}

		enc := json.NewEncoder(outWriter)
		enc.SetIndent("", "  ")
		enc.Encode(output)
	} else {
		printExtractionResults(result)
	}
}

func performExtraction(ctx context.Context, extractor *db.Extractor) (*db.ExtractionResult, error) {
	if *allCreds {
		return extractor.ExtractAll(ctx, *decrypt)
	}

	result := &db.ExtractionResult{
		ExtractionTime: time.Now(),
	}

	// Get database info
	dbInfo, err := extractor.GetDatabaseInfo(ctx)
	if err == nil {
		result.DatabaseInfo = *dbInfo
	}

	// Open encryption keys if decrypting
	if *decrypt && result.DatabaseInfo.EncryptionEnabled {
		if err := extractor.OpenEncryptionKeys(ctx); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("open encryption keys: %v", err))
		} else {
			defer extractor.CloseEncryptionKeys(ctx)
			result.DecryptionSuccess = true
		}
	}

	if *variables {
		vars, err := extractor.ExtractVariables(ctx, *decrypt && result.DecryptionSuccess)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("variables: %v", err))
		} else {
			result.Variables = vars
		}
	}

	if *runbooks {
		creds, err := extractor.ExtractRunbookCredentials(ctx, *decrypt && result.DecryptionSuccess)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("runbook credentials: %v", err))
		} else {
			result.RunbookCredentials = creds
		}
	}

	if *ips {
		conns, err := extractor.ExtractIPConnections(ctx)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("IP connections: %v", err))
		} else {
			result.IPConnections = conns
		}
	}

	return result, nil
}

func printDatabaseInfo(info *db.SCORCHDatabaseInfo) {
	fmt.Printf("\n[+] SCORCH Database Information\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Database Name:     %s\n", info.DatabaseName)
	fmt.Printf("  Server Name:       %s\n", info.ServerName)
	fmt.Printf("  Version:           %s\n", info.Version)
	fmt.Printf("  Symmetric Key:     %v\n", info.HasSymmetricKey)
	fmt.Printf("  Asymmetric Key:    %v\n", info.HasAsymmetricKey)
	fmt.Printf("  Encryption Ready:  %v\n", info.EncryptionEnabled)
	fmt.Printf("  Total Variables:   %d\n", info.TotalVariables)
	fmt.Printf("  Encrypted Vars:    %d\n", info.EncryptedVariables)
	fmt.Printf("  Total Runbooks:    %d\n", info.TotalRunbooks)
	fmt.Printf("  Total Connections: %d\n", info.TotalConnections)
	fmt.Println()
}

func printExtractionResults(result *db.ExtractionResult) {
	if len(result.Errors) > 0 {
		fmt.Printf("\n[!] Errors during extraction:\n")
		for _, e := range result.Errors {
			fmt.Printf("    - %s\n", e)
		}
	}

	if len(result.Variables) > 0 {
		fmt.Printf("\n[+] Global Variables (%d found, decryption=%v)\n", 
			len(result.Variables), result.DecryptionSuccess)
		fmt.Println(strings.Repeat("-", 80))

		encrypted := 0
		for _, v := range result.Variables {
			if v.IsEncrypted {
				encrypted++
			}
		}
		fmt.Printf("    Encrypted: %d, Plaintext: %d\n\n", encrypted, len(result.Variables)-encrypted)

		for _, v := range result.Variables {
			encStatus := ""
			if v.IsEncrypted {
				encStatus = "[ENCRYPTED]"
			}

			value := v.EncryptedValue
			if v.DecryptedValue != "" {
				if *sensitive {
					value = v.DecryptedValue
				} else {
					value = maskPassword(v.DecryptedValue)
				}
			} else if v.IsEncrypted {
				value = "[encrypted - decryption failed or disabled]"
			}

			fmt.Printf("  %s %s\n", v.Name, encStatus)
			fmt.Printf("    Path:  %s\n", v.FolderPath)
			fmt.Printf("    Value: %s\n", truncateString(value, 60))
			fmt.Println()
		}
	}

	if len(result.RunbookCredentials) > 0 {
		fmt.Printf("\n[+] Runbook Credentials (%d found)\n", len(result.RunbookCredentials))
		fmt.Println(strings.Repeat("-", 80))

		for _, c := range result.RunbookCredentials {
			fmt.Printf("  Runbook: %s\n", c.RunbookName)
			fmt.Printf("    Path:     %s\n", c.RunbookPath)
			fmt.Printf("    Activity: %s (%s)\n", c.ActivityName, c.ActivityType)
			if c.Server != "" {
				fmt.Printf("    Server:   %s\n", c.Server)
			}
			if c.Username != "" {
				fmt.Printf("    Username: %s\n", c.Username)
			}
			if c.DecryptedPassword != "" {
				pass := c.DecryptedPassword
				if !*sensitive {
					pass = maskPassword(pass)
				}
				fmt.Printf("    Password: %s\n", pass)
			}
			fmt.Println()
		}
	}

	if len(result.IPConnections) > 0 {
		fmt.Printf("\n[+] Integration Pack Connections (%d found)\n", len(result.IPConnections))
		fmt.Println(strings.Repeat("-", 80))

		for _, c := range result.IPConnections {
			fmt.Printf("  %s\n", c.Name)
			fmt.Printf("    Integration Pack: %s\n", c.IntegrationPack)
			if c.Server != "" {
				fmt.Printf("    Server: %s\n", c.Server)
			}
			if c.Username != "" {
				fmt.Printf("    Username: %s\n", c.Username)
			}
			if c.DecryptedPassword != "" {
				pass := c.DecryptedPassword
				if !*sensitive {
					pass = maskPassword(pass)
				}
				fmt.Printf("    Password: %s\n", pass)
			}
			fmt.Println()
		}
	}

	fmt.Printf("\n[+] Extraction completed at %s\n", result.ExtractionTime.Format(time.RFC3339))
}

func outputResults(results []map[string]interface{}, title string) {
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
		return
	}

	fmt.Printf("\n[+] %s (%d rows)\n", title, len(results))
	fmt.Println(strings.Repeat("-", 80))

	if len(results) == 0 {
		fmt.Println("  No results")
		return
	}

	// Get column names from first row
	var cols []string
	for k := range results[0] {
		cols = append(cols, k)
	}

	// Print results
	for i, row := range results {
		fmt.Printf("\n  Row %d:\n", i+1)
		for _, col := range cols {
			val := row[col]
			valStr := fmt.Sprintf("%v", val)
			if len(valStr) > 80 {
				valStr = valStr[:80] + "..."
			}
			fmt.Printf("    %-20s: %s\n", col, valStr)
		}
	}
	fmt.Println()
}

func maskPassword(password string) string {
	if len(password) == 0 {
		return ""
	}
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func maskSensitiveData(result *db.ExtractionResult) *db.ExtractionResult {
	// Create a copy with masked passwords
	masked := &db.ExtractionResult{
		DatabaseInfo:      result.DatabaseInfo,
		ExtractionTime:    result.ExtractionTime,
		DecryptionSuccess: result.DecryptionSuccess,
		Errors:            result.Errors,
	}

	for _, v := range result.Variables {
		maskedVar := v
		if maskedVar.DecryptedValue != "" {
			maskedVar.DecryptedValue = maskPassword(maskedVar.DecryptedValue)
		}
		masked.Variables = append(masked.Variables, maskedVar)
	}

	for _, c := range result.RunbookCredentials {
		maskedCred := c
		if maskedCred.DecryptedPassword != "" {
			maskedCred.DecryptedPassword = maskPassword(maskedCred.DecryptedPassword)
		}
		masked.RunbookCredentials = append(masked.RunbookCredentials, maskedCred)
	}

	for _, ip := range result.IPConnections {
		maskedIP := ip
		if maskedIP.DecryptedPassword != "" {
			maskedIP.DecryptedPassword = maskPassword(maskedIP.DecryptedPassword)
		}
		masked.IPConnections = append(masked.IPConnections, maskedIP)
	}

	return masked
}
