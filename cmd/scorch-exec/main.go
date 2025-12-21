package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"scorch-tools/internal/auth"
	"scorch-tools/pkg/api"
)

var (
	// Connection flags
	server     = flag.String("server", "", "SCORCH server hostname or IP")
	port       = flag.Int("port", 81, "SCORCH web service port")
	useTLS     = flag.Bool("tls", false, "Use HTTPS")
	skipVerify = flag.Bool("skip-verify", false, "Skip TLS certificate verification")
	timeout    = flag.Duration("timeout", 60*time.Second, "Request timeout")

	// Authentication flags
	username   = flag.String("username", "", "Username for authentication")
	password   = flag.String("password", "", "Password for authentication")
	domain     = flag.String("domain", "", "Domain for NTLM authentication")
	hash       = flag.String("hash", "", "NT hash for Pass-the-Hash (format: LM:NT or just NT)")
	authMethod = flag.String("auth", "auto", "Auth method: auto, ntlm, pth, basic, kerberos, none")

	// Action flags
	listRunbooks    = flag.Bool("list", false, "List all runbooks")
	searchRunbooks  = flag.String("search", "", "Search runbooks by name")
	runbookInfo     = flag.String("info", "", "Get detailed info for runbook (ID or name)")
	executeRunbook  = flag.String("exec", "", "Execute runbook (ID or name)")
	runbookParams   = flag.String("params", "", "Parameters for execution (key=value,key=value)")
	waitForJob      = flag.Bool("wait", false, "Wait for job completion")
	jobTimeout      = flag.Duration("job-timeout", 5*time.Minute, "Timeout waiting for job")
	listJobs        = flag.Bool("jobs", false, "List recent jobs")
	jobInfo         = flag.String("job-info", "", "Get info for specific job ID")
	stopJob         = flag.String("stop", "", "Stop a running job by ID")
	
	// Advanced operations
	getServers     = flag.Bool("servers", false, "List runbook servers")
	getStats       = flag.Bool("stats", false, "Get execution statistics")
	scanCreds      = flag.Bool("scan-creds", false, "Scan job outputs for credential exposure")
	exportRunbook  = flag.String("export", "", "Export runbook definition (ID)")
	testAuth       = flag.Bool("test-auth", false, "Test authentication only")

	// Output flags
	jsonOutput = flag.Bool("json", false, "Output in JSON format")
	debug      = flag.Bool("debug", false, "Enable debug output")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SCORCH-Exec - System Center Orchestrator Interaction Tool

Execute runbooks, manage jobs, and interact with SCORCH using various 
authentication methods including Pass-the-Hash.

Usage: scorch-exec [options]

Connection Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Authentication Methods:
  auto     - Auto-detect (PTH if hash provided, NTLM if password, anonymous otherwise)
  ntlm     - NTLM authentication with password
  pth      - Pass-the-Hash with NT hash
  basic    - HTTP Basic authentication
  kerberos - Kerberos authentication (requires ticket)
  none     - Anonymous/unauthenticated

Examples:
  # List runbooks with NTLM auth
  scorch-exec -server scorch.domain.local -username admin -password secret -domain CORP -list

  # Pass-the-Hash authentication
  scorch-exec -server scorch.domain.local -username admin -hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -domain CORP -list

  # Execute runbook with parameters
  scorch-exec -server scorch.domain.local -username admin -password secret \
    -exec "Backup Server" -params "ServerName=DC01,BackupType=Full" -wait

  # Get job status
  scorch-exec -server scorch.domain.local -username admin -password secret \
    -job-info "12345678-1234-1234-1234-123456789012"

  # Scan for credential exposure
  scorch-exec -server scorch.domain.local -username admin -password secret -scan-creds

  # Test authentication
  scorch-exec -server scorch.domain.local -username admin -hash <nthash> -domain CORP -test-auth
`)
	}

	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: -server is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse credentials
	creds, err := auth.ParseCredentials(*username, *password, *domain, *hash, *authMethod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing credentials: %v\n", err)
		os.Exit(1)
	}

	if *debug {
		fmt.Printf("[DEBUG] Auth method: %s\n", creds.Method)
		fmt.Printf("[DEBUG] Username: %s\\%s\n", creds.Domain, creds.Username)
	}

	// Test auth only if requested
	if *testAuth {
		testAuthentication(creds)
		return
	}

	// Create client
	client, err := api.NewClient(api.ClientConfig{
		Server:     *server,
		Port:       *port,
		Username:   *username,
		Password:   *password,
		Domain:     *domain,
		UseNTLM:    creds.Method == auth.AuthNTLM || creds.Method == auth.AuthNTLMHash,
		UseTLS:     *useTLS,
		SkipVerify: *skipVerify,
		Timeout:    *timeout,
		Debug:      *debug,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	// TODO: Replace transport with authenticated transport for PTH support
	// This would require modifying the client to use our auth package

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Detect API version
	if _, err := client.DetectAPIVersion(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to SCORCH: %v\n", err)
		os.Exit(1)
	}

	// Execute requested action
	switch {
	case *listRunbooks:
		doListRunbooks(ctx, client)
	case *searchRunbooks != "":
		doSearchRunbooks(ctx, client, *searchRunbooks)
	case *runbookInfo != "":
		doRunbookInfo(ctx, client, *runbookInfo)
	case *executeRunbook != "":
		doExecuteRunbook(ctx, client, *executeRunbook, *runbookParams, *waitForJob, *jobTimeout)
	case *listJobs:
		doListJobs(ctx, client)
	case *jobInfo != "":
		doJobInfo(ctx, client, *jobInfo)
	case *stopJob != "":
		doStopJob(ctx, client, *stopJob)
	case *getServers:
		doListServers(ctx, client)
	case *getStats:
		doGetStats(ctx, client)
	case *scanCreds:
		doScanCredentials(ctx, client)
	case *exportRunbook != "":
		doExportRunbook(ctx, client, *exportRunbook)
	default:
		fmt.Fprintln(os.Stderr, "Error: No action specified. Use -list, -exec, -jobs, etc.")
		flag.Usage()
		os.Exit(1)
	}
}

func testAuthentication(creds *auth.Credentials) {
	scheme := "http"
	if *useTLS {
		scheme = "https"
	}
	target := fmt.Sprintf("%s://%s:%d/api/runbooks", scheme, *server, *port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, msg, err := auth.TestAuthentication(ctx, target, creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Authentication test error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		result := map[string]interface{}{
			"success": success,
			"message": msg,
			"method":  creds.Method.String(),
			"target":  target,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
	} else {
		if success {
			fmt.Printf("[+] %s\n", msg)
			fmt.Printf("    Method: %s\n", creds.Method)
			fmt.Printf("    User:   %s\\%s\n", creds.Domain, creds.Username)
		} else {
			fmt.Printf("[-] %s\n", msg)
		}
	}

	if !success {
		os.Exit(1)
	}
}

func doListRunbooks(ctx context.Context, client *api.Client) {
	runbooks, err := client.GetRunbooks(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing runbooks: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(runbooks)
		return
	}

	fmt.Printf("[+] Found %d runbooks\n\n", len(runbooks))
	for _, rb := range runbooks {
		status := "Draft"
		if rb.Published {
			status = "Published"
		}
		fmt.Printf("  %-40s [%s]\n", rb.Name, status)
		fmt.Printf("    ID:   %s\n", rb.ID)
		if rb.Path != "" {
			fmt.Printf("    Path: %s\n", rb.Path)
		}
		fmt.Println()
	}
}

func doSearchRunbooks(ctx context.Context, client *api.Client, pattern string) {
	runbooks, err := client.SearchRunbooks(ctx, pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error searching runbooks: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(runbooks)
		return
	}

	fmt.Printf("[+] Found %d runbooks matching '%s'\n\n", len(runbooks), pattern)
	for _, rb := range runbooks {
		fmt.Printf("  %s\n", rb.Name)
		fmt.Printf("    ID: %s\n", rb.ID)
		fmt.Println()
	}
}

func doRunbookInfo(ctx context.Context, client *api.Client, nameOrID string) {
	// Try by ID first
	runbook, err := client.GetRunbook(ctx, nameOrID)
	if err != nil {
		// Search by name
		runbooks, err := client.SearchRunbooks(ctx, nameOrID)
		if err != nil || len(runbooks) == 0 {
			fmt.Fprintf(os.Stderr, "Error: Runbook not found: %s\n", nameOrID)
			os.Exit(1)
		}
		runbook = &runbooks[0]
	}

	params, _ := client.GetRunbookParameters(ctx, runbook.ID)

	if *jsonOutput {
		result := map[string]interface{}{
			"runbook":    runbook,
			"parameters": params,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	fmt.Printf("[+] Runbook Details\n")
	fmt.Printf("    Name:        %s\n", runbook.Name)
	fmt.Printf("    ID:          %s\n", runbook.ID)
	fmt.Printf("    Path:        %s\n", runbook.Path)
	fmt.Printf("    Published:   %v\n", runbook.Published)
	fmt.Printf("    Description: %s\n", runbook.Description)
	fmt.Printf("    Modified:    %s\n", runbook.LastModifiedTime.Format(time.RFC3339))
	
	if len(params) > 0 {
		fmt.Printf("\n    Parameters:\n")
		for _, p := range params {
			dir := "In"
			if p.Direction != "" {
				dir = p.Direction
			}
			fmt.Printf("      [%s] %s (%s)\n", dir, p.Name, p.Type)
		}
	}
}

func doExecuteRunbook(ctx context.Context, client *api.Client, nameOrID, paramStr string, wait bool, jobTimeout time.Duration) {
	// Parse parameters
	params := make(map[string]string)
	if paramStr != "" {
		pairs := strings.Split(paramStr, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	executor := api.NewRunbookExecutor(client)

	if wait {
		fmt.Printf("[*] Executing runbook '%s' and waiting for completion...\n", nameOrID)
		result, err := executor.ExecuteAndWait(ctx, nameOrID, params, jobTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			return
		}

		fmt.Printf("[+] Job completed\n")
		fmt.Printf("    Job ID:   %s\n", result.Job.ID)
		fmt.Printf("    Status:   %s\n", result.Job.Status)
		fmt.Printf("    Duration: %s\n", result.EndTime.Sub(result.StartTime))
		if result.Output != nil && len(result.Output.Parameters) > 0 {
			fmt.Printf("    Output:\n")
			for _, p := range result.Output.Parameters {
				fmt.Printf("      %s: %s\n", p.Name, p.Value)
			}
		}
	} else {
		job, err := executor.ExecuteRunbook(ctx, nameOrID, params)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(job)
			return
		}

		fmt.Printf("[+] Job started\n")
		fmt.Printf("    Job ID: %s\n", job.ID)
		fmt.Printf("    Status: %s\n", job.Status)
		fmt.Printf("\n    Use -job-info %s to check status\n", job.ID)
	}
}

func doListJobs(ctx context.Context, client *api.Client) {
	jobs, err := client.GetJobs(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing jobs: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(jobs)
		return
	}

	fmt.Printf("[+] Recent Jobs (%d)\n\n", len(jobs))
	for _, j := range jobs {
		fmt.Printf("  [%s] %s\n", j.Status, j.ID)
		fmt.Printf("    Runbook: %s\n", j.RunbookID)
		fmt.Printf("    Created: %s by %s\n", j.CreationTime.Format(time.RFC3339), j.CreatedBy)
		fmt.Println()
	}
}

func doJobInfo(ctx context.Context, client *api.Client, jobID string) {
	jobs, err := client.GetJobs(ctx, fmt.Sprintf("Id eq '%s'", jobID))
	if err != nil || len(jobs) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Job not found: %s\n", jobID)
		os.Exit(1)
	}

	job := &jobs[0]
	output, _ := client.GetJobOutput(ctx, jobID)
	logs, _ := client.GetJobLogs(ctx, jobID)

	if *jsonOutput {
		result := map[string]interface{}{
			"job":    job,
			"output": output,
			"logs":   logs,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
		return
	}

	fmt.Printf("[+] Job Details\n")
	fmt.Printf("    ID:        %s\n", job.ID)
	fmt.Printf("    Status:    %s\n", job.Status)
	fmt.Printf("    Runbook:   %s\n", job.RunbookID)
	fmt.Printf("    Created:   %s\n", job.CreationTime.Format(time.RFC3339))
	fmt.Printf("    Completed: %s\n", job.CompletionTime.Format(time.RFC3339))
	fmt.Printf("    Created By:%s\n", job.CreatedBy)

	if output != nil && len(output.Parameters) > 0 {
		fmt.Printf("\n    Output:\n")
		for _, p := range output.Parameters {
			fmt.Printf("      %s: %s\n", p.Name, p.Value)
		}
	}
}

func doStopJob(ctx context.Context, client *api.Client, jobID string) {
	if err := client.StopJob(ctx, jobID); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping job: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Job %s stop requested\n", jobID)
}

func doListServers(ctx context.Context, client *api.Client) {
	servers, err := client.GetRunbookServers(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing servers: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(servers)
		return
	}

	fmt.Printf("[+] Runbook Servers (%d)\n\n", len(servers))
	for _, s := range servers {
		status := "Offline"
		if s.Available {
			status = "Online"
		}
		fmt.Printf("  %s [%s]\n", s.Name, status)
		fmt.Printf("    Machine:    %s\n", s.MachineName)
		fmt.Printf("    Jobs:       %d/%d\n", s.RunningJobs, s.MaxRunningJobs)
		fmt.Printf("    Heartbeat:  %s\n", s.LastHeartbeat.Format(time.RFC3339))
		fmt.Println()
	}
}

func doGetStats(ctx context.Context, client *api.Client) {
	stats, err := client.GetStatistics(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting statistics: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(stats)
}

func doScanCredentials(ctx context.Context, client *api.Client) {
	fmt.Println("[*] Scanning job outputs for credential exposure...")
	
	exposures, err := client.ScanForCredentialExposure(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(exposures)
		return
	}

	if len(exposures) == 0 {
		fmt.Println("[+] No credential exposure detected")
		return
	}

	fmt.Printf("[!] Found %d potential credential exposures\n\n", len(exposures))
	for i, e := range exposures {
		fmt.Printf("[%d] %s\n", i+1, e.Type)
		fmt.Printf("    Location: %s\n", e.Location)
		fmt.Printf("    Pattern:  %s\n", e.Pattern)
		fmt.Printf("    Snippet:  %s\n", e.Snippet)
		fmt.Println()
	}
}

func doExportRunbook(ctx context.Context, client *api.Client, runbookID string) {
	def, err := client.GetRunbookDefinition(ctx, runbookID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting runbook: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(def)
}
