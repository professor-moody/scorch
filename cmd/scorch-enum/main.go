package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"scorch-tools/pkg/api"
)

var (
	// Connection flags
	server     = flag.String("server", "", "SCORCH server hostname or IP")
	port       = flag.Int("port", 81, "SCORCH web service port")
	username   = flag.String("username", "", "Username for authentication")
	password   = flag.String("password", "", "Password for authentication")
	domain     = flag.String("domain", "", "Domain for NTLM authentication")
	useTLS     = flag.Bool("tls", false, "Use HTTPS")
	skipVerify = flag.Bool("skip-verify", false, "Skip TLS certificate verification")
	timeout    = flag.Duration("timeout", 30*time.Second, "Request timeout")

	// Action flags
	runbooks   = flag.Bool("runbooks", false, "Enumerate runbooks")
	servers    = flag.Bool("servers", false, "Enumerate runbook servers")
	folders    = flag.Bool("folders", false, "Enumerate folders")
	jobs       = flag.Bool("jobs", false, "Enumerate recent jobs")
	all        = flag.Bool("all", false, "Enumerate everything")
	search     = flag.String("search", "", "Search for runbooks by name pattern")
	runbookID  = flag.String("runbook-id", "", "Get details for specific runbook")
	params     = flag.Bool("params", false, "Include parameters when getting runbook details")

	// Output flags
	jsonOutput = flag.Bool("json", false, "Output in JSON format")
	debug      = flag.Bool("debug", false, "Enable debug output")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `SCORCH-Enum - System Center Orchestrator Remote Enumeration Tool

Usage: scorch-enum [options]

Connection Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  # Enumerate all runbooks
  scorch-enum -server scorch.domain.local -all

  # Search for specific runbooks
  scorch-enum -server scorch.domain.local -search "backup"

  # Get runbook details with parameters
  scorch-enum -server scorch.domain.local -runbook-id <guid> -params

  # Authenticate with domain credentials
  scorch-enum -server scorch.domain.local -domain CORP -username admin -password secret -all
`)
	}

	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: -server is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create client
	client, err := api.NewClient(api.ClientConfig{
		Server:     *server,
		Port:       *port,
		Username:   *username,
		Password:   *password,
		Domain:     *domain,
		UseNTLM:    *domain != "",
		UseTLS:     *useTLS,
		SkipVerify: *skipVerify,
		Timeout:    *timeout,
		Debug:      *debug,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout*5)
	defer cancel()

	// Detect API version
	if *debug {
		fmt.Println("[*] Detecting API version...")
	}
	apiVersion, err := client.DetectAPIVersion(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error detecting API version: %v\n", err)
		os.Exit(1)
	}
	if !*jsonOutput {
		versionStr := "Legacy (OData)"
		if apiVersion == api.APIVersionModern {
			versionStr = "Modern (JSON)"
		}
		fmt.Printf("[+] Connected to SCORCH server: %s (API: %s)\n", *server, versionStr)
	}

	// Execute requested actions
	result := &api.EnumerationResult{
		Timestamp:  time.Now(),
		Target:     *server,
		APIVersion: fmt.Sprintf("%d", apiVersion),
	}

	if *runbookID != "" {
		// Get specific runbook
		rb, err := client.GetRunbook(ctx, *runbookID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting runbook: %v\n", err)
			os.Exit(1)
		}
		if *params {
			rbParams, err := client.GetRunbookParameters(ctx, *runbookID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to get parameters: %v\n", err)
			}
			printRunbookDetails(rb, rbParams)
		} else {
			result.Runbooks = []api.Runbook{*rb}
		}
	}

	if *search != "" {
		rbs, err := client.SearchRunbooks(ctx, *search)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error searching runbooks: %v\n", err)
			os.Exit(1)
		}
		result.Runbooks = rbs
	}

	if *runbooks || *all {
		rbs, err := client.GetRunbooks(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting runbooks: %v\n", err)
		} else {
			result.Runbooks = rbs
		}
	}

	if *servers || *all {
		srvs, err := client.GetRunbookServers(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting runbook servers: %v\n", err)
		} else {
			result.RunbookServers = srvs
		}
	}

	if *folders || *all {
		fldrs, err := client.GetFolders(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting folders: %v\n", err)
		} else {
			result.Folders = fldrs
		}
	}

	if *jobs || *all {
		jbs, err := client.GetJobs(ctx, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting jobs: %v\n", err)
		} else {
			result.Jobs = jbs
		}
	}

	// Output results
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
	} else {
		printResults(result)
	}
}

func printResults(result *api.EnumerationResult) {
	if len(result.Runbooks) > 0 {
		fmt.Printf("\n[+] Runbooks (%d found)\n", len(result.Runbooks))
		fmt.Println(strings.Repeat("-", 80))
		for _, rb := range result.Runbooks {
			published := "Draft"
			if rb.Published {
				published = "Published"
			}
			fmt.Printf("  %-40s [%s] %s\n", rb.Name, published, rb.ID)
			if rb.Path != "" {
				fmt.Printf("    Path: %s\n", rb.Path)
			}
			if rb.Description != "" && len(rb.Description) > 0 {
				desc := rb.Description
				if len(desc) > 60 {
					desc = desc[:60] + "..."
				}
				fmt.Printf("    Description: %s\n", desc)
			}
		}
	}

	if len(result.RunbookServers) > 0 {
		fmt.Printf("\n[+] Runbook Servers (%d found)\n", len(result.RunbookServers))
		fmt.Println(strings.Repeat("-", 80))
		for _, srv := range result.RunbookServers {
			status := "Offline"
			if srv.Available {
				status = "Online"
			}
			fmt.Printf("  %-30s [%s] %s\n", srv.Name, status, srv.MachineName)
			fmt.Printf("    Running Jobs: %d/%d\n", srv.RunningJobs, srv.MaxRunningJobs)
			fmt.Printf("    Last Heartbeat: %s\n", srv.LastHeartbeat.Format(time.RFC3339))
		}
	}

	if len(result.Folders) > 0 {
		fmt.Printf("\n[+] Folders (%d found)\n", len(result.Folders))
		fmt.Println(strings.Repeat("-", 80))
		for _, f := range result.Folders {
			fmt.Printf("  %s\n", f.Path)
			if f.Description != "" {
				fmt.Printf("    Description: %s\n", f.Description)
			}
		}
	}

	if len(result.Jobs) > 0 {
		fmt.Printf("\n[+] Recent Jobs (%d found)\n", len(result.Jobs))
		fmt.Println(strings.Repeat("-", 80))
		for _, j := range result.Jobs {
			fmt.Printf("  [%s] %s\n", j.Status, j.ID)
			fmt.Printf("    RunbookID: %s\n", j.RunbookID)
			fmt.Printf("    Created: %s by %s\n", j.CreationTime.Format(time.RFC3339), j.CreatedBy)
		}
	}

	fmt.Println()
}

func printRunbookDetails(rb *api.Runbook, params []api.RunbookParameter) {
	fmt.Printf("\n[+] Runbook Details\n")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  Name:        %s\n", rb.Name)
	fmt.Printf("  ID:          %s\n", rb.ID)
	fmt.Printf("  Path:        %s\n", rb.Path)
	fmt.Printf("  Published:   %v\n", rb.Published)
	fmt.Printf("  Description: %s\n", rb.Description)
	fmt.Printf("  Created:     %s\n", rb.CreationTime.Format(time.RFC3339))
	fmt.Printf("  Modified:    %s by %s\n", rb.LastModifiedTime.Format(time.RFC3339), rb.LastModifiedBy)
	if rb.CheckedOutBy != "" {
		fmt.Printf("  Checked Out: %s at %s\n", rb.CheckedOutBy, rb.CheckOutTime.Format(time.RFC3339))
	}

	if len(params) > 0 {
		fmt.Printf("\n  Parameters:\n")
		for _, p := range params {
			direction := "In"
			if p.Direction != "" {
				direction = p.Direction
			}
			fmt.Printf("    [%s] %s (%s)\n", direction, p.Name, p.Type)
			if p.Description != "" {
				fmt.Printf("         %s\n", p.Description)
			}
		}
	}

	fmt.Println()
}
