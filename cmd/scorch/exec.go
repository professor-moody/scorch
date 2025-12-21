package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func runExec(args []string) error {
	if containsHelp(args) {
		printExecHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	// Parse exec-specific flags
	runbookID, remaining := parseFlag(remaining, "-id", "-runbook-id", "--runbook-id")
	runbookName, remaining := parseFlag(remaining, "-name", "-runbook", "--runbook")
	paramsStr, remaining := parseFlag(remaining, "-params", "--params")
	wait, _ := parseBoolFlag(remaining, "-wait", "--wait")

	if err := opts.Validate(); err != nil {
		return err
	}

	if runbookID == "" && runbookName == "" {
		return fmt.Errorf("-id or -name is required")
	}

	ctx, cancel := createContext(opts)
	defer cancel()

	client, err := NewHTTPClient(opts)
	if err != nil {
		return err
	}

	_, err = client.DetectAPIVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Resolve runbook name to ID if needed
	if runbookID == "" && runbookName != "" {
		printf(opts, "[*] Searching for runbook: %s\n", runbookName)
		runbooks, err := client.SearchRunbooks(ctx, runbookName)
		if err != nil {
			return err
		}
		if len(runbooks) == 0 {
			return fmt.Errorf("no runbook found matching: %s", runbookName)
		}
		if len(runbooks) > 1 {
			fmt.Printf("Multiple runbooks found:\n")
			for _, rb := range runbooks {
				fmt.Printf("  %s: %s\n", rb.ID, rb.Name)
			}
			return fmt.Errorf("please specify exact runbook ID with -id")
		}
		runbookID = runbooks[0].ID
		printf(opts, "[+] Found: %s (%s)\n", runbooks[0].Name, runbookID)
	}

	// Parse parameters
	params := make(map[string]string)
	if paramsStr != "" {
		for _, p := range strings.Split(paramsStr, ",") {
			parts := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(parts) == 2 {
				params[parts[0]] = parts[1]
			}
		}
	}

	printf(opts, "[*] Executing runbook %s with %d parameters\n", runbookID, len(params))

	// Create job
	job, err := createJob(ctx, client, opts, runbookID, params)
	if err != nil {
		return fmt.Errorf("failed to start job: %w", err)
	}

	printf(opts, "[+] Job started: %s\n", job.ID)

	if !wait {
		if opts.JSON {
			output, cleanup, _ := getOutput(opts)
			defer cleanup()
			return writeJSON(output, job)
		}
		fmt.Printf("Job ID: %s\n", job.ID)
		return nil
	}

	// Wait for completion
	printf(opts, "[*] Waiting for completion...\n")
	finalJob, err := waitForJob(ctx, client, opts, job.ID, 5*time.Minute)
	if err != nil {
		return err
	}

	if opts.JSON {
		output, cleanup, _ := getOutput(opts)
		defer cleanup()
		return writeJSON(output, finalJob)
	}

	fmt.Printf("\nJob completed:\n")
	fmt.Printf("  ID:     %s\n", finalJob.ID)
	fmt.Printf("  Status: %s\n", finalJob.Status)

	return nil
}

func createJob(ctx context.Context, client *HTTPClient, opts *CommonOpts, runbookID string, params map[string]string) (*Job, error) {
	var path string
	var body []byte
	var err error

	if client.apiVersion == "modern" {
		path = "/api/jobs"
		reqBody := map[string]interface{}{
			"RunbookId":  runbookID,
			"Parameters": params,
		}
		body, err = json.Marshal(reqBody)
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Jobs"
		body = buildAtomPubJobRequest(runbookID, params)
	}

	if err != nil {
		return nil, err
	}

	url := opts.BaseURL() + path
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	if client.apiVersion == "modern" {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/atom+xml")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var job Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, err
	}

	return &job, nil
}

func buildAtomPubJobRequest(runbookID string, params map[string]string) []byte {
	// Build parameter XML
	var paramXML string
	if len(params) > 0 {
		paramXML = "<Data>"
		for name, value := range params {
			paramXML += fmt.Sprintf("<Parameter><Name>%s</Name><Value>%s</Value></Parameter>", name, value)
		}
		paramXML += "</Data>"
	}

	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" 
       xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" 
       xmlns="http://www.w3.org/2005/Atom">
  <content type="application/xml">
    <m:properties>
      <d:RunbookId type="Edm.Guid">%s</d:RunbookId>
      <d:Parameters><![CDATA[%s]]></d:Parameters>
    </m:properties>
  </content>
</entry>`, runbookID, paramXML))
}

func waitForJob(ctx context.Context, client *HTTPClient, opts *CommonOpts, jobID string, timeout time.Duration) (*Job, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for job completion")
			}

			job, err := getJob(ctx, client, opts, jobID)
			if err != nil {
				debugf(opts, "Error getting job status: %v", err)
				continue
			}

			debugf(opts, "Job status: %s", job.Status)

			switch strings.ToLower(job.Status) {
			case "completed", "succeeded", "success":
				return job, nil
			case "failed", "error", "canceled":
				return job, fmt.Errorf("job %s: %s", job.Status, jobID)
			}
		}
	}
}

func getJob(ctx context.Context, client *HTTPClient, opts *CommonOpts, jobID string) (*Job, error) {
	var path string
	if client.apiVersion == "modern" {
		path = fmt.Sprintf("/api/jobs/%s", jobID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Jobs(guid'%s')", jobID)
	}

	resp, err := client.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var job Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, err
	}

	return &job, nil
}

func printExecHelp() {
	fmt.Print(`
scorch exec - Execute SCORCH runbooks

Usage: scorch exec [options]

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

Execution:
  -id            Runbook ID (GUID)
  -name          Runbook name (will search)
  -params        Parameters as Name=Value,Name2=Value2
  -wait          Wait for runbook completion

Output:
  -json          JSON output
  -o, -output    Write to file
  -debug         Debug output

Examples:
  # Execute by ID with parameters
  scorch exec -t scorch.corp.local -u admin -p Pass123 \
    -id 12345678-1234-1234-1234-123456789012 \
    -params "ServerName=DC01,Action=Restart" -wait

  # Execute by name
  scorch exec -t scorch.corp.local -u admin -p Pass123 \
    -name "Restart Server" -params "Target=webserver01"

`)
}
