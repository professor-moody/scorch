package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RunbookExecutor provides high-level runbook execution capabilities
type RunbookExecutor struct {
	client *Client
}

// NewRunbookExecutor creates a new executor from an existing client
func NewRunbookExecutor(client *Client) *RunbookExecutor {
	return &RunbookExecutor{client: client}
}

// ExecuteRunbook finds and executes a runbook by name or ID with parameters
func (e *RunbookExecutor) ExecuteRunbook(ctx context.Context, nameOrID string, params map[string]string) (*Job, error) {
	// Try to find runbook by ID first
	runbook, err := e.client.GetRunbook(ctx, nameOrID)
	if err != nil {
		// Search by name
		runbooks, err := e.client.SearchRunbooks(ctx, nameOrID)
		if err != nil {
			return nil, fmt.Errorf("failed to find runbook: %w", err)
		}
		if len(runbooks) == 0 {
			return nil, fmt.Errorf("no runbook found matching: %s", nameOrID)
		}
		if len(runbooks) > 1 {
			return nil, fmt.Errorf("multiple runbooks match '%s', specify exact ID", nameOrID)
		}
		runbook = &runbooks[0]
	}

	// Get runbook parameters to validate
	rbParams, err := e.client.GetRunbookParameters(ctx, runbook.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get runbook parameters: %w", err)
	}

	// Build parameter list
	jobParams := make([]JobParameter, 0)
	for _, p := range rbParams {
		if p.Direction == "In" || p.Direction == "" {
			if val, ok := params[p.Name]; ok {
				jobParams = append(jobParams, JobParameter{
					Name:  p.Name,
					Value: val,
				})
			}
		}
	}

	// Create job
	req := CreateJobRequest{
		RunbookID:  runbook.ID,
		Parameters: jobParams,
	}

	return e.client.CreateJob(ctx, req)
}

// ExecuteAndWait executes a runbook and waits for completion
func (e *RunbookExecutor) ExecuteAndWait(ctx context.Context, nameOrID string, params map[string]string, timeout time.Duration) (*JobResult, error) {
	job, err := e.ExecuteRunbook(ctx, nameOrID, params)
	if err != nil {
		return nil, err
	}

	completedJob, err := e.client.WaitForJob(ctx, job.ID, timeout)
	if err != nil {
		return nil, err
	}

	// Get job output
	output, err := e.client.GetJobOutput(ctx, job.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get job output: %w", err)
	}

	return &JobResult{
		Job:       completedJob,
		Output:    output,
		Success:   completedJob.Status == JobStatusCompleted,
		StartTime: job.CreationTime,
		EndTime:   completedJob.CompletionTime,
	}, nil
}

// JobResult holds the complete result of a job execution
type JobResult struct {
	Job       *Job              `json:"job"`
	Output    *JobOutput        `json:"output"`
	Success   bool              `json:"success"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
	Duration  time.Duration     `json:"duration"`
}

// JobOutput holds the output/returned data from a job
type JobOutput struct {
	Parameters []OutputParameter `json:"parameters"`
	Logs       []JobLogEntry     `json:"logs,omitempty"`
	RawOutput  string            `json:"raw_output,omitempty"`
}

// OutputParameter represents a returned parameter value
type OutputParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// JobLogEntry represents a log entry from job execution
type JobLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Activity  string    `json:"activity"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

// GetJobOutput retrieves the output/returned data from a completed job
func (c *Client) GetJobOutput(ctx context.Context, jobID string) (*JobOutput, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/jobs/%s/instances", jobID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Jobs(guid'%s')/Instances", jobID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get job output: %d - %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	output := &JobOutput{
		RawOutput: string(body),
	}

	// Parse output based on API version
	// This is simplified - actual parsing would be more complex
	if err := json.Unmarshal(body, &output.Parameters); err != nil {
		// Try to extract from raw output
		output.Parameters = extractParametersFromOutput(string(body))
	}

	return output, nil
}

// extractParametersFromOutput attempts to parse parameters from raw output
func extractParametersFromOutput(raw string) []OutputParameter {
	params := make([]OutputParameter, 0)
	
	// Try JSON parsing
	var data interface{}
	if err := json.Unmarshal([]byte(raw), &data); err == nil {
		if m, ok := data.(map[string]interface{}); ok {
			for k, v := range m {
				params = append(params, OutputParameter{
					Name:  k,
					Value: fmt.Sprintf("%v", v),
				})
			}
		}
	}
	
	return params
}

// GetJobLogs retrieves execution logs for a job
func (c *Client) GetJobLogs(ctx context.Context, jobID string) ([]JobLogEntry, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/jobs/%s/activityinstances", jobID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Jobs(guid'%s')/ActivityInstances", jobID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get job logs: %d", resp.StatusCode)
	}

	var logs []JobLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
		return nil, err
	}

	return logs, nil
}

// ====== Variable Operations ======

// GetVariables retrieves global variables (if accessible via API)
func (c *Client) GetVariables(ctx context.Context) ([]Variable, error) {
	// Note: Variables are typically not exposed via the standard API
	// This might work on some versions or with certain permissions
	var path string
	if c.apiVersion == APIVersionModern {
		path = "/api/variables"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Variables"
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("variables endpoint not accessible: %d", resp.StatusCode)
	}

	var variables []Variable
	if err := json.NewDecoder(resp.Body).Decode(&variables); err != nil {
		return nil, err
	}

	return variables, nil
}

// ====== Runbook Management ======

// ExportRunbook exports a runbook definition (if permissions allow)
func (c *Client) ExportRunbook(ctx context.Context, runbookID string) ([]byte, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/runbooks/%s/export", runbookID)
	} else {
		// Legacy API might not support export directly
		return nil, fmt.Errorf("export not supported on legacy API")
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to export runbook: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// GetRunbookDefinition retrieves the internal definition of a runbook
func (c *Client) GetRunbookDefinition(ctx context.Context, runbookID string) (string, error) {
	runbook, err := c.GetRunbook(ctx, runbookID)
	if err != nil {
		return "", err
	}

	// The definition might be in the runbook object or require separate call
	// This is version/permission dependent
	
	var path string
	if c.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/runbooks/%s/activities", runbookID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')/Activities", runbookID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	return fmt.Sprintf("Runbook: %s\nActivities:\n%s", runbook.Name, string(body)), nil
}

// ====== Connection/Integration Pack Info ======

// GetConnections attempts to retrieve Integration Pack connections
func (c *Client) GetConnections(ctx context.Context) ([]Connection, error) {
	// Connections are typically not exposed via API
	// This is a probe for potential misconfiguration
	endpoints := []string{
		"/api/connections",
		"/api/integrationpacks",
		"/Orchestrator2012/Orchestrator.svc/Connections",
	}

	for _, path := range endpoints {
		resp, err := c.doRequest(ctx, "GET", path, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var connections []Connection
			if err := json.NewDecoder(resp.Body).Decode(&connections); err == nil {
				return connections, nil
			}
		}
	}

	return nil, fmt.Errorf("connections endpoint not accessible")
}

// ====== Statistics and Monitoring ======

// GetStatistics retrieves job execution statistics
func (c *Client) GetStatistics(ctx context.Context) (map[string]interface{}, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = "/api/statistics"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Statistics"
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("statistics not accessible: %d", resp.StatusCode)
	}

	var stats map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return stats, nil
}

// GetEvents retrieves system events
func (c *Client) GetEvents(ctx context.Context, filter string) ([]map[string]interface{}, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = "/api/events"
		if filter != "" {
			path += "?" + url.QueryEscape(filter)
		}
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Events"
		if filter != "" {
			path += "?$filter=" + url.QueryEscape(filter)
		}
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("events not accessible: %d", resp.StatusCode)
	}

	var events []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}

	return events, nil
}

// ====== Credential Exposure Detection ======

// ScanForCredentialExposure searches job outputs and runbooks for credential leakage
func (c *Client) ScanForCredentialExposure(ctx context.Context) ([]CredentialExposure, error) {
	exposures := make([]CredentialExposure, 0)

	// Get recent jobs
	jobs, err := c.GetJobs(ctx, "")
	if err != nil {
		return nil, err
	}

	// Scan job outputs for sensitive patterns
	sensitivePatterns := []string{
		"password",
		"secret",
		"credential",
		"apikey",
		"api_key",
		"connectionstring",
		"connection_string",
		"private_key",
		"token",
		"bearer",
	}

	for _, job := range jobs {
		output, err := c.GetJobOutput(ctx, job.ID)
		if err != nil {
			continue
		}

		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(output.RawOutput), pattern) {
				exposures = append(exposures, CredentialExposure{
					Type:      "JobOutput",
					Location:  fmt.Sprintf("Job %s", job.ID),
					Pattern:   pattern,
					Snippet:   extractSnippet(output.RawOutput, pattern),
					Timestamp: time.Now(),
				})
			}
		}
	}

	return exposures, nil
}

// CredentialExposure represents a potential credential leak
type CredentialExposure struct {
	Type      string    `json:"type"`
	Location  string    `json:"location"`
	Pattern   string    `json:"pattern"`
	Snippet   string    `json:"snippet"`
	Timestamp time.Time `json:"timestamp"`
}

// extractSnippet extracts a snippet of text around the pattern
func extractSnippet(text, pattern string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, pattern)
	if idx == -1 {
		return ""
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 50
	if end > len(text) {
		end = len(text)
	}

	return "..." + text[start:end] + "..."
}

// ====== Legacy OData XML Support ======

// LegacyRunbookEntry represents an OData AtomPub entry for runbooks
type LegacyRunbookEntry struct {
	XMLName xml.Name `xml:"entry"`
	ID      string   `xml:"id"`
	Title   string   `xml:"title"`
	Updated string   `xml:"updated"`
	Content struct {
		Properties struct {
			ID          string `xml:"Id"`
			Name        string `xml:"Name"`
			Description string `xml:"Description"`
			FolderID    string `xml:"FolderId"`
			Path        string `xml:"Path"`
			Published   bool   `xml:"IsPublished"`
		} `xml:"properties"`
	} `xml:"content"`
}

// LegacyFeed represents an OData AtomPub feed
type LegacyFeed struct {
	XMLName xml.Name             `xml:"feed"`
	Entries []LegacyRunbookEntry `xml:"entry"`
}

// parseLegacyRunbooks parses AtomPub XML response
func parseLegacyRunbooks(data []byte) ([]Runbook, error) {
	var feed LegacyFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, err
	}

	runbooks := make([]Runbook, len(feed.Entries))
	for i, entry := range feed.Entries {
		runbooks[i] = Runbook{
			ID:          entry.Content.Properties.ID,
			Name:        entry.Content.Properties.Name,
			Description: entry.Content.Properties.Description,
			FolderID:    entry.Content.Properties.FolderID,
			Path:        entry.Content.Properties.Path,
			Published:   entry.Content.Properties.Published,
		}
	}

	return runbooks, nil
}

// createLegacyJobRequest creates an AtomPub XML request for job creation
func createLegacyJobRequest(runbookID string, params []JobParameter) ([]byte, error) {
	// Build parameter XML
	paramXML := "<Data>"
	for _, p := range params {
		paramXML += fmt.Sprintf("<Parameter><Name>%s</Name><Value>%s</Value></Parameter>",
			escapeXML(p.Name), escapeXML(p.Value))
	}
	paramXML += "</Data>"

	entry := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<entry xmlns="http://www.w3.org/2005/Atom" 
       xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" 
       xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">
  <content type="application/xml">
    <m:properties>
      <d:RunbookId type="Edm.Guid">%s</d:RunbookId>
      <d:Parameters><![CDATA[%s]]></d:Parameters>
    </m:properties>
  </content>
</entry>`, runbookID, paramXML)

	return []byte(entry), nil
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
