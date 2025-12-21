package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIVersion represents the SCORCH API version
type APIVersion int

const (
	// APIVersionLegacy is the OData/AtomPub API (pre-2022)
	APIVersionLegacy APIVersion = iota
	// APIVersionModern is the JSON REST API (2022+)
	APIVersionModern
)

// Client is the SCORCH API client
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiVersion APIVersion
	username   string
	password   string
	domain     string
	useNTLM    bool
	debug      bool
}

// ClientConfig holds configuration for creating a new client
type ClientConfig struct {
	Server     string
	Port       int
	Username   string
	Password   string
	Domain     string
	UseNTLM    bool
	UseTLS     bool
	SkipVerify bool
	Timeout    time.Duration
	Debug      bool
}

// NewClient creates a new SCORCH API client
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	
	if cfg.Port == 0 {
		cfg.Port = 81 // Default SCORCH web service port
	}
	
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, cfg.Server, cfg.Port)
	
	// Create transport with optional TLS skip verify
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
	}
	
	httpClient := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}
	
	client := &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
		username:   cfg.Username,
		password:   cfg.Password,
		domain:     cfg.Domain,
		useNTLM:    cfg.UseNTLM,
		debug:      cfg.Debug,
	}
	
	return client, nil
}

// DetectAPIVersion probes the server to determine API version
func (c *Client) DetectAPIVersion(ctx context.Context) (APIVersion, error) {
	// Try modern API first
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/api/runbooks", nil)
	if err != nil {
		return APIVersionLegacy, err
	}
	
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	
	resp, err := c.httpClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		c.apiVersion = APIVersionModern
		return APIVersionModern, nil
	}
	if resp != nil {
		resp.Body.Close()
	}
	
	// Fall back to legacy OData API
	req, err = http.NewRequestWithContext(ctx, "GET", c.baseURL+"/Orchestrator2012/Orchestrator.svc/", nil)
	if err != nil {
		return APIVersionLegacy, err
	}
	
	c.setAuth(req)
	
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return APIVersionLegacy, fmt.Errorf("failed to connect to SCORCH API: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		c.apiVersion = APIVersionLegacy
		return APIVersionLegacy, nil
	}
	
	return APIVersionLegacy, fmt.Errorf("unable to detect API version, status: %d", resp.StatusCode)
}

// setAuth sets authentication headers on the request
func (c *Client) setAuth(req *http.Request) {
	if c.username != "" && c.password != "" {
		if c.useNTLM {
			// For NTLM, we use Basic auth header which gets negotiated
			// In production, you'd want proper NTLM negotiation
			auth := c.username
			if c.domain != "" {
				auth = c.domain + "\\" + c.username
			}
			req.SetBasicAuth(auth, c.password)
		} else {
			req.SetBasicAuth(c.username, c.password)
		}
	}
}

// doRequest executes an HTTP request with common handling
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}
	
	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	
	c.setAuth(req)
	
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	
	if c.debug {
		fmt.Printf("[DEBUG] %s %s\n", method, fullURL)
	}
	
	return c.httpClient.Do(req)
}

// GetRunbooks returns all runbooks
func (c *Client) GetRunbooks(ctx context.Context) ([]Runbook, error) {
	var path string
	if c.apiVersion == APIVersionModern {
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
		return nil, fmt.Errorf("failed to get runbooks: %d - %s", resp.StatusCode, string(body))
	}
	
	if c.apiVersion == APIVersionModern {
		var runbooks []Runbook
		if err := json.NewDecoder(resp.Body).Decode(&runbooks); err != nil {
			return nil, fmt.Errorf("failed to decode runbooks: %w", err)
		}
		return runbooks, nil
	}
	
	// Legacy API returns OData format
	return c.parseODataRunbooks(resp.Body)
}

// GetRunbook returns a specific runbook by ID
func (c *Client) GetRunbook(ctx context.Context, id string) (*Runbook, error) {
	var path string
	if c.apiVersion == APIVersionModern {
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
		return nil, fmt.Errorf("failed to get runbook: %d", resp.StatusCode)
	}
	
	var runbook Runbook
	if err := json.NewDecoder(resp.Body).Decode(&runbook); err != nil {
		return nil, fmt.Errorf("failed to decode runbook: %w", err)
	}
	
	return &runbook, nil
}

// GetRunbookParameters returns parameters for a runbook
func (c *Client) GetRunbookParameters(ctx context.Context, runbookID string) ([]RunbookParameter, error) {
	var path string
	if c.apiVersion == APIVersionModern {
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
		return nil, fmt.Errorf("failed to get parameters: %d", resp.StatusCode)
	}
	
	var params []RunbookParameter
	if err := json.NewDecoder(resp.Body).Decode(&params); err != nil {
		return nil, fmt.Errorf("failed to decode parameters: %w", err)
	}
	
	return params, nil
}

// GetRunbookServers returns all runbook servers
func (c *Client) GetRunbookServers(ctx context.Context) ([]RunbookServer, error) {
	var path string
	if c.apiVersion == APIVersionModern {
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
		return nil, fmt.Errorf("failed to get runbook servers: %d", resp.StatusCode)
	}
	
	var servers []RunbookServer
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return nil, fmt.Errorf("failed to decode runbook servers: %w", err)
	}
	
	return servers, nil
}

// GetFolders returns all folders
func (c *Client) GetFolders(ctx context.Context) ([]Folder, error) {
	var path string
	if c.apiVersion == APIVersionModern {
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
		return nil, fmt.Errorf("failed to get folders: %d", resp.StatusCode)
	}
	
	var folders []Folder
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		return nil, fmt.Errorf("failed to decode folders: %w", err)
	}
	
	return folders, nil
}

// GetJobs returns all jobs, optionally filtered
func (c *Client) GetJobs(ctx context.Context, filter string) ([]Job, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = "/api/jobs"
		if filter != "" {
			path += "?" + url.QueryEscape(filter)
		}
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Jobs"
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
		return nil, fmt.Errorf("failed to get jobs: %d", resp.StatusCode)
	}
	
	var jobs []Job
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return nil, fmt.Errorf("failed to decode jobs: %w", err)
	}
	
	return jobs, nil
}

// CreateJob starts a new runbook job
func (c *Client) CreateJob(ctx context.Context, req CreateJobRequest) (*Job, error) {
	var path string
	if c.apiVersion == APIVersionModern {
		path = "/api/jobs"
	} else {
		path = "/Orchestrator2012/Orchestrator.svc/Jobs"
	}
	
	resp, err := c.doRequest(ctx, "POST", path, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create job: %d - %s", resp.StatusCode, string(body))
	}
	
	var job Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, fmt.Errorf("failed to decode job response: %w", err)
	}
	
	return &job, nil
}

// StopJob stops a running job
func (c *Client) StopJob(ctx context.Context, jobID string) error {
	var path string
	if c.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/jobs/%s/stop", jobID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Jobs(guid'%s')/Stop", jobID)
	}
	
	resp, err := c.doRequest(ctx, "POST", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to stop job: %d", resp.StatusCode)
	}
	
	return nil
}

// WaitForJob waits for a job to complete
func (c *Client) WaitForJob(ctx context.Context, jobID string, timeout time.Duration) (*Job, error) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		
		jobs, err := c.GetJobs(ctx, fmt.Sprintf("Id eq '%s'", jobID))
		if err != nil {
			return nil, err
		}
		
		if len(jobs) == 0 {
			return nil, fmt.Errorf("job not found: %s", jobID)
		}
		
		job := &jobs[0]
		switch job.Status {
		case JobStatusCompleted, JobStatusFailed, JobStatusCanceled:
			return job, nil
		}
		
		time.Sleep(2 * time.Second)
	}
	
	return nil, fmt.Errorf("timeout waiting for job: %s", jobID)
}

// SearchRunbooks searches for runbooks by name pattern
func (c *Client) SearchRunbooks(ctx context.Context, pattern string) ([]Runbook, error) {
	runbooks, err := c.GetRunbooks(ctx)
	if err != nil {
		return nil, err
	}
	
	var matches []Runbook
	pattern = strings.ToLower(pattern)
	
	for _, rb := range runbooks {
		if strings.Contains(strings.ToLower(rb.Name), pattern) ||
			strings.Contains(strings.ToLower(rb.Path), pattern) {
			matches = append(matches, rb)
		}
	}
	
	return matches, nil
}

// OData/AtomPub XML structures for legacy API parsing
type odataFeed struct {
	XMLName xml.Name     `xml:"feed"`
	Entries []odataEntry `xml:"entry"`
}

type odataEntry struct {
	Content odataContent `xml:"content"`
}

type odataContent struct {
	Properties odataProperties `xml:"properties"`
}

type odataProperties struct {
	ID          string `xml:"Id"`
	Name        string `xml:"Name"`
	Description string `xml:"Description"`
	Path        string `xml:"Path"`
	IsPublished string `xml:"IsPublished"`
	FolderID    string `xml:"FolderId"`
}

// parseODataRunbooks parses legacy OData XML response for runbooks
func (c *Client) parseODataRunbooks(body io.Reader) ([]Runbook, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	// Try JSON first (some versions return JSON even for legacy endpoints)
	var response ODataRunbooksResponse
	if err := json.Unmarshal(data, &response); err == nil && len(response.Value) > 0 {
		return response.Value, nil
	}

	// Parse OData/AtomPub XML format
	var feed odataFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse OData response: %w", err)
	}

	var runbooks []Runbook
	for _, entry := range feed.Entries {
		props := entry.Content.Properties
		published := strings.ToLower(props.IsPublished) == "true"
		runbooks = append(runbooks, Runbook{
			ID:          props.ID,
			Name:        props.Name,
			Description: props.Description,
			Path:        props.Path,
			Published:   published,
			FolderID:    props.FolderID,
		})
	}

	return runbooks, nil
}

// TestConnection tests if the connection to SCORCH is working
func (c *Client) TestConnection(ctx context.Context) error {
	version, err := c.DetectAPIVersion(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	if c.debug {
		fmt.Printf("[DEBUG] API Version: %v\n", version)
	}
	
	// Try to get runbooks as a basic test
	_, err = c.GetRunbooks(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve runbooks: %w", err)
	}
	
	return nil
}

// GetAPIVersion returns the detected API version
func (c *Client) GetAPIVersion() APIVersion {
	return c.apiVersion
}

// GetBaseURL returns the base URL of the client
func (c *Client) GetBaseURL() string {
	return c.baseURL
}
