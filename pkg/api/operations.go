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
	"text/template"
	"time"
)

// RunbookOperator provides full runbook manipulation capabilities
type RunbookOperator struct {
	client *Client
	debug  bool
}

// NewRunbookOperator creates a new runbook operator
func NewRunbookOperator(client *Client) *RunbookOperator {
	return &RunbookOperator{client: client}
}

// SetDebug enables debug output
func (r *RunbookOperator) SetDebug(debug bool) {
	r.debug = debug
	r.client.debug = debug
}

// ExecuteRunbook starts a runbook with the given parameters
func (r *RunbookOperator) ExecuteRunbook(ctx context.Context, runbookID string, params map[string]string, waitForCompletion bool, timeout time.Duration) (*JobExecutionResult, error) {
	if r.debug {
		fmt.Printf("[*] Executing runbook %s with %d parameters\n", runbookID, len(params))
	}
	
	// Get runbook parameters first to map names to IDs (for legacy API)
	rbParams, err := r.client.GetRunbookParameters(ctx, runbookID)
	if err != nil {
		return nil, fmt.Errorf("failed to get runbook parameters: %w", err)
	}
	
	// Create parameter mapping
	paramValues := make([]JobParameter, 0)
	for name, value := range params {
		// Find parameter ID for legacy API
		for _, p := range rbParams {
			if strings.EqualFold(p.Name, name) {
				paramValues = append(paramValues, JobParameter{
					Name:  name,
					Value: value,
				})
				break
			}
		}
	}
	
	// Start the job
	job, err := r.startJob(ctx, runbookID, paramValues, rbParams)
	if err != nil {
		return nil, fmt.Errorf("failed to start job: %w", err)
	}
	
	result := &JobExecutionResult{
		JobID:       job.ID,
		RunbookID:   runbookID,
		StartTime:   time.Now(),
		Status:      job.Status,
	}
	
	if !waitForCompletion {
		return result, nil
	}
	
	// Wait for completion
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	
	completedJob, err := r.client.WaitForJob(ctx, job.ID, timeout)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	
	result.Status = completedJob.Status
	result.EndTime = time.Now()
	
	// Get output data
	output, err := r.GetJobOutput(ctx, job.ID)
	if err == nil {
		result.OutputData = output
	}
	
	return result, nil
}

// startJob creates and starts a new job
func (r *RunbookOperator) startJob(ctx context.Context, runbookID string, params []JobParameter, rbParams []RunbookParameter) (*Job, error) {
	if r.client.apiVersion == APIVersionModern {
		return r.startJobModern(ctx, runbookID, params)
	}
	return r.startJobLegacy(ctx, runbookID, params, rbParams)
}

// startJobModern starts a job using the modern JSON API
func (r *RunbookOperator) startJobModern(ctx context.Context, runbookID string, params []JobParameter) (*Job, error) {
	req := CreateJobRequest{
		RunbookID:  runbookID,
		Parameters: params,
	}
	return r.client.CreateJob(ctx, req)
}

// startJobLegacy starts a job using the legacy OData API
func (r *RunbookOperator) startJobLegacy(ctx context.Context, runbookID string, params []JobParameter, rbParams []RunbookParameter) (*Job, error) {
	// Build parameter XML for legacy API
	paramXML := r.buildParameterXML(params, rbParams)
	
	// Build AtomPub entry
	entry := r.buildAtomPubJobEntry(runbookID, paramXML)
	
	url := r.client.baseURL + "/Orchestrator2012/Orchestrator.svc/Jobs"
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(entry))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/atom+xml")
	req.Header.Set("Accept", "application/atom+xml")
	r.client.setAuth(req)
	
	resp, err := r.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create job: %d - %s", resp.StatusCode, string(body))
	}
	
	// Parse response
	return r.parseAtomPubJobResponse(resp.Body)
}

// buildParameterXML builds the parameter XML for legacy API
func (r *RunbookOperator) buildParameterXML(params []JobParameter, rbParams []RunbookParameter) string {
	if len(params) == 0 {
		return ""
	}
	
	var sb strings.Builder
	sb.WriteString("<Data>")
	
	for _, param := range params {
		// Find parameter ID
		var paramID string
		for _, rp := range rbParams {
			if strings.EqualFold(rp.Name, param.Name) {
				paramID = rp.ID
				break
			}
		}
		
		if paramID != "" {
			sb.WriteString(fmt.Sprintf("<Parameter><ID>{%s}</ID><Value>%s</Value></Parameter>",
				paramID, xmlEscape(param.Value)))
		}
	}
	
	sb.WriteString("</Data>")
	return sb.String()
}

// buildAtomPubJobEntry builds the AtomPub entry for job creation
func (r *RunbookOperator) buildAtomPubJobEntry(runbookID, paramXML string) []byte {
	tmpl := `<?xml version="1.0" encoding="utf-8"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" 
       xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" 
       xmlns="http://www.w3.org/2005/Atom">
  <content type="application/xml">
    <m:properties>
      <d:RunbookId type="Edm.Guid">{{.RunbookID}}</d:RunbookId>
      <d:Parameters><![CDATA[{{.Parameters}}]]></d:Parameters>
    </m:properties>
  </content>
</entry>`
	
	t := template.Must(template.New("entry").Parse(tmpl))
	var buf bytes.Buffer
	t.Execute(&buf, map[string]string{
		"RunbookID":  runbookID,
		"Parameters": paramXML,
	})
	
	return buf.Bytes()
}

// parseAtomPubJobResponse parses the AtomPub job response
func (r *RunbookOperator) parseAtomPubJobResponse(body io.Reader) (*Job, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	
	// Parse XML response
	type AtomEntry struct {
		XMLName xml.Name `xml:"entry"`
		Content struct {
			Properties struct {
				ID       string `xml:"Id"`
				Status   string `xml:"Status"`
			} `xml:"properties"`
		} `xml:"content"`
	}
	
	var entry AtomEntry
	if err := xml.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	return &Job{
		ID:     entry.Content.Properties.ID,
		Status: entry.Content.Properties.Status,
	}, nil
}

// GetJobOutput retrieves the output data from a completed job
func (r *RunbookOperator) GetJobOutput(ctx context.Context, jobID string) (map[string]string, error) {
	var path string
	if r.client.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/jobs/%s/instances", jobID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Jobs(guid'%s')/Instances", jobID)
	}
	
	resp, err := r.client.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get job instances: %d", resp.StatusCode)
	}
	
	// Parse output - structure varies by API version
	output := make(map[string]string)
	
	// Get returned data from instances
	// This is a simplified implementation
	return output, nil
}

// StopRunbook stops a running runbook job
func (r *RunbookOperator) StopRunbook(ctx context.Context, jobID string) error {
	return r.client.StopJob(ctx, jobID)
}

// GetRunbookDetails retrieves detailed information about a runbook
func (r *RunbookOperator) GetRunbookDetails(ctx context.Context, runbookID string) (*RunbookDetails, error) {
	runbook, err := r.client.GetRunbook(ctx, runbookID)
	if err != nil {
		return nil, err
	}
	
	params, err := r.client.GetRunbookParameters(ctx, runbookID)
	if err != nil {
		params = []RunbookParameter{} // Non-fatal
	}
	
	details := &RunbookDetails{
		Runbook:    *runbook,
		Parameters: params,
	}
	
	// Get activities if available
	activities, err := r.GetRunbookActivities(ctx, runbookID)
	if err == nil {
		details.Activities = activities
	}
	
	return details, nil
}

// GetRunbookActivities retrieves activities within a runbook
func (r *RunbookOperator) GetRunbookActivities(ctx context.Context, runbookID string) ([]Activity, error) {
	var path string
	if r.client.apiVersion == APIVersionModern {
		path = fmt.Sprintf("/api/runbooks/%s/activities", runbookID)
	} else {
		path = fmt.Sprintf("/Orchestrator2012/Orchestrator.svc/Runbooks(guid'%s')/Activities", runbookID)
	}
	
	resp, err := r.client.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get activities: %d", resp.StatusCode)
	}
	
	var activities []Activity
	if err := json.NewDecoder(resp.Body).Decode(&activities); err != nil {
		return nil, err
	}
	
	return activities, nil
}

// EnumerateAll performs comprehensive enumeration of SCORCH
func (r *RunbookOperator) EnumerateAll(ctx context.Context) (*EnumerationResult, error) {
	result := &EnumerationResult{
		Timestamp:  time.Now(),
		Target:     r.client.baseURL,
		APIVersion: fmt.Sprintf("%d", r.client.apiVersion),
	}
	
	// Get runbooks
	runbooks, err := r.client.GetRunbooks(ctx)
	if err == nil {
		result.Runbooks = runbooks
	}
	
	// Get folders
	folders, err := r.client.GetFolders(ctx)
	if err == nil {
		result.Folders = folders
	}
	
	// Get runbook servers
	servers, err := r.client.GetRunbookServers(ctx)
	if err == nil {
		result.RunbookServers = servers
	}
	
	// Get recent jobs
	jobs, err := r.client.GetJobs(ctx, "")
	if err == nil {
		result.Jobs = jobs
	}
	
	return result, nil
}

// FindCredentialRunbooks searches for runbooks that likely handle credentials
func (r *RunbookOperator) FindCredentialRunbooks(ctx context.Context) ([]CredentialRunbook, error) {
	runbooks, err := r.client.GetRunbooks(ctx)
	if err != nil {
		return nil, err
	}
	
	// Keywords that suggest credential handling
	keywords := []string{
		"password", "credential", "secret", "key", "token",
		"auth", "login", "account", "service", "connect",
		"database", "sql", "ldap", "exchange", "vmm", "scom", "sccm",
	}
	
	var credRunbooks []CredentialRunbook
	
	for _, rb := range runbooks {
		matches := []string{}
		searchText := strings.ToLower(rb.Name + " " + rb.Description)
		
		for _, kw := range keywords {
			if strings.Contains(searchText, kw) {
				matches = append(matches, kw)
			}
		}
		
		if len(matches) > 0 {
			// Get parameters to identify credential inputs
			params, _ := r.client.GetRunbookParameters(ctx, rb.ID)
			
			var inputParams []string
			for _, p := range params {
				if p.Direction == "In" {
					inputParams = append(inputParams, p.Name)
				}
			}
			
			credRunbooks = append(credRunbooks, CredentialRunbook{
				Runbook:      rb,
				Keywords:     matches,
				InputParams:  inputParams,
				Confidence:   calculateConfidence(matches, inputParams),
			})
		}
	}
	
	return credRunbooks, nil
}

// GetJobHistory retrieves job history with optional filtering
func (r *RunbookOperator) GetJobHistory(ctx context.Context, runbookID string, status string, limit int) ([]Job, error) {
	filter := ""
	if runbookID != "" {
		filter = fmt.Sprintf("RunbookId eq guid'%s'", runbookID)
	}
	if status != "" {
		if filter != "" {
			filter += " and "
		}
		filter += fmt.Sprintf("Status eq '%s'", status)
	}
	
	jobs, err := r.client.GetJobs(ctx, filter)
	if err != nil {
		return nil, err
	}
	
	if limit > 0 && len(jobs) > limit {
		return jobs[:limit], nil
	}
	
	return jobs, nil
}

// ExportRunbook exports a runbook definition (if permissions allow)
func (r *RunbookOperator) ExportRunbook(ctx context.Context, runbookID string) (*RunbookExport, error) {
	// Get full runbook details
	details, err := r.GetRunbookDetails(ctx, runbookID)
	if err != nil {
		return nil, err
	}
	
	export := &RunbookExport{
		ExportTime: time.Now(),
		Runbook:    details.Runbook,
		Parameters: details.Parameters,
		Activities: details.Activities,
	}
	
	return export, nil
}

// MonitorJobs monitors jobs in real-time
func (r *RunbookOperator) MonitorJobs(ctx context.Context, pollInterval time.Duration, callback func([]Job)) error {
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}
	
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	
	seenJobs := make(map[string]string) // jobID -> status
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			jobs, err := r.client.GetJobs(ctx, "Status eq 'Running' or Status eq 'Pending'")
			if err != nil {
				continue
			}
			
			// Check for new or changed jobs
			var changedJobs []Job
			for _, job := range jobs {
				if lastStatus, seen := seenJobs[job.ID]; !seen || lastStatus != job.Status {
					changedJobs = append(changedJobs, job)
					seenJobs[job.ID] = job.Status
				}
			}
			
			if len(changedJobs) > 0 {
				callback(changedJobs)
			}
		}
	}
}

// Additional types for runbook operations

// JobExecutionResult holds the result of a runbook execution
type JobExecutionResult struct {
	JobID      string            `json:"job_id"`
	RunbookID  string            `json:"runbook_id"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time,omitempty"`
	Status     string            `json:"status"`
	OutputData map[string]string `json:"output_data,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// RunbookDetails contains detailed runbook information
type RunbookDetails struct {
	Runbook    Runbook            `json:"runbook"`
	Parameters []RunbookParameter `json:"parameters"`
	Activities []Activity         `json:"activities"`
}

// CredentialRunbook represents a runbook that likely handles credentials
type CredentialRunbook struct {
	Runbook     Runbook  `json:"runbook"`
	Keywords    []string `json:"keywords"`
	InputParams []string `json:"input_params"`
	Confidence  float64  `json:"confidence"`
}

// RunbookExport represents an exported runbook
type RunbookExport struct {
	ExportTime time.Time          `json:"export_time"`
	Runbook    Runbook            `json:"runbook"`
	Parameters []RunbookParameter `json:"parameters"`
	Activities []Activity         `json:"activities"`
	Definition string             `json:"definition,omitempty"` // Raw XML if available
}

// Helper functions

func xmlEscape(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func calculateConfidence(keywords, params []string) float64 {
	score := float64(len(keywords)) * 0.2
	
	// High-value keywords
	highValue := map[string]bool{
		"password": true, "credential": true, "secret": true, "token": true,
	}
	
	for _, kw := range keywords {
		if highValue[kw] {
			score += 0.3
		}
	}
	
	// Check parameters for credential indicators
	for _, p := range params {
		pLower := strings.ToLower(p)
		if strings.Contains(pLower, "password") || strings.Contains(pLower, "secret") {
			score += 0.2
		}
	}
	
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// QueryBuilder helps build OData queries
type QueryBuilder struct {
	filters  []string
	orderBy  string
	top      int
	skip     int
	expand   []string
	selectF  []string
}

// NewQueryBuilder creates a new query builder
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{}
}

// Filter adds a filter condition
func (q *QueryBuilder) Filter(condition string) *QueryBuilder {
	q.filters = append(q.filters, condition)
	return q
}

// OrderBy sets the order by clause
func (q *QueryBuilder) OrderBy(field string, desc bool) *QueryBuilder {
	q.orderBy = field
	if desc {
		q.orderBy += " desc"
	}
	return q
}

// Top limits the number of results
func (q *QueryBuilder) Top(n int) *QueryBuilder {
	q.top = n
	return q
}

// Skip skips the first n results
func (q *QueryBuilder) Skip(n int) *QueryBuilder {
	q.skip = n
	return q
}

// Expand expands related entities
func (q *QueryBuilder) Expand(entities ...string) *QueryBuilder {
	q.expand = append(q.expand, entities...)
	return q
}

// Select specifies which fields to return
func (q *QueryBuilder) Select(fields ...string) *QueryBuilder {
	q.selectF = append(q.selectF, fields...)
	return q
}

// Build constructs the query string
func (q *QueryBuilder) Build() string {
	params := url.Values{}
	
	if len(q.filters) > 0 {
		params.Set("$filter", strings.Join(q.filters, " and "))
	}
	
	if q.orderBy != "" {
		params.Set("$orderby", q.orderBy)
	}
	
	if q.top > 0 {
		params.Set("$top", fmt.Sprintf("%d", q.top))
	}
	
	if q.skip > 0 {
		params.Set("$skip", fmt.Sprintf("%d", q.skip))
	}
	
	if len(q.expand) > 0 {
		params.Set("$expand", strings.Join(q.expand, ","))
	}
	
	if len(q.selectF) > 0 {
		params.Set("$select", strings.Join(q.selectF, ","))
	}
	
	if len(params) == 0 {
		return ""
	}
	
	return "?" + params.Encode()
}
