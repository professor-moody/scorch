package api

import (
	"time"
)

// Runbook represents a SCORCH runbook
type Runbook struct {
	ID                string    `json:"Id"`
	Name              string    `json:"Name"`
	Description       string    `json:"Description"`
	FolderID          string    `json:"FolderId"`
	FolderPath        string    `json:"FolderPath"`
	Path              string    `json:"Path"`
	CheckedOutBy      string    `json:"CheckedOutBy"`
	CheckOutTime      time.Time `json:"CheckOutTime"`
	CreationTime      time.Time `json:"CreationTime"`
	LastModifiedBy    string    `json:"LastModifiedBy"`
	LastModifiedTime  time.Time `json:"LastModifiedTime"`
	IsMonitor         bool      `json:"IsMonitor"`
	Published         bool      `json:"Published"`
}

// RunbookParameter represents a runbook input/output parameter
type RunbookParameter struct {
	ID          string `json:"Id"`
	RunbookID   string `json:"RunbookId"`
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Direction   string `json:"Direction"` // "In" or "Out"
	Description string `json:"Description"`
}

// Job represents a SCORCH job instance
type Job struct {
	ID              string    `json:"Id"`
	RunbookID       string    `json:"RunbookId"`
	Status          string    `json:"Status"`
	CreationTime    time.Time `json:"CreationTime"`
	LastModifiedTime time.Time `json:"LastModifiedTime"`
	CompletionTime  time.Time `json:"CompletionTime"`
	CreatedBy       string    `json:"CreatedBy"`
	RunbookServerID string    `json:"RunbookServerId"`
	Parameters      string    `json:"Parameters"`
}

// JobInstance represents a specific execution of a job
type JobInstance struct {
	ID         string    `json:"Id"`
	JobID      string    `json:"JobId"`
	Status     string    `json:"Status"`
	StartTime  time.Time `json:"StartTime"`
	EndTime    time.Time `json:"EndTime"`
}

// RunbookServer represents a SCORCH runbook server
type RunbookServer struct {
	ID              string    `json:"Id"`
	Name            string    `json:"Name"`
	LastHeartbeat   time.Time `json:"LastHeartbeat"`
	MachineName     string    `json:"MachineName"`
	RunningJobs     int       `json:"RunningJobs"`
	MaxRunningJobs  int       `json:"MaxRunningJobs"`
	Available       bool      `json:"Available"`
}

// Folder represents a SCORCH folder
type Folder struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Path        string `json:"Path"`
	ParentID    string `json:"ParentId"`
	Description string `json:"Description"`
}

// Activity represents a SCORCH activity within a runbook
type Activity struct {
	ID          string `json:"Id"`
	RunbookID   string `json:"RunbookId"`
	Name        string `json:"Name"`
	Type        string `json:"Type"`
	Description string `json:"Description"`
}

// Variable represents a SCORCH global variable
type Variable struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Value       string `json:"Value"`
	Description string `json:"Description"`
	Encrypted   bool   `json:"Encrypted"`
	FolderPath  string `json:"FolderPath"`
}

// Connection represents an Integration Pack connection
type Connection struct {
	ID              string            `json:"Id"`
	Name            string            `json:"Name"`
	IntegrationPack string            `json:"IntegrationPack"`
	Type            string            `json:"Type"`
	Properties      map[string]string `json:"Properties"`
	Credentials     *ConnectionCreds  `json:"Credentials,omitempty"`
}

// ConnectionCreds holds decrypted credentials for a connection
type ConnectionCreds struct {
	Server   string `json:"Server"`
	Domain   string `json:"Domain"`
	Username string `json:"Username"`
	Password string `json:"Password"`
}

// JobStatus constants
const (
	JobStatusPending   = "Pending"
	JobStatusRunning   = "Running"
	JobStatusCompleted = "Completed"
	JobStatusFailed    = "Failed"
	JobStatusCanceled  = "Canceled"
)

// OData response wrappers for legacy API

// ODataResponse is the wrapper for OData responses
type ODataResponse struct {
	Value    interface{} `json:"value"`
	NextLink string      `json:"@odata.nextLink,omitempty"`
	Count    int         `json:"@odata.count,omitempty"`
}

// ODataRunbooksResponse wraps runbook list responses
type ODataRunbooksResponse struct {
	Value    []Runbook `json:"value"`
	NextLink string    `json:"@odata.nextLink,omitempty"`
}

// ODataJobsResponse wraps job list responses
type ODataJobsResponse struct {
	Value    []Job  `json:"value"`
	NextLink string `json:"@odata.nextLink,omitempty"`
}

// CreateJobRequest is the request body for creating a new job
type CreateJobRequest struct {
	RunbookID       string              `json:"RunbookId"`
	RunbookServers  []string            `json:"RunbookServers,omitempty"`
	Parameters      []JobParameter      `json:"Parameters,omitempty"`
	CreatedBy       string              `json:"CreatedBy,omitempty"`
}

// JobParameter represents a parameter passed to a job
type JobParameter struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

// LegacyJobRequest is the XML structure for legacy OData API
type LegacyJobRequest struct {
	RunbookID  string `xml:"RunbookId"`
	Parameters string `xml:"Parameters"` // CDATA wrapped parameter XML
}

// EnumerationResult holds the results of SCORCH enumeration
type EnumerationResult struct {
	Runbooks       []Runbook        `json:"runbooks"`
	Folders        []Folder         `json:"folders"`
	RunbookServers []RunbookServer  `json:"runbook_servers"`
	Variables      []Variable       `json:"variables"`
	Connections    []Connection     `json:"connections"`
	Jobs           []Job            `json:"jobs"`
	Timestamp      time.Time        `json:"timestamp"`
	Target         string           `json:"target"`
	APIVersion     string           `json:"api_version"`
}
