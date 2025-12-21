package db

import (
	"time"
)

// DatabaseConfig holds configuration for database connections
type DatabaseConfig struct {
	Server          string
	Port            int
	Database        string
	Username        string
	Password        string
	UseTrustedAuth  bool
	ApplicationName string
	Timeout         time.Duration
}

// EncryptedVariable represents a variable from the database
type EncryptedVariable struct {
	UniqueID       string `db:"UniqueID"`
	Name           string `db:"Name"`
	EncryptedValue string `db:"Value"`
	DecryptedValue string `db:"-"` // Populated after decryption
	FolderPath     string `db:"FolderPath"`
	IsEncrypted    bool   `db:"-"`
	Deleted        bool   `db:"Deleted"`
}

// RunbookCredential represents credentials found in runbook activities
type RunbookCredential struct {
	RunbookID       string `db:"RunbookID"`
	RunbookName     string `db:"RunbookName"`
	RunbookPath     string `db:"RunbookPath"`
	ActivityID      string `db:"ActivityID"`
	ActivityName    string `db:"ActivityName"`
	ActivityType    string `db:"ActivityType"`
	CredentialType  string `db:"CredentialType"`
	Username        string `db:"Username"`
	EncryptedPassword string `db:"Password"`
	DecryptedPassword string `db:"-"`
	Server          string `db:"Server"`
	Domain          string `db:"Domain"`
}

// IntegrationPackConnection represents stored IP connection credentials
type IntegrationPackConnection struct {
	ID                string `db:"UniqueID"`
	Name              string `db:"Name"`
	IntegrationPackID string `db:"IntegrationPackID"`
	IntegrationPack   string `db:"IntegrationPackName"`
	Server            string `db:"Server"`
	Port              int    `db:"Port"`
	Domain            string `db:"Domain"`
	Username          string `db:"Username"`
	EncryptedPassword string `db:"Password"`
	DecryptedPassword string `db:"-"`
	ConfigurationXML  string `db:"Configuration"`
}

// DatabaseQueryCredential represents credentials in Query Database activities
type DatabaseQueryCredential struct {
	ActivityID        string `db:"UniqueID"`
	ActivityName      string `db:"Name"`
	RunbookID         string `db:"PolicyID"`
	RunbookName       string `db:"PolicyName"`
	ConnectionString  string `db:"ConnectionString"`
	Server            string `db:"Server"`
	Database          string `db:"Database"`
	Username          string `db:"Username"`
	EncryptedPassword string `db:"Password"`
	DecryptedPassword string `db:"-"`
	AuthenticationType string `db:"AuthType"`
}

// SCORCHDatabaseInfo holds information about the SCORCH database
type SCORCHDatabaseInfo struct {
	DatabaseName      string
	ServerName        string
	Version           string
	HasSymmetricKey   bool
	HasAsymmetricKey  bool
	EncryptionEnabled bool
	TotalVariables    int
	EncryptedVariables int
	TotalRunbooks     int
	TotalConnections  int
}

// ExtractionResult holds all extracted credentials
type ExtractionResult struct {
	DatabaseInfo      SCORCHDatabaseInfo              `json:"database_info"`
	Variables         []EncryptedVariable             `json:"variables"`
	RunbookCredentials []RunbookCredential           `json:"runbook_credentials"`
	IPConnections     []IntegrationPackConnection    `json:"ip_connections"`
	DBQueryCredentials []DatabaseQueryCredential     `json:"db_query_credentials"`
	ExtractionTime    time.Time                       `json:"extraction_time"`
	DecryptionSuccess bool                            `json:"decryption_success"`
	Errors            []string                        `json:"errors,omitempty"`
}

// SQL Query constants for SCORCH database

// QueryCheckEncryptionKeys checks if encryption keys exist
const QueryCheckEncryptionKeys = `
SELECT 
    (SELECT COUNT(*) FROM sys.symmetric_keys WHERE name = 'ORCHESTRATOR_SYM_KEY') as HasSymKey,
    (SELECT COUNT(*) FROM sys.asymmetric_keys WHERE name = 'ORCHESTRATOR_ASYM_KEY') as HasAsymKey
`

// QueryOpenSymmetricKey opens the symmetric key for decryption
const QueryOpenSymmetricKey = `
OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY 
    DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY
`

// QueryCloseSymmetricKey closes the symmetric key
const QueryCloseSymmetricKey = `
CLOSE SYMMETRIC KEY ORCHESTRATOR_SYM_KEY
`

// QueryGetVariables retrieves all variables with their encrypted values
const QueryGetVariables = `
WITH VariablePath AS (
    SELECT 'Variables\' + CAST(name AS VARCHAR(MAX)) AS [path], uniqueid
    FROM dbo.FOLDERS b
    WHERE b.ParentID = '00000000-0000-0000-0000-000000000005' 
        AND disabled = 0 AND deleted = 0
    UNION ALL
    SELECT CAST(c.[path] + '\' + CAST(b.name AS VARCHAR(MAX)) AS VARCHAR(MAX)), b.uniqueid
    FROM dbo.FOLDERS b
    INNER JOIN VariablePath c ON b.ParentID = c.UniqueID
    WHERE b.Disabled = 0 AND b.Deleted = 0
)
SELECT 
    o.UniqueID,
    o.Name,
    v.Value,
    ISNULL(vp.[path], 'Variables') AS FolderPath,
    o.Deleted
FROM [dbo].[VARIABLES] v
INNER JOIN [dbo].[OBJECTS] o ON o.UniqueID = v.UniqueID
LEFT JOIN VariablePath vp ON o.ParentID = vp.UniqueID
WHERE o.Deleted = 0
`

// QueryDecryptVariable decrypts a single variable value
const QueryDecryptVariable = `
SELECT 
    CASE 
        WHEN @value LIKE '%~De/%' 
        THEN CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(
            CONVERT(VARBINARY(MAX), 
                SUBSTRING(@value, CHARINDEX('/', @value) + 1, 
                    LEN(@value) - (2 * CHARINDEX('/', @value))), 2)))
        ELSE @value 
    END AS DecryptedValue
`

// QueryGetRunbookCredentials retrieves credentials from various activity types
const QueryGetRunbookCredentials = `
WITH RunbookPath AS (
    SELECT 'Policies\' + CAST(name AS VARCHAR(MAX)) AS [path], uniqueid
    FROM dbo.FOLDERS b
    WHERE b.ParentID = '00000000-0000-0000-0000-000000000000' 
        AND disabled = 0 AND deleted = 0
    UNION ALL
    SELECT CAST(c.[path] + '\' + CAST(b.name AS VARCHAR(MAX)) AS VARCHAR(MAX)), b.uniqueid
    FROM dbo.FOLDERS b
    INNER JOIN RunbookPath c ON b.ParentID = c.UniqueID
    WHERE b.Disabled = 0 AND b.Deleted = 0
)
SELECT 
    r.UniqueID AS RunbookID,
    r.Name AS RunbookName,
    ISNULL(rp.[path], 'Policies') AS RunbookPath,
    o.UniqueID AS ActivityID,
    o.Name AS ActivityName,
    o.ObjectType AS ActivityType,
    'QueryDatabase' AS CredentialType,
    qd.Username,
    qd.Password,
    qd.Server,
    '' AS Domain
FROM dbo.POLICIES r
INNER JOIN RunbookPath rp ON r.ParentID = rp.UniqueID
INNER JOIN dbo.OBJECTS o ON o.ParentID = r.UniqueID
INNER JOIN dbo.TASK_QUERYDATABASE qd ON qd.UniqueID = o.UniqueID
WHERE r.Deleted = 0 AND o.Deleted = 0
    AND qd.Password IS NOT NULL 
    AND qd.Password <> ''
`

// QueryGetIPConnections retrieves Integration Pack connection configurations
const QueryGetIPConnections = `
SELECT 
    c.UniqueID,
    c.Name,
    ip.UniqueID AS IntegrationPackID,
    ip.Name AS IntegrationPackName,
    c.Configuration
FROM dbo.CONNECTIONS c
INNER JOIN dbo.INTEGRATION_PACKS ip ON c.IntegrationPackID = ip.UniqueID
WHERE c.Deleted = 0
`

// QueryGetDatabaseInfo retrieves SCORCH database metadata
const QueryGetDatabaseInfo = `
SELECT 
    DB_NAME() AS DatabaseName,
    @@SERVERNAME AS ServerName,
    (SELECT TOP 1 Value FROM dbo.CONFIGURATION WHERE Name = 'Version') AS Version,
    (SELECT COUNT(*) FROM dbo.VARIABLES v INNER JOIN dbo.OBJECTS o ON v.UniqueID = o.UniqueID WHERE o.Deleted = 0) AS TotalVariables,
    (SELECT COUNT(*) FROM dbo.VARIABLES v INNER JOIN dbo.OBJECTS o ON v.UniqueID = o.UniqueID WHERE o.Deleted = 0 AND v.Value LIKE '%~De/%') AS EncryptedVariables,
    (SELECT COUNT(*) FROM dbo.POLICIES WHERE Deleted = 0) AS TotalRunbooks,
    (SELECT COUNT(*) FROM dbo.CONNECTIONS WHERE Deleted = 0) AS TotalConnections
`

// QueryGetRunbookServers retrieves runbook server information
const QueryGetRunbookServers = `
SELECT 
    UniqueID,
    Name,
    Computer,
    LastHeartbeat,
    MaxRunningJobs,
    Running
FROM dbo.RUNBOOKSERVERS
WHERE Deleted = 0
`

// EncryptionMarkerPrefix is the prefix used for encrypted values in SCORCH
const EncryptionMarkerPrefix = "`d.T.~De/"

// EncryptionMarkerSuffix is the suffix used for encrypted values in SCORCH
const EncryptionMarkerSuffix = "`d.T.~De/"

// IsEncryptedValue checks if a value is encrypted based on SCORCH markers
func IsEncryptedValue(value string) bool {
	return len(value) > 0 && 
		(contains(value, "~De/") || contains(value, "~Ec/"))
}

// Helper function for string contains check
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ExtractHexFromEncrypted extracts the hex portion from an encrypted value
func ExtractHexFromEncrypted(value string) string {
	// Format: `d.T.~De/[hex_data]`d.T.~De/
	// We need to extract the hex data between the markers
	start := 0
	end := len(value)
	
	// Find start marker
	for i := 0; i < len(value)-3; i++ {
		if value[i:i+1] == "/" {
			start = i + 1
			break
		}
	}
	
	// Find end marker (search from end)
	for i := len(value) - 1; i > start; i-- {
		if value[i:i+1] == "/" {
			// Check if this is part of the end marker
			if i > 0 && value[i-1:i] != "\\" {
				end = i
				break
			}
		}
	}
	
	if start >= end {
		return value
	}
	
	return value[start:end]
}
