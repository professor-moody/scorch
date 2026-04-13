# SCORCH v2.0.1 — Tier 2 Assessment & Exploitation Tool Review

**Reviewer:** Code Review Agent  
**Date:** 2025-07-11  
**Codebase:** scorch-tools v2.0.1 | Go 1.21 | 5,389 LoC | 11 source files  
**Scope:** Security logic correctness, operational reliability, architecture, test quality, maintainability

---

## Executive Summary

SCORCH is a focused, single-binary Go toolkit for offensive operations against Microsoft System Center Orchestrator deployments. It covers discovery, enumeration, assessment, credential extraction, runbook execution, and password spraying across the SCORCH attack surface (OData/REST API, SQL Server, LDAP, Kerberos).

**Overall verdict: Usable for targeted engagements with known caveats, but carries significant reliability risks that would cause operator pain on varied real-world deployments.**

The tool correctly implements NTLMv2, OData XML parsing, SQL-based credential extraction, and LDAP enumeration. However, it has **zero tests**, **stale transitive dependencies with 37 known CVEs** (17 module-level, 4 package-level, 16 stdlib symbol-level), several silent-failure paths that can suppress critical engagement data, and assessment checks that will produce false negatives against common SCORCH configurations. The prior review round (commit fdce174) fixed 12 issues including XML injection, OData filter injection, and TCP connection leaks — those fixes are verified clean.

**Would I trust this tool's output on an engagement tomorrow?** With reservations. The `dump`, `discover`, and `ntlm` modules are the strongest. The `assess` and `enum` modules have correctness issues that could mislead an operator. The `spray` module works but creates a new HTTP transport per attempt (no connection reuse), making it noisy.

---

## Findings

### P0 — Critical

*None identified at P0 level. Prior review addressed the critical issues (XML injection in exec, OData filter injection).*

---

### P1 — High

#### H-1: Severely Stale Dependencies (golang.org/x/crypto v0.18.0, golang.org/x/net v0.20.0)

**Files:** [go.mod](go.mod)  
**Evidence:** `govulncheck` reports 37 total vulnerabilities:
- **16 symbol-level** (Go stdlib, reachable in the binary): crypto/tls DoS, crypto/x509 chain validation bypass, net/url parsing bugs, net/http cookie memory exhaustion, encoding/asn1 memory exhaustion
- **4 package-level** (imported but not directly called): net/textproto CPU exhaustion, net/http cross-origin bypass
- **17 module-level** (in dependency tree): golang.org/x/crypto v0.18.0 has 5 CVEs (SSH auth bypass GO-2024-3321, DoS in ssh/agent), golang.org/x/net v0.20.0 has 5 CVEs (infinite parsing loop, XSS, proxy bypass)

**Impact:** The x/crypto SSH authorization bypass (GO-2024-3321) is in the dependency graph. While scorch doesn't use x/crypto/ssh directly (only md4), any downstream consumer or CI importing this module inherits the vuln. The stdlib vulns in crypto/tls and net/url are directly reachable.  
**Remediation:** `go get -u golang.org/x/crypto golang.org/x/net && go mod tidy`. Update `go.mod` directive to `go 1.22` minimum.

#### H-2: GetEvents Filter Parameter Not URL-Escaped (OData Injection)

**File:** [client.go](cmd/scorch/client.go#L612)  
**Evidence:** `GetJobs` correctly uses `url.QueryEscape(filter)` but `GetEvents` concatenates the filter raw:
```go
// GetJobs (correct):
path += "?$filter=" + url.QueryEscape(filter)

// GetEvents (vulnerable):
path += "?$filter=" + filter
```
Currently the only caller passes `""`, so this is not exploitable today. But the API is public and any future caller passing user-controlled input hits an OData injection path.  
**Impact:** Inconsistent security posture. If events filtering is ever exposed to user input, OData injection allows arbitrary query manipulation.  
**Remediation:** Apply `url.QueryEscape(filter)` to `GetEvents`, same as `GetJobs`.

#### H-3: NTLMv2 Domain Casing Bug — Username+Domain Concatenation

**File:** [ntlm.go](cmd/scorch/ntlm.go#L293-L296)  
**Evidence:**
```go
userDomain := toUnicode(strings.ToUpper(a.User) + strings.ToUpper(a.Domain))
```
The NTLMv2 spec (MS-NLMP §3.3.2) requires `UPPER(User) + UPPER(Domain)` for the NTLMv2 hash computation. This is correct. However, the **Type 3 message** at line 334 sends the domain and username in their **original casing**:
```go
domain := toUnicode(a.Domain)
user := toUnicode(a.User)
```
This is also correct per the spec (the response payload carries original strings; only the hash computation uppercases). **However**, some non-Microsoft NTLM implementations (e.g., certain IIS load balancers, WAFs) compare the Type 3 domain field case-sensitively. If the operator passes `-d corp` instead of `-d CORP`, authentication succeeds against standard Windows but may fail against intermediate proxies.

**More critically:** there is no validation that the NT hash (`-H` flag) is passed as lowercase hex. `hex.DecodeString` is case-insensitive, but the debug output and any hash comparison logging would be inconsistent. This is a minor correctness nit, not a functional bug.

**Impact:** Subtle auth failures in non-standard environments. Operators won't know why.  
**Remediation:** Document that `-d` should be the NetBIOS domain name (typically uppercase). Consider normalizing domain to uppercase in the `NTLMAuth` struct initialization.

#### H-4: Assessment checkNTLMRelay Produces False Negatives on HTTPS

**File:** [assess.go](cmd/scorch/assess.go#L224-L227)  
**Evidence:**
```go
func checkNTLMRelay(ctx context.Context, opts *CommonOpts, client *http.Client, result *AssessmentResult) {
    if opts.TLS {
        return // Relay much harder over HTTPS with proper certs
    }
```
This early return means the check **never runs** when `-tls` is used. But NTLM relay over HTTPS is absolutely possible when:
- The server doesn't enforce EPA (Extended Protection for Authentication / Channel Binding)
- Self-signed or misconfigured certificates are in use (common in SCORCH deployments)
- The `-k` (skip verify) flag is used, indicating the operator already knows certs are bad

The check should still run on HTTPS targets and report a lower-severity finding noting the EPA dependency.

**Impact:** False negative on a real finding. Operator gets a clean assess report for an HTTPS SCORCH server that is actually relay-vulnerable.  
**Remediation:** Remove the early return. Adjust severity to MEDIUM for HTTPS targets and note EPA dependency in the finding description.

---

### P2 — Medium

#### M-1: createJob Bypasses doRequest — No NTLM Body Replay

**File:** [exec.go](cmd/scorch/exec.go#L131-L147)  
**Evidence:** `createJob` constructs its own `http.NewRequestWithContext` and calls `client.httpClient.Do(req)` directly, bypassing `doRequest`. The `doRequest` method sets `req.GetBody` to allow NTLM transport to replay the request body during the 3-message handshake. `createJob` does not set `GetBody`.

```go
// exec.go line 140 — direct call, no GetBody
req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
...
resp, err := client.httpClient.Do(req)
```

**Impact:** Runbook execution (`scorch exec`) will fail when using NTLM authentication if the body is consumed during the first 401 response. The NTLM transport's `cloneRequest` calls `req.GetBody()` which returns nil, so `clone.Body` is nil on retry. The POST body is lost.  
**Remediation:** Set `req.GetBody` the same way `doRequest` does, or refactor `createJob` to use `doRequest`.

#### M-2: Spray Creates New Transport Per Attempt — No Connection Reuse

**File:** [spray.go](cmd/scorch/spray.go#L237-L260)  
**Evidence:** `tryAuth` creates a new `http.Transport` and `http.Client` for every single username/password combination:
```go
func tryAuth(...) SprayResult {
    transport := &http.Transport{...}
    client = &http.Client{Transport: ...}
```
With 1000 users × 3 passwords = 3000 new TCP connections, each with a full TLS handshake (if `-tls`). This is:
1. **Extremely slow** compared to connection-reusing approaches
2. **Very noisy** — 3000 distinct TCP connections from the same source IP
3. **Leaky** — transports are never closed, connections linger until GC

**Impact:** Poor operational performance and increased detection risk on real engagements. IDS/IPS will easily detect the connection storm.  
**Remediation:** For Basic auth spraying, share a single transport. For NTLM, the transport can still be shared (NTLM auth is per-connection, but the transport pool handles this). Create worker-level transports at minimum, not per-attempt.

#### M-3: Legacy OData XML Parsing Only Implemented for Runbooks

**File:** [client.go](cmd/scorch/client.go#L280-L313)  
**Evidence:** `GetRunbooks` has dual-format parsing (JSON + OData XML fallback via `parseODataRunbooks`). Every other endpoint (`GetRunbookServers`, `GetFolders`, `GetJobs`, `GetActivities`, `GetEvents`, `GetStatistics`, `GetJobInstances`) only parses JSON:
```go
// GetRunbookServers — JSON only
var result struct { Value []RunbookServer `json:"value"` }
json.NewDecoder(resp.Body).Decode(&result)
```
Legacy SCORCH (2012/2016) returns OData/AtomPub XML, not JSON. These endpoints will return empty results on legacy deployments because `json.Decode` will silently produce zero-value structs.

**Impact:** On legacy SCORCH (which is the most common deployment), everything except runbooks returns empty. The operator sees `[+] Runbook Servers (0)` and assumes the deployment has no servers. This is a **silent data loss** issue that will mislead operators.  
**Remediation:** Either implement OData XML parsing for all entity types, or clearly warn the user when the API is detected as "legacy" that only runbook enumeration is fully supported.

#### M-4: KerberosClient Never Closed — TGT Persists

**Files:** [client.go](cmd/scorch/client.go#L74-L81), [kerberos.go](internal/auth/kerberos.go#L183-L186)  
**Evidence:** `createKerberosClient` returns a `*auth.KerberosClient` that is stored in the `KerberosTransport` but never closed. The `KerberosClient.Close()` method calls `k.client.Destroy()` to clean up the TGT, but nothing calls it.

**Impact:** Minor resource leak. More importantly, the TGT stays in memory for the process lifetime. For a short-lived CLI tool this is acceptable, but it's poor hygiene for a security tool.  
**Remediation:** Store the Kerberos client in `HTTPClient` and close it in a `Close()` method that callers invoke with `defer`.

#### M-5: Concurrent Map Access in spray stopFlag

**File:** [spray.go](cmd/scorch/spray.go#L153-L168)  
**Evidence:** The `stopFlag` bool is protected by `stopMu` mutex, which is correct. However, workers check `stopFlag` inside the work loop but the **producer goroutine** doesn't check it — it continues feeding work into `workChan` even after `stopFlag` is set. The bounded channel buffer (numThreads*2) means the producer will eventually block, but only after filling the buffer with work that will be discarded.

This is a minor correctness issue, not a race. But it means that after `-stop` triggers, up to `numThreads*2` additional authentication attempts may be executed.

**Impact:** Extra auth attempts after a success was found, potentially triggering lockout on the next few accounts.  
**Remediation:** Either have the producer check a shared stop signal, or close a done channel that the producer selects on.

#### M-6: buildFolderPaths Has No Cycle Protection

**File:** [parse.go](cmd/scorch/parse.go#L238-L270)  
**Evidence:** The recursive `getPath` function builds folder paths by walking `folder.ParentID` up the tree. If a malicious/corrupt OIS export file has a folder cycle (A→B→A), this will stack overflow.
```go
var getPath func(id string) string
getPath = func(id string) string {
    ...
    parentPath := getPath(folder.ParentID) // recursive, no depth limit
```

**Impact:** Panic/crash when parsing adversarial OIS export files. Since `parse` operates on files obtained from the target, an adversary who controls the SCORCH deployment could craft an export that crashes the tool.  
**Remediation:** Add a `visited` set or depth counter.

---

### P3 — Low

#### L-1: Password Visible in Process Listings

**Files:** [main.go](cmd/scorch/main.go#L186-L192)  
**Evidence:** The `-p` / `-password` flag is passed as a command-line argument. On Linux/macOS, `ps aux` shows full command lines. Any co-located operator or monitoring agent can see the password.

**Impact:** Credential exposure on shared systems (jump boxes, shared VMs).  
**Remediation:** Support reading password from stdin or an environment variable (e.g., `SCORCH_PASSWORD`). Document the risk.

#### L-2: Output File Creation Uses os.Create (Truncates Existing)

**File:** [main.go](cmd/scorch/main.go#L316-L321)  
**Evidence:** `getOutput` uses `os.Create` which truncates any existing file at the output path. If the operator accidentally specifies an existing engagement file as output, data is silently destroyed.

**Impact:** Data loss of existing engagement artifacts.  
**Remediation:** Consider `os.OpenFile` with `O_CREATE|O_EXCL` for safety, or prompt/warn.

#### L-3: Assess checkAuthMethods Only Checks Legacy Endpoint

**File:** [assess.go](cmd/scorch/assess.go#L125-L131)  
**Evidence:** `checkAuthMethods` only probes `/Orchestrator2012/Orchestrator.svc/` for WWW-Authenticate headers. Modern SCORCH (2022+) uses `/api/` which may have different auth configuration.

**Impact:** Incomplete auth method discovery on modern deployments.

#### L-4: LDAP connectLDAP Hardcodes Port 389, No LDAPS Support

**File:** [discover.go](cmd/scorch/discover.go#L327-L328)  
**Evidence:**
```go
address := fmt.Sprintf("%s:389", ldapServer)
conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s", address))
```
LDAPS (port 636) is never used. In environments that disable LDAP (port 389) in favor of LDAPS-only, the entire LDAP enumeration and SPN discovery silently fails.

**Impact:** Complete LDAP enumeration failure in LDAPS-only environments. The error is reported but the operator may not realize it's a protocol issue.  
**Remediation:** Add `-ldaps` flag or auto-detect based on port scan results.

#### L-5: detect API Version Logic Can Misclassify

**File:** [client.go](cmd/scorch/client.go#L127-L155)  
**Evidence:** `DetectAPIVersion` tries the modern API first, and if it gets HTTP 200 or 401 with a JSON content-type, it classifies as "modern". Otherwise it falls through to legacy. But:
1. If the modern endpoint returns 401 with no Content-Type (common), it's classified as legacy
2. If a reverse proxy or WAF returns 200 for `/api/` with a JSON error page, it's classified as modern
3. If the legacy endpoint also fails, the code falls through and sets `apiVersion = "legacy"` without confirming the endpoint actually works

**Impact:** Misclassification causes all subsequent API calls to use wrong paths, resulting in silent 404s.

---

### Info

#### I-1: No Rate Limiting or Jitter in Password Spray

**File:** [spray.go](cmd/scorch/spray.go)  
The `-delay` flag adds a fixed sleep, not randomized jitter. Fixed intervals are easier to fingerprint by detection systems.

#### I-2: Version String Hardcoded in Source

**File:** [main.go](cmd/scorch/main.go#L13)  
`var version = "2.0.1"` — consider using `-ldflags` for build-time injection.

#### I-3: Unused `decryptDPAPI` Function

**File:** [dump.go](cmd/scorch/dump.go#L368-L385)  
Placeholder function that always returns an error. Dead code.

#### I-4: Kerberos auth.KerberosClient Implements RoundTripper Redundantly

**File:** [kerberos.go](internal/auth/kerberos.go#L169-L181)  
The `KerberosClient.RoundTrip` method is never called — `KerberosTransport` in client.go wraps the actual transport. The method on `KerberosClient` is dead code.

---

## Notable Strengths

1. **NTLMv2 implementation is correct.** The full Type 1/2/3 message construction, HMAC-MD5 computations, Unicode handling, and FILETIME generation all follow MS-NLMP faithfully. Pass-the-hash works correctly with the NTLMv2 response mechanism.

2. **SQL credential extraction is well-structured.** The `dump` command correctly handles the SCORCH encryption hierarchy (ORCHESTRATOR_SYM_KEY protected by ORCHESTRATOR_ASYM_KEY), CTE-based folder path resolution, connection XML parsing, and IP type classification. The Integration Pack filtering (`-ip AD`, `-ip SCOM`) is operationally useful.

3. **OData XML parsing handles real SCORCH response format.** The `parseODataRunbooks` function correctly handles the AtomPub entry/content/properties structure that real SCORCH 2012/2016 returns, not a simplified mock.

4. **LDAP enumeration covers the right surface.** The LDAP filters include gMSA/MSA object classes, SCORCH-specific group names (`OrchestratorSystemGroup`, etc.), and SPN patterns on ports 81/82. This shows SCORCH domain knowledge.

5. **OIS export parser extracts variable references.** The `findVariableRefs` function traces GUID-based variable references (`\`d.T.~Vb/{guid}\`d.T.~Vb/`) through activity parameters back to named variables — non-trivial domain logic that's valuable for offline analysis.

6. **Previous review fixes are solid.** XML escaping in `exec.go`, OData filter escaping in `client.go`, body replay via `GetBody`, bounded channel in spray, TCP leak fix in scanner — all verified clean in the current code.

---

## Residual Risk Areas

| Risk | Likelihood | Impact | Area |
|------|-----------|--------|------|
| Silent empty results on legacy SCORCH (all endpoints except runbooks) | **High** | **High** | enum, client |
| False negative on NTLM relay assessment over HTTPS | **High** | **Medium** | assess |
| Runbook execution failure with NTLM auth (missing GetBody) | **Medium** | **High** | exec |
| Dependency CVEs in x/crypto and x/net exploitable by malicious target | **Low** | **Medium** | go.mod |
| Spray connection storm triggering detection/lockout | **High** | **Medium** | spray |
| LDAP enumeration failure in LDAPS-only environments | **Medium** | **Medium** | discover |
| Folder cycle in adversarial OIS export causing crash | **Low** | **Low** | parse |

---

## Target Coverage Matrix

| Target Component | Commands | Auth Methods | Completeness |
|-----------------|----------|-------------|--------------|
| SCORCH OData API (port 81) | enum, assess, exec | NTLM, Kerberos, Basic | **Partial** — Legacy XML only for runbooks |
| SCORCH Web Console (port 82) | assess (port scan) | — | **Minimal** — Port scan only |
| SQL Server (port 1433) | dump | SQL Auth, Windows Auth | **Strong** — Full extraction + decryption |
| LDAP (port 389) | discover | Simple bind (UPN) | **Good** — No LDAPS, no NTLM bind |
| Kerberos (port 88) | discover (SPN) | Password, Keytab, CCache | **Good** — Full gokrb5 integration |
| Password Spraying | spray | NTLM, Basic | **Functional** — Performance issues |
| OIS Export Files | parse | N/A (offline) | **Strong** — Full export parsing |
| Modern SCORCH API (2022+) | enum, exec | Same as OData | **Untested** — JSON path exists but unvalidated |

---

## Next Inspection Targets

1. **exec.go createJob** — Needs integration testing with NTLM auth to confirm the GetBody bug manifests
2. **client.go DetectAPIVersion** — Needs testing against actual SCORCH 2022 to validate the modern API detection logic
3. **dump.go decryptVariables** — The hex extraction from `\`d.T.~De/[hex]\`d.T.~De/` format should be validated against real encrypted variable samples to confirm offset math
4. **ntlm.go NTLMv2** — Cross-validate against a known-good NTLMv2 test vector (e.g., MS-NLMP §4.2.4 examples) to confirm computational correctness
5. **spray.go** — Load test to quantify the connection-per-attempt overhead and measure detection signatures
6. **Module dependencies** — `golang.org/x/crypto` and `golang.org/x/net` need immediate update; re-run `govulncheck` after update

---

## Dependency Vulnerability Summary

| Module | Current | Fixed In | CVE Count | Severity |
|--------|---------|----------|-----------|----------|
| golang.org/x/crypto | v0.18.0 | v0.45.0 | 5 | SSH auth bypass, DoS |
| golang.org/x/net | v0.20.0 | v0.45.0 | 5 | Infinite loop, XSS, proxy bypass |
| Go stdlib (go1.25) | go1.25.0 | go1.25.9 | 16 (symbol) + 4 (package) + 7 (module) | TLS DoS, x509 bypass, URL parsing |

**Note:** The stdlib vulnerabilities are tied to the local Go toolchain version (go1.25.0), not the `go 1.21` directive in go.mod. Updating the toolchain to go1.25.9+ resolves the stdlib issues. The x/crypto and x/net issues require `go get -u`.

---

*Review conducted against commit fdce174 (origin/dev). Zero test files exist in the codebase — all findings are from static analysis and code reading only.*
