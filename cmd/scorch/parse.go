package main

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

// OIS Export XML structures
type ExportData struct {
	XMLName   xml.Name    `xml:"ExportData"`
	Folders   []OISFolder `xml:"Folders>Folder"`
	Policies  []Policy    `xml:"Policies>Policy"`
	Variables []OISVar    `xml:"Variables>Variable"`
	Schedules []Schedule  `xml:"Schedules>Schedule"`
	Counters  []Counter   `xml:"Counters>Counter"`
}

type OISFolder struct {
	UniqueID    string `xml:"UniqueID" json:"unique_id"`
	ParentID    string `xml:"ParentID" json:"parent_id"`
	Name        string `xml:"Name" json:"name"`
	Description string `xml:"Description" json:"description,omitempty"`
}

type OISVar struct {
	UniqueID    string `xml:"UniqueID" json:"unique_id"`
	ParentID    string `xml:"ParentID" json:"parent_id"`
	Name        string `xml:"Name" json:"name"`
	Value       string `xml:"Value" json:"value,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
	IsEncrypted bool   `xml:"IsEncrypted" json:"is_encrypted"`
}

type Policy struct {
	UniqueID    string       `xml:"UniqueID" json:"unique_id"`
	ParentID    string       `xml:"ParentID" json:"parent_id"`
	Name        string       `xml:"Name" json:"name"`
	Description string       `xml:"Description" json:"description,omitempty"`
	Objects     []PolicyObj  `xml:"Object" json:"objects,omitempty"`
	Links       []PolicyLink `xml:"Link" json:"links,omitempty"`
}

type PolicyObj struct {
	UniqueID   string     `xml:"UniqueID" json:"unique_id"`
	Name       string     `xml:"Name" json:"name"`
	ObjectType string     `xml:"ObjectType" json:"object_type"`
	Parameters []OISParam `xml:"ObjectProperties>Property" json:"parameters,omitempty"`
}

type OISParam struct {
	Name  string `xml:"Name,attr" json:"name"`
	Value string `xml:",chardata" json:"value,omitempty"`
}

type PolicyLink struct {
	UniqueID string `xml:"UniqueID" json:"unique_id"`
	SourceID string `xml:"SourceObject" json:"source_id"`
	TargetID string `xml:"TargetObject" json:"target_id"`
}

type Schedule struct {
	UniqueID string `xml:"UniqueID" json:"unique_id"`
	Name     string `xml:"Name" json:"name"`
}

type Counter struct {
	UniqueID string `xml:"UniqueID" json:"unique_id"`
	Name     string `xml:"Name" json:"name"`
	Value    int    `xml:"Value" json:"value"`
}

// Encrypted value markers
const (
	EncryptedPrefix     = "`d.T.~De/"
	EncryptedSuffix     = "`d.T.~De/"
	VariableRefPrefix   = "`d.T.~Vb/{"
	VariableRefSuffix   = "}`d.T.~Vb/"
	RootVariablesFolder = "00000000-0000-0000-0000-000000000005"
)

// ParseResult holds parsed OIS data
type ParseResult struct {
	FilePath    string           `json:"file_path"`
	Folders     int              `json:"folder_count"`
	Runbooks    int              `json:"runbook_count"`
	Variables   int              `json:"variable_count"`
	Encrypted   int              `json:"encrypted_count"`
	VarDetails  []ParsedVariable `json:"variables,omitempty"`
	RunbookList []ParsedRunbook  `json:"runbooks,omitempty"`
}

type ParsedVariable struct {
	Name           string `json:"name"`
	Path           string `json:"path,omitempty"`
	Value          string `json:"value,omitempty"`
	IsEncrypted    bool   `json:"is_encrypted"`
	EncryptedBytes string `json:"encrypted_hex,omitempty"`
}

type ParsedRunbook struct {
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Description string   `json:"description,omitempty"`
	Activities  int      `json:"activity_count"`
	VarRefs     []string `json:"variable_refs,omitempty"`
}

func runParse(args []string) error {
	if containsHelp(args) {
		printParseHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	filePath, remaining := parseFlag(remaining, "-f", "--file")
	if filePath == "" && len(remaining) > 0 {
		filePath = remaining[0]
	}

	if filePath == "" {
		printParseHelp()
		return nil
	}

	varsOnly, remaining := parseBoolFlag(remaining, "-vars", "--vars")
	encryptedOnly, remaining := parseBoolFlag(remaining, "-encrypted", "--encrypted")
	runbooksOnly, remaining := parseBoolFlag(remaining, "-runbooks", "--runbooks")
	showRefs, _ := parseBoolFlag(remaining, "-refs", "--refs")

	// Determine output
	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	printf(opts, "[*] Parsing OIS export file: %s\n", filePath)

	// Parse the file
	exportData, err := parseOISFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse file: %w", err)
	}

	// Build folder path map
	folderPaths := buildFolderPaths(exportData.Folders)

	// Build result
	result := &ParseResult{
		FilePath:  filePath,
		Folders:   len(exportData.Folders),
		Runbooks:  len(exportData.Policies),
		Variables: len(exportData.Variables),
	}

	// Process variables
	for _, v := range exportData.Variables {
		pv := ParsedVariable{
			Name:        v.Name,
			Path:        folderPaths[v.ParentID],
			IsEncrypted: v.IsEncrypted || isEncryptedValue(v.Value),
		}

		if pv.IsEncrypted {
			result.Encrypted++
			hexData := extractEncryptedHex(v.Value)
			if hexData != "" {
				pv.EncryptedBytes = hexData
			}
		} else {
			pv.Value = v.Value
		}

		result.VarDetails = append(result.VarDetails, pv)
	}

	// Process runbooks
	varMap := buildVariableMap(exportData.Variables)
	for _, p := range exportData.Policies {
		pr := ParsedRunbook{
			Name:        p.Name,
			Path:        folderPaths[p.ParentID],
			Description: p.Description,
			Activities:  len(p.Objects),
		}

		// Find variable references in activities
		if showRefs {
			refs := findVariableRefs(p, varMap)
			pr.VarRefs = refs
		}

		result.RunbookList = append(result.RunbookList, pr)
	}

	// Output based on flags
	if opts.JSON {
		return writeJSON(output, result)
	}

	// Text output
	if varsOnly || encryptedOnly {
		printVariables(output, result, encryptedOnly)
	} else if runbooksOnly {
		printRunbooks(output, result, showRefs)
	} else {
		printParseSummary(output, result)
	}

	return nil
}

func parseOISFile(filepath string) (*ExportData, error) {
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

func buildFolderPaths(folders []OISFolder) map[string]string {
	paths := make(map[string]string)
	folderMap := make(map[string]OISFolder)

	for _, f := range folders {
		folderMap[f.UniqueID] = f
	}

	var getPath func(id string) string
	getPath = func(id string) string {
		if cached, ok := paths[id]; ok {
			return cached
		}

		folder, ok := folderMap[id]
		if !ok {
			return ""
		}

		if folder.ParentID == "" || folder.ParentID == "00000000-0000-0000-0000-000000000000" ||
			folder.ParentID == RootVariablesFolder {
			paths[id] = folder.Name
			return folder.Name
		}

		parentPath := getPath(folder.ParentID)
		if parentPath != "" {
			paths[id] = parentPath + "\\" + folder.Name
		} else {
			paths[id] = folder.Name
		}
		return paths[id]
	}

	for _, f := range folders {
		getPath(f.UniqueID)
	}

	return paths
}

func buildVariableMap(vars []OISVar) map[string]OISVar {
	m := make(map[string]OISVar)
	for _, v := range vars {
		m[v.UniqueID] = v
	}
	return m
}

func isEncryptedValue(value string) bool {
	return strings.Contains(value, EncryptedPrefix)
}

func extractEncryptedHex(value string) string {
	if !strings.Contains(value, EncryptedPrefix) {
		return ""
	}

	start := strings.Index(value, EncryptedPrefix)
	if start == -1 {
		return ""
	}
	start += len(EncryptedPrefix)

	end := strings.LastIndex(value, EncryptedSuffix)
	if end <= start {
		return ""
	}

	hexData := value[start:end]
	// Validate it's hex
	if _, err := hex.DecodeString(hexData); err != nil {
		return ""
	}
	return hexData
}

func findVariableRefs(policy Policy, varMap map[string]OISVar) []string {
	var refs []string
	seen := make(map[string]bool)

	for _, obj := range policy.Objects {
		for _, param := range obj.Parameters {
			// Find variable references in parameter values
			value := param.Value
			for strings.Contains(value, VariableRefPrefix) {
				start := strings.Index(value, VariableRefPrefix)
				if start == -1 {
					break
				}
				start += len(VariableRefPrefix)

				end := strings.Index(value[start:], VariableRefSuffix)
				if end == -1 {
					break
				}

				guid := value[start : start+end]
				if v, ok := varMap[guid]; ok && !seen[v.Name] {
					refs = append(refs, v.Name)
					seen[v.Name] = true
				}

				value = value[start+end:]
			}
		}
	}

	return refs
}

func printParseSummary(w io.Writer, result *ParseResult) {
	fmt.Fprintf(w, "\n[+] OIS Export Summary: %s\n", result.FilePath)
	fmt.Fprintln(w, strings.Repeat("=", 50))
	fmt.Fprintf(w, "  Folders:   %d\n", result.Folders)
	fmt.Fprintf(w, "  Runbooks:  %d\n", result.Runbooks)
	fmt.Fprintf(w, "  Variables: %d (%d encrypted)\n", result.Variables, result.Encrypted)

	if result.Encrypted > 0 {
		fmt.Fprintln(w, "\n[!] Encrypted Variables Found:")
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for _, v := range result.VarDetails {
			if v.IsEncrypted {
				path := v.Path
				if path != "" {
					path += "\\"
				}
				fmt.Fprintf(w, "  %s%s\n", path, v.Name)
			}
		}
	}

	if len(result.RunbookList) > 0 {
		fmt.Fprintf(w, "\n[+] Runbooks (%d)\n", len(result.RunbookList))
		fmt.Fprintln(w, strings.Repeat("-", 40))
		for _, r := range result.RunbookList {
			path := r.Path
			if path != "" {
				path += "\\"
			}
			fmt.Fprintf(w, "  %s%s (%d activities)\n", path, r.Name, r.Activities)
		}
	}

	fmt.Fprintln(w)
}

func printVariables(w io.Writer, result *ParseResult, encryptedOnly bool) {
	title := "Variables"
	if encryptedOnly {
		title = "Encrypted Variables"
	}
	fmt.Fprintf(w, "\n[+] %s\n", title)
	fmt.Fprintln(w, strings.Repeat("-", 50))

	for _, v := range result.VarDetails {
		if encryptedOnly && !v.IsEncrypted {
			continue
		}

		path := v.Path
		if path != "" {
			path += "\\"
		}

		if v.IsEncrypted {
			fmt.Fprintf(w, "  %s%s = [ENCRYPTED]\n", path, v.Name)
			if v.EncryptedBytes != "" {
				// Show first 32 chars of hex
				preview := v.EncryptedBytes
				if len(preview) > 64 {
					preview = preview[:64] + "..."
				}
				fmt.Fprintf(w, "    Hex: %s\n", preview)
			}
		} else {
			value := v.Value
			if len(value) > 50 {
				value = value[:50] + "..."
			}
			fmt.Fprintf(w, "  %s%s = %s\n", path, v.Name, value)
		}
	}
	fmt.Fprintln(w)
}

func printRunbooks(w io.Writer, result *ParseResult, showRefs bool) {
	fmt.Fprintf(w, "\n[+] Runbooks (%d)\n", len(result.RunbookList))
	fmt.Fprintln(w, strings.Repeat("-", 50))

	for _, r := range result.RunbookList {
		path := r.Path
		if path != "" {
			path += "\\"
		}
		fmt.Fprintf(w, "  %s%s\n", path, r.Name)
		if r.Description != "" {
			fmt.Fprintf(w, "    Description: %s\n", truncate(r.Description, 60))
		}
		fmt.Fprintf(w, "    Activities: %d\n", r.Activities)

		if showRefs && len(r.VarRefs) > 0 {
			fmt.Fprintf(w, "    Variable Refs: %s\n", strings.Join(r.VarRefs, ", "))
		}
	}
	fmt.Fprintln(w)
}

func printParseHelp() {
	fmt.Print(`
scorch parse - Parse OIS export files for offline analysis

Usage: scorch parse -f <file.ois_export> [options]

Input:
  -f, -file      OIS export file to parse (required)

Filters:
  -vars          Show all variables
  -encrypted     Show only encrypted variables
  -runbooks      Show runbooks
  -refs          Include variable references in runbook output

Output:
  -json          JSON output
  -o, -output    Write to file

Examples:
  # Parse and show summary
  scorch parse -f exported.ois_export

  # Show all variables
  scorch parse -f exported.ois_export -vars

  # Show only encrypted variables
  scorch parse -f exported.ois_export -encrypted

  # Show runbooks with variable references
  scorch parse -f exported.ois_export -runbooks -refs

  # Export to JSON
  scorch parse -f exported.ois_export -json -o parsed.json

Notes:
  - OIS export files can be created from Runbook Designer (Export...)
  - Encrypted variables show hex data but cannot be decrypted offline
    without the ORCHESTRATOR_SYM_KEY from the database
  - Use 'dump' command for online decryption with database access

`)
}
