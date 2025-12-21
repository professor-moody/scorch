package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

var version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "enum":
		if err := runEnum(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "assess":
		if err := runAssess(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "exec":
		if err := runExec(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "dump":
		if err := runDump(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "spray":
		if err := runSpray(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "discover":
		if err := runDiscover(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("scorch v%s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`
┌─────────────────────────────────────────────────────────────┐
│  SCORCH - System Center Orchestrator Security Toolkit       │
│  v` + version + `                                                       │
└─────────────────────────────────────────────────────────────┘

Usage: scorch <command> [options]

Commands:
  enum      Enumerate runbooks, servers, and jobs via REST API
  assess    Security assessment and vulnerability scanning
  exec      Execute runbooks with parameters
  dump      Extract credentials from SCORCH database
  spray     Password spray against SCORCH web service
  discover  Network discovery, LDAP enumeration, and SPN discovery
  help      Show this help

Run 'scorch <command> -h' for command-specific help.

Quick Examples:
  # Enumerate from Linux with NTLM
  scorch enum -target scorch.corp.local -d CORP -u admin -p 'P@ssw0rd'

  # Pass-the-hash
  scorch enum -target scorch.corp.local -d CORP -u admin -H aad3b435b51404eeaad3b435b51404ee

  # Kerberos authentication
  scorch enum -target scorch.corp.local -kerberos -u admin -p 'P@ssw0rd' -realm CORP.LOCAL

  # Kerberos with existing ticket (kinit first)
  scorch enum -target scorch.corp.local -kerberos

  # Security scan
  scorch assess -target scorch.corp.local

  # Dump creds from database
  scorch dump -target sqlserver.corp.local -db Orchestrator

  # Network discovery and SPN enumeration
  scorch discover -target dc01.corp.local -d CORP -u admin -p Pass123 -all

`)
}

// CommonOpts are parsed by all commands
type CommonOpts struct {
	Target     string
	Port       int
	TLS        bool
	SkipVerify bool
	Timeout    time.Duration

	Username string
	Password string
	Domain   string
	NTHash   string

	// Kerberos options
	Kerberos bool   // Enable Kerberos authentication
	Realm    string // Kerberos realm (defaults to uppercase domain)
	KDC      string // KDC address (optional, uses DNS/krb5.conf if not set)
	Keytab   string // Path to keytab file
	CCache   string // Path to credential cache

	JSON   bool
	Output string
	Debug  bool
	Quiet  bool
}

func (o *CommonOpts) Validate() error {
	if o.Target == "" {
		return fmt.Errorf("-target is required")
	}
	return nil
}

func (o *CommonOpts) BaseURL() string {
	scheme := "http"
	if o.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, o.Target, o.Port)
}

func (o *CommonOpts) HasCredentials() bool {
	return o.Username != "" && (o.Password != "" || o.NTHash != "")
}

// parseCommonFlags extracts common flags from args
func parseCommonFlags(args []string) (*CommonOpts, []string, error) {
	opts := &CommonOpts{
		Port:    81,
		Timeout: 30 * time.Second,
	}

	var remaining []string
	i := 0
	for i < len(args) {
		arg := args[i]
		getValue := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}

		switch arg {
		case "-target", "-t", "--target":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Target = v
		case "-port", "-P", "--port":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			fmt.Sscanf(v, "%d", &opts.Port)
		case "-tls", "--tls":
			opts.TLS = true
		case "-k", "-skip-verify", "--skip-verify":
			opts.SkipVerify = true
		case "-timeout", "--timeout":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid timeout: %v", err)
			}
			opts.Timeout = d
		case "-u", "-user", "-username", "--username":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Username = v
		case "-p", "-pass", "-password", "--password":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Password = v
		case "-d", "-domain", "--domain":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Domain = v
		case "-H", "-hash", "-nthash", "--hash":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.NTHash = v
		case "-kerberos", "--kerberos":
			opts.Kerberos = true
		case "-realm", "--realm":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Realm = v
		case "-kdc", "--kdc":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.KDC = v
		case "-keytab", "--keytab":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Keytab = v
		case "-ccache", "--ccache":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.CCache = v
		case "-json", "--json":
			opts.JSON = true
		case "-o", "-output", "--output":
			v, err := getValue()
			if err != nil {
				return nil, nil, err
			}
			opts.Output = v
		case "-debug", "--debug":
			opts.Debug = true
		case "-q", "-quiet", "--quiet":
			opts.Quiet = true
		default:
			remaining = append(remaining, arg)
		}
		i++
	}

	return opts, remaining, nil
}

// getOutput returns the output writer
func getOutput(opts *CommonOpts) (io.Writer, func(), error) {
	if opts.Output == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(opts.Output)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// writeJSON writes data as JSON
func writeJSON(w io.Writer, data interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// printf prints if not in quiet mode
func printf(opts *CommonOpts, format string, args ...interface{}) {
	if !opts.Quiet && !opts.JSON {
		fmt.Printf(format, args...)
	}
}

// debugf prints debug output
func debugf(opts *CommonOpts, format string, args ...interface{}) {
	if opts.Debug {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// createContext creates a context with timeout
func createContext(opts *CommonOpts) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opts.Timeout*10)
}

// containsHelp checks if args contain help flag
func containsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}
	return false
}

// parseFlag extracts a flag value from remaining args
func parseFlag(args []string, flags ...string) (string, []string) {
	for i := 0; i < len(args); i++ {
		for _, f := range flags {
			if args[i] == f && i+1 < len(args) {
				val := args[i+1]
				newArgs := append(args[:i], args[i+2:]...)
				return val, newArgs
			}
		}
	}
	return "", args
}

// parseBoolFlag checks if a flag is present
func parseBoolFlag(args []string, flags ...string) (bool, []string) {
	for i := 0; i < len(args); i++ {
		for _, f := range flags {
			if args[i] == f {
				newArgs := append(args[:i], args[i+1:]...)
				return true, newArgs
			}
		}
	}
	return false, args
}

// truncate truncates a string
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// maskPassword masks a password for display
func maskPassword(p string) string {
	if len(p) <= 4 {
		return strings.Repeat("*", len(p))
	}
	return p[:2] + strings.Repeat("*", len(p)-4) + p[len(p)-2:]
}
