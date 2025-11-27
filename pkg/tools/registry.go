package tools

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ToolFunc func(params map[string]string, state interface{}) (string, bool, error)

type Tool struct {
	Name        string
	Description string
	RunInSandbox bool
	Execute     ToolFunc
}

var (
	registry   = make(map[string]*Tool)
	registryMu sync.RWMutex
)

func Register(t *Tool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[t.Name] = t
}

func Get(name string) (*Tool, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if t, ok := registry[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("tool not found: %s", name)
}

func GetPrompt() string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	prompt := "<tools>\n"
	for _, t := range registry {
		prompt += fmt.Sprintf(`<tool name="%s">%s</tool>`+"\n", t.Name, t.Description)
	}
	prompt += "</tools>"
	return prompt
}

func init() {
	Register(&Tool{
		Name:         "terminal_execute",
		Description:  "Execute a shell command. Parameters: command (required)",
		RunInSandbox: false,
		Execute:      executeTerminal,
	})
	Register(&Tool{
		Name:         "port_scan",
		Description:  "Scan ports on a target. Parameters: target (required - IP or hostname), ports (optional - comma-separated or range like 1-1000, defaults to common ports)",
		RunInSandbox: false,
		Execute:      executePortScan,
	})
	Register(&Tool{
		Name:         "report_vulnerability",
		Description:  "Report a discovered vulnerability. Parameters: title (required), severity (required: critical/high/medium/low/info), description (required), url (required - where it was found)",
		RunInSandbox: false,
		Execute:      executeReportVulnerability,
	})
	Register(&Tool{
		Name:         "finish_scan",
		Description:  "Complete scan with report. Parameters: summary (required)",
		RunInSandbox: false,
		Execute: func(params map[string]string, _ interface{}) (string, bool, error) {
			return params["summary"], true, nil
		},
	})
	Register(&Tool{
		Name:         "thinking",
		Description:  "Plan next steps. Parameters: thought (required)",
		RunInSandbox: false,
		Execute: func(params map[string]string, _ interface{}) (string, bool, error) {
			return "Recorded: " + params["thought"], false, nil
		},
	})
}

func executeTerminal(params map[string]string, _ interface{}) (string, bool, error) {
	cmd := params["command"]
	if cmd == "" {
		return "Error: no command provided", false, nil
	}

	// Use exec to run command
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Command failed: %s\nOutput: %s", err, string(out)), false, nil
	}

	result := string(out)
	if len(result) > 4000 {
		result = result[:4000] + "\n... (truncated)"
	}
	return result, false, nil
}

// Common ports and their services
var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	27017: "mongodb",
}

func executePortScan(params map[string]string, _ interface{}) (string, bool, error) {
	target := params["target"]
	if target == "" {
		return "Error: no target provided", false, nil
	}

	// Parse ports parameter
	var ports []int
	portsParam := params["ports"]
	if portsParam == "" {
		// Use common ports
		for p := range commonPorts {
			ports = append(ports, p)
		}
	} else {
		ports = parsePorts(portsParam)
	}

	if len(ports) == 0 {
		return "Error: no valid ports to scan", false, nil
	}

	// Resolve hostname to IP (prefer IPv4)
	ips, err := net.LookupIP(target)
	var ip string
	if err != nil {
		// Might already be an IP
		ip = target
	} else if len(ips) > 0 {
		// Prefer IPv4 address
		for _, addr := range ips {
			if ipv4 := addr.To4(); ipv4 != nil {
				ip = ipv4.String()
				break
			}
		}
		// Fallback to first IP if no IPv4 found
		if ip == "" {
			ip = ips[0].String()
		}
	} else {
		return fmt.Sprintf("Error: could not resolve %s", target), false, nil
	}

	// Concurrent port scanning
	type scanResult struct {
		port   int
		open   bool
		banner string
	}

	results := make(chan scanResult, len(ports))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 100) // Limit concurrency

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				results <- scanResult{port: p, open: false}
				return
			}
			defer conn.Close()

			// Try to grab banner
			banner := ""
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				banner = strings.TrimSpace(string(buf[:n]))
				if len(banner) > 50 {
					banner = banner[:50] + "..."
				}
			}

			results <- scanResult{port: p, open: true, banner: banner}
		}(port)
	}

	// Wait and collect
	go func() {
		wg.Wait()
		close(results)
	}()

	var openPorts []scanResult
	for r := range results {
		if r.open {
			openPorts = append(openPorts, r)
		}
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Port scan results for %s (%s)\n", target, ip))
	sb.WriteString(fmt.Sprintf("Scanned %d ports\n\n", len(ports)))

	if len(openPorts) == 0 {
		sb.WriteString("No open ports found.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Open ports (%d):\n", len(openPorts)))
		for _, r := range openPorts {
			service := commonPorts[r.port]
			if service == "" {
				service = "unknown"
			}
			line := fmt.Sprintf("  %d/tcp  open  %s", r.port, service)
			if r.banner != "" {
				line += fmt.Sprintf("  [%s]", r.banner)
			}
			sb.WriteString(line + "\n")
		}
	}

	return sb.String(), false, nil
}

func parsePorts(portsStr string) []int {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range like 1-100
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil && start > 0 && end <= 65535 && start <= end {
					for p := start; p <= end; p++ {
						if !seen[p] {
							ports = append(ports, p)
							seen[p] = true
						}
					}
				}
			}
		} else {
			// Single port
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 && !seen[p] {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	return ports
}

func executeReportVulnerability(params map[string]string, _ interface{}) (string, bool, error) {
	title := params["title"]
	severity := params["severity"]
	description := params["description"]
	url := params["url"]

	if title == "" || severity == "" || description == "" {
		return "Error: title, severity, and description are required", false, nil
	}

	// Validate severity
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	severity = strings.ToLower(severity)
	if !validSeverities[severity] {
		severity = "info"
	}

	// Output in a structured format that the backend can parse
	// Using JSON-like format for easy parsing
	output := fmt.Sprintf(`[VULNERABILITY]{"title":"%s","severity":"%s","description":"%s","url":"%s"}[/VULNERABILITY]`,
		strings.ReplaceAll(title, `"`, `\"`),
		severity,
		strings.ReplaceAll(description, `"`, `\"`),
		strings.ReplaceAll(url, `"`, `\"`),
	)

	fmt.Println(output) // Print to stdout for backend to capture

	return fmt.Sprintf("Vulnerability reported: %s (%s)", title, severity), false, nil
}
