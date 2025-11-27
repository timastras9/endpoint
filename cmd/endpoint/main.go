package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/timastras9/endpoint/pkg/agent"
	"github.com/timastras9/endpoint/pkg/llm"
	"github.com/timastras9/endpoint/pkg/tools"
)

var (
	targets     []string
	instruction string
	runName     string
	noSandbox   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "endpoint",
		Short: "AI-powered penetration testing",
		Run:   run,
	}

	rootCmd.Flags().StringArrayVarP(&targets, "target", "t", nil, "Target URLs/IPs")
	rootCmd.Flags().StringVarP(&instruction, "instruction", "i", "", "Custom instructions")
	rootCmd.Flags().StringVarP(&runName, "run-name", "n", "", "Scan name")
	rootCmd.Flags().BoolVar(&noSandbox, "no-sandbox", false, "Run without Docker sandbox")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Validate environment
	if os.Getenv("ENDPOINT_LLM") == "" {
		color.Red("Error: ENDPOINT_LLM environment variable required")
		os.Exit(1)
	}

	if len(targets) == 0 {
		color.Red("Error: At least one target required (-t)")
		os.Exit(1)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		color.Yellow("\nShutting down...")
		cancel()
	}()

	// Create LLM client
	config := llm.NewConfigFromEnv()
	llmClient := llm.NewClient(config)

	// Build system prompt
	systemPrompt := buildSystemPrompt()

	// Create and run agent
	a := agent.New("EndpointAgent", llmClient, systemPrompt)
	a.NoSandbox = noSandbox

	task := buildTask(targets, instruction)
	color.Cyan("Starting scan of %d target(s)...\n", len(targets))

	result, err := a.Run(ctx, task)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	color.Green("\n=== Scan Complete ===\n")
	fmt.Println(result)
}

func buildSystemPrompt() string {
	return `You are Endpoint, an AI security testing agent. You MUST use tools to perform actions.

` + tools.GetPrompt() + `

IMPORTANT: You MUST call tools using this exact XML format:
<function name="tool_name">
<parameter_name>value</parameter_name>
</function>

Example - port scan (ALWAYS use this instead of nmap):
<function name="port_scan">
<target>example.com</target>
</function>

Example - to run a command:
<function name="terminal_execute">
<command>curl -I https://example.com</command>
</function>

Example - report a vulnerability (ALWAYS report findings this way):
<function name="report_vulnerability">
<title>Missing X-Frame-Options Header</title>
<severity>medium</severity>
<description>The server does not set X-Frame-Options header, making it vulnerable to clickjacking attacks.</description>
<url>https://example.com</url>
</function>

Example - to finish:
<function name="finish_scan">
<summary>Scan complete. Found X vulnerabilities...</summary>
</function>

RULES:
- Use port_scan tool for port scanning, NOT nmap or similar external tools
- ALWAYS use report_vulnerability to report ANY security issue found
- Always call a tool in each response
- Start with port_scan, then run curl -I on each open HTTP/HTTPS port

MANDATORY SCAN SEQUENCE:
1. port_scan the target
2. For each open web port (80, 443, 8080, 8443): run "curl -I http(s)://target:port"
3. Analyze headers and report ALL missing security headers as vulnerabilities
4. Check HTTP->HTTPS redirect with "curl -I http://target"
5. Finish with summary

HEADER CHECKS (report each missing one as a vulnerability):
- X-Frame-Options missing = medium severity (clickjacking risk)
- X-Content-Type-Options missing = low severity (MIME sniffing risk)
- Strict-Transport-Security missing = high severity (MITM risk)
- Content-Security-Policy missing = medium severity (XSS risk)
- X-XSS-Protection missing = low severity (XSS risk)
- Server header showing version = info severity (information disclosure)

SEVERITY GUIDE:
- critical: RCE, SQLi, auth bypass, exposed credentials
- high: HSTS missing, open admin panels, sensitive data exposure
- medium: clickjacking, missing CSP, CORS misconfiguration
- low: minor info disclosure, missing optional headers
- info: version disclosure, technology fingerprinting`
}

func buildTask(targets []string, instruction string) string {
	task := "Perform security testing on:\n"
	for _, t := range targets {
		task += fmt.Sprintf("- %s\n", t)
	}
	if instruction != "" {
		task += "\nInstructions: " + instruction
	}
	return task
}
