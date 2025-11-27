package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Client is the main LLM client
type Client struct {
	config     *Config
	httpClient *http.Client
	semaphore  chan struct{}
	stats      RequestStats
	statsMu    sync.RWMutex
}

// NewClient creates a new LLM client
func NewClient(config *Config) *Client {
	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		semaphore: make(chan struct{}, config.MaxConcurrent),
		stats:     RequestStats{},
	}
}

// Generate sends a request to the LLM and returns the response
func (c *Client) Generate(ctx context.Context, messages []Message, systemPrompt string) (*Response, error) {
	// Acquire semaphore for rate limiting
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Build full message list with system prompt
	fullMessages := make([]Message, 0, len(messages)+1)
	if systemPrompt != "" {
		fullMessages = append(fullMessages, Message{
			Role:    "system",
			Content: systemPrompt,
		})
	}
	fullMessages = append(fullMessages, messages...)

	// Route to appropriate provider
	var content string
	var err error

	switch c.config.Provider() {
	case "ollama", "ollama_chat":
		content, err = c.callOllama(ctx, fullMessages)
	case "anthropic":
		content, err = c.callAnthropic(ctx, fullMessages)
	default:
		content, err = c.callOpenAICompatible(ctx, fullMessages)
	}

	if err != nil {
		c.statsMu.Lock()
		c.stats.FailedRequests++
		c.statsMu.Unlock()
		return nil, err
	}

	c.statsMu.Lock()
	c.stats.Requests++
	c.statsMu.Unlock()

	// Add closing tag if stopped by stop word
	if strings.Contains(content, "<function") && !strings.Contains(content, "</function>") {
		content = content + "</function>"
	}

	// Parse tool invocations from response
	toolInvocations := parseToolInvocations(content)

	return &Response{
		Content:         content,
		ToolInvocations: toolInvocations,
		Role:            "assistant",
	}, nil
}

// callOllama makes a request to Ollama API
func (c *Client) callOllama(ctx context.Context, messages []Message) (string, error) {
	apiBase := c.config.APIBase
	if apiBase == "" {
		apiBase = "http://localhost:11434"
	}

	// Extract model name (remove "ollama_chat/" or "ollama/" prefix)
	model := c.config.ModelName
	if strings.HasPrefix(model, "ollama_chat/") {
		model = strings.TrimPrefix(model, "ollama_chat/")
	} else if strings.HasPrefix(model, "ollama/") {
		model = strings.TrimPrefix(model, "ollama/")
	}

	req := OllamaRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
		Options: &Options{
			NumCtx: 32768, // Use larger context window
			Stop:   []string{"</function>"},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return ollamaResp.Message.Content, nil
}

// callOpenAICompatible makes a request to OpenAI-compatible API
func (c *Client) callOpenAICompatible(ctx context.Context, messages []Message) (string, error) {
	apiBase := c.config.APIBase
	if apiBase == "" {
		apiBase = "https://api.openai.com/v1"
	}

	// Extract model name (remove provider prefix)
	model := c.config.ModelName
	if idx := strings.Index(model, "/"); idx != -1 {
		model = model[idx+1:]
	}

	req := OpenAIRequest{
		Model:    model,
		Messages: messages,
		Stop:     []string{"</function>"},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var openaiResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return openaiResp.Choices[0].Message.Content, nil
}

// callAnthropic makes a request to Anthropic API
func (c *Client) callAnthropic(ctx context.Context, messages []Message) (string, error) {
	// Extract system message
	var system string
	var chatMsgs []map[string]string
	for _, m := range messages {
		if m.Role == "system" {
			system = m.Content
		} else {
			chatMsgs = append(chatMsgs, map[string]string{"role": m.Role, "content": m.Content})
		}
	}

	model := c.config.ModelName
	if idx := strings.Index(model, "/"); idx != -1 {
		model = model[idx+1:]
	}

	reqBody := map[string]interface{}{
		"model":      model,
		"max_tokens": 4096,
		"system":     system,
		"messages":   chatMsgs,
		"stop_sequences": []string{"</function>"},
	}

	body, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("anthropic error %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if len(result.Content) > 0 {
		return result.Content[0].Text, nil
	}
	return "", nil
}

// parseToolInvocations extracts tool calls from LLM response
func parseToolInvocations(content string) []ToolInvocation {
	var invocations []ToolInvocation

	// Match <function name="tool_name">...</function>
	funcRegex := regexp.MustCompile(`(?s)<function\s+name="([^"]+)"[^>]*>(.*?)</function>`)
	matches := funcRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		toolName := match[1]
		paramsContent := match[2]

		// Parse parameters - match any XML tag pair
		params := make(map[string]string)
		tagRegex := regexp.MustCompile(`(?s)<([a-zA-Z_][a-zA-Z0-9_]*)>(.*?)</([a-zA-Z_][a-zA-Z0-9_]*)>`)
		tagMatches := tagRegex.FindAllStringSubmatch(paramsContent, -1)

		for _, tm := range tagMatches {
			if len(tm) >= 4 && tm[1] == tm[3] { // opening tag matches closing tag
				params[tm[1]] = strings.TrimSpace(tm[2])
			}
		}

		invocations = append(invocations, ToolInvocation{
			ID:         fmt.Sprintf("tool_%d", time.Now().UnixNano()),
			Name:       toolName,
			Parameters: params,
		})
	}

	return invocations
}

// GetStats returns current request statistics
func (c *Client) GetStats() RequestStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	return c.stats
}
