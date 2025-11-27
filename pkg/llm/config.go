package llm

import (
	"os"
	"strconv"
	"time"
)

// Config holds LLM configuration
type Config struct {
	ModelName           string
	APIKey              string
	APIBase             string
	Timeout             time.Duration
	EnablePromptCaching bool
	PromptModules       []string
	MaxRetries          int
	MaxConcurrent       int
}

// NewConfigFromEnv creates config from environment variables
func NewConfigFromEnv() *Config {
	timeout := 600 * time.Second
	if t := os.Getenv("LLM_TIMEOUT"); t != "" {
		if secs, err := strconv.Atoi(t); err == nil {
			timeout = time.Duration(secs) * time.Second
		}
	}

	maxConcurrent := 6
	if c := os.Getenv("LLM_RATE_LIMIT_CONCURRENT"); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			maxConcurrent = n
		}
	}

	return &Config{
		ModelName:           os.Getenv("ENDPOINT_LLM"),
		APIKey:              os.Getenv("LLM_API_KEY"),
		APIBase:             getAPIBase(),
		Timeout:             timeout,
		EnablePromptCaching: true,
		MaxRetries:          7,
		MaxConcurrent:       maxConcurrent,
	}
}

func getAPIBase() string {
	if base := os.Getenv("LLM_API_BASE"); base != "" {
		return base
	}
	if base := os.Getenv("OPENAI_API_BASE"); base != "" {
		return base
	}
	if base := os.Getenv("OLLAMA_API_BASE"); base != "" {
		return base
	}
	return ""
}

// Provider returns the LLM provider type
func (c *Config) Provider() string {
	if c.ModelName == "" {
		return ""
	}
	// Parse provider from model name like "ollama_chat/qwen2.5:7b" or "anthropic/claude"
	for i, ch := range c.ModelName {
		if ch == '/' {
			return c.ModelName[:i]
		}
	}
	// Default providers based on model name prefix
	switch {
	case contains(c.ModelName, "gpt"):
		return "openai"
	case contains(c.ModelName, "claude"):
		return "anthropic"
	case contains(c.ModelName, "gemini"):
		return "google"
	default:
		return "openai" // default
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
