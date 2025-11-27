package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/timastras9/endpoint/pkg/llm"
	"github.com/timastras9/endpoint/pkg/runtime"
)

type Executor struct {
	sandbox *runtime.SandboxInfo
	client  *http.Client
}

func NewExecutor() *Executor {
	return &Executor{client: &http.Client{}}
}

func (e *Executor) SetSandbox(s *runtime.SandboxInfo) {
	e.sandbox = s
}

func (e *Executor) Execute(ctx context.Context, invoc llm.ToolInvocation, state interface{}) (string, bool, error) {
	tool, err := Get(invoc.Name)
	if err != nil {
		return "", false, err
	}

	if tool.RunInSandbox {
		return e.executeInSandbox(ctx, invoc)
	}

	if tool.Execute != nil {
		return tool.Execute(invoc.Parameters, state)
	}

	return "", false, fmt.Errorf("tool %s has no executor", invoc.Name)
}

func (e *Executor) executeInSandbox(ctx context.Context, invoc llm.ToolInvocation) (string, bool, error) {
	if e.sandbox == nil {
		return "", false, fmt.Errorf("no sandbox available")
	}

	reqBody := map[string]interface{}{
		"tool_name": invoc.Name,
		"kwargs":    invoc.Parameters,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", e.sandbox.URL+"/execute", bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.sandbox.Token)

	resp, err := e.client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("sandbox error: %s", string(respBody))
	}

	var result struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	json.Unmarshal(respBody, &result)

	if result.Error != "" {
		return result.Error, false, nil
	}
	return result.Output, false, nil
}
