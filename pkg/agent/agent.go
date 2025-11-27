package agent

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/timastras9/endpoint/pkg/llm"
	"github.com/timastras9/endpoint/pkg/runtime"
	"github.com/timastras9/endpoint/pkg/tools"
)

type Agent struct {
	State        *State
	LLM          *llm.Client
	Runtime      *runtime.DockerRuntime
	ToolExecutor *tools.Executor
	SystemPrompt string
	NoSandbox    bool
}

func New(name string, llmClient *llm.Client, systemPrompt string) *Agent {
	return &Agent{
		State:        NewState(name, 300),
		LLM:          llmClient,
		Runtime:      runtime.NewDockerRuntime(),
		ToolExecutor: tools.NewExecutor(),
		SystemPrompt: systemPrompt,
	}
}

func (a *Agent) Run(ctx context.Context, task string) (string, error) {
	a.State.Task = task
	a.State.AddMessage("user", task)

	// Create sandbox async
	sandboxCh := make(chan *runtime.SandboxInfo, 1)
	sandboxErr := make(chan error, 1)

	if !a.NoSandbox {
		go func() {
			sandbox, err := a.Runtime.CreateSandbox(ctx, a.State.ID)
			if err != nil {
				sandboxErr <- err
				return
			}
			sandboxCh <- sandbox
		}()

		select {
		case sandbox := <-sandboxCh:
			defer a.Runtime.DestroySandbox(ctx, sandbox.ContainerID)
			a.State.SetSandbox(sandbox.ContainerID, sandbox.Token, sandbox.URL)
			a.ToolExecutor.SetSandbox(sandbox)
		case err := <-sandboxErr:
			return "", fmt.Errorf("failed to create sandbox: %w", err)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	log.Printf("[%s] Starting agent loop", a.State.Name)

	// Main agent loop
	for !a.State.ShouldStop() {
		iter := a.State.IncrementIteration()
		log.Printf("[%s] Iteration %d/%d", a.State.Name, iter, a.State.MaxIterations)

		// Call LLM
		resp, err := a.LLM.Generate(ctx, a.State.GetMessages(), a.SystemPrompt)
		if err != nil {
			a.State.Errors = append(a.State.Errors, err.Error())
			log.Printf("[%s] LLM error: %v", a.State.Name, err)
			continue
		}

		// Skip empty responses
		if strings.TrimSpace(resp.Content) == "" {
			log.Printf("[%s] Empty response, retrying", a.State.Name)
			continue
		}

		log.Printf("[%s] Response (%d tools): %.200s...", a.State.Name, len(resp.ToolInvocations), resp.Content)
		a.State.AddMessage("assistant", resp.Content)

		// Execute tools concurrently if multiple
		if len(resp.ToolInvocations) > 0 {
			results := a.executeToolsAsync(ctx, resp.ToolInvocations)
			for _, r := range results {
				if r.err != nil {
					a.State.AddMessage("user", fmt.Sprintf("Tool error: %v", r.err))
					continue
				}
				a.State.AddMessage("user", r.output)
				if r.finished {
					a.State.SetCompleted(r.output)
					return a.State.FinalResult, nil
				}
			}
		}

		if iter == a.State.MaxIterations-20 {
			a.State.AddMessage("system", "Warning: Approaching max iterations.")
		}
	}

	return a.State.FinalResult, nil
}

type toolResult struct {
	output   string
	finished bool
	err      error
}

func (a *Agent) executeToolsAsync(ctx context.Context, invocations []llm.ToolInvocation) []toolResult {
	results := make([]toolResult, len(invocations))
	var wg sync.WaitGroup

	for i, invoc := range invocations {
		wg.Add(1)
		go func(idx int, inv llm.ToolInvocation) {
			defer wg.Done()
			output, finished, err := a.ToolExecutor.Execute(ctx, inv, a.State)
			results[idx] = toolResult{output, finished, err}
		}(i, invoc)
	}

	wg.Wait()
	return results
}
