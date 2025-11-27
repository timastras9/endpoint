package agent

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/timastras9/endpoint/pkg/llm"
)

type State struct {
	mu              sync.RWMutex
	ID              string
	Name            string
	ParentID        string
	SandboxID       string
	SandboxToken    string
	SandboxURL      string
	Task            string
	Iteration       int
	MaxIterations   int
	Completed       bool
	StopRequested   bool
	WaitingForInput bool
	LLMFailed       bool
	Messages        []llm.Message
	ActionsTaken    []string
	Observations    []string
	Errors          []string
	Context         map[string]interface{}
	FinalResult     string
	StartTime       time.Time
}

func NewState(name string, maxIterations int) *State {
	return &State{
		ID:            uuid.New().String(),
		Name:          name,
		MaxIterations: maxIterations,
		Messages:      make([]llm.Message, 0),
		ActionsTaken:  make([]string, 0),
		Observations:  make([]string, 0),
		Errors:        make([]string, 0),
		Context:       make(map[string]interface{}),
		StartTime:     time.Now(),
	}
}

func (s *State) AddMessage(role, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Messages = append(s.Messages, llm.Message{Role: role, Content: content})
}

func (s *State) IncrementIteration() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Iteration++
	return s.Iteration
}

func (s *State) ShouldStop() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Completed || s.StopRequested || s.Iteration >= s.MaxIterations
}

func (s *State) SetCompleted(result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Completed = true
	s.FinalResult = result
}

func (s *State) GetMessages() []llm.Message {
	s.mu.RLock()
	defer s.mu.RUnlock()
	msgs := make([]llm.Message, len(s.Messages))
	copy(msgs, s.Messages)
	return msgs
}

func (s *State) SetSandbox(id, token, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SandboxID = id
	s.SandboxToken = token
	s.SandboxURL = url
}
