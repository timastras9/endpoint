package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const DefaultImage = "ghcr.io/timastras9/endpoint-sandbox:latest"

type SandboxInfo struct {
	ContainerID string
	URL         string
	Token       string
	Port        int
}

type DockerRuntime struct {
	image string
}

func NewDockerRuntime() *DockerRuntime {
	image := os.Getenv("ENDPOINT_IMAGE")
	if image == "" {
		image = DefaultImage
	}
	return &DockerRuntime{image: image}
}

func (r *DockerRuntime) CreateSandbox(ctx context.Context, agentID string) (*SandboxInfo, error) {
	token := generateToken()
	port := 8000 + (time.Now().UnixNano() % 1000) // Simple port selection

	// Start container
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"-p", fmt.Sprintf("%d:8080", port),
		"-e", fmt.Sprintf("AUTH_TOKEN=%s", token),
		"-e", fmt.Sprintf("AGENT_ID=%s", agentID),
		"--name", fmt.Sprintf("endpoint-%s", agentID[:8]),
		r.image,
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	containerID := string(output[:12])

	// Wait for container to be ready
	time.Sleep(2 * time.Second)

	return &SandboxInfo{
		ContainerID: containerID,
		URL:         fmt.Sprintf("http://localhost:%d", port),
		Token:       token,
		Port:        int(port),
	}, nil
}

func (r *DockerRuntime) DestroySandbox(ctx context.Context, containerID string) error {
	exec.CommandContext(ctx, "docker", "stop", containerID).Run()
	exec.CommandContext(ctx, "docker", "rm", containerID).Run()
	return nil
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
