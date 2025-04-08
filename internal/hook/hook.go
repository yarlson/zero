package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

type Hook struct {
	command       string
	containerName string
	dockerSocket  string
}

func New(command string, containerName string) *Hook {
	return &Hook{
		command:       command,
		containerName: containerName,
		dockerSocket:  "/var/run/docker.sock",
	}
}

func (h *Hook) Execute() error {
	if h.containerName == "" {
		return h.executeLocal()
	}
	return h.executeInContainer()
}

func (h *Hook) executeLocal() error {
	cmdParts := strings.Fields(h.command)
	if len(cmdParts) == 0 {
		return fmt.Errorf("empty command")
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command execution failed: %w, output: %s", err, string(output))
	}
	return nil
}

func (h *Hook) executeInContainer() error {
	containerID, err := h.findContainer()
	if err != nil {
		return fmt.Errorf("find container: %w", err)
	}

	execID, err := h.createExec(containerID)
	if err != nil {
		return fmt.Errorf("create exec: %w", err)
	}

	if err := h.startExec(execID); err != nil {
		return fmt.Errorf("start exec: %w", err)
	}

	return nil
}

func (h *Hook) findContainer() (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", h.dockerSocket)
			},
		},
	}

	req, err := http.NewRequest("GET", "http://localhost/v1.41/containers/json", nil)
	if err != nil {
		return "", err
	}
	req.URL.Scheme = "http"

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	var containers []struct {
		ID              string   `json:"Id"`
		Names           []string `json:"Names"`
		NetworkSettings struct {
			Networks map[string]struct {
				Aliases []string `json:"Aliases"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return "", err
	}

	for _, container := range containers {
		// Check container names
		for _, name := range container.Names {
			// Remove leading slash from name
			name = strings.TrimPrefix(name, "/")
			if strings.Contains(name, h.containerName) {
				return container.ID, nil
			}
		}

		// Check network aliases
		for _, network := range container.NetworkSettings.Networks {
			for _, alias := range network.Aliases {
				if strings.Contains(alias, h.containerName) {
					return container.ID, nil
				}
			}
		}
	}

	return "", fmt.Errorf("container %s not found", h.containerName)
}

func (h *Hook) createExec(containerID string) (string, error) {
	payload := map[string]interface{}{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          strings.Fields(h.command),
		"Tty":          true,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", h.dockerSocket)
			},
		},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost/v1.41/containers/%s/exec", containerID), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.ID, nil
}

func (h *Hook) startExec(execID string) error {
	payload := map[string]interface{}{
		"Detach": false,
		"Tty":    true,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", h.dockerSocket)
			},
		},
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost/v1.41/exec/%s/start", execID), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	return nil
}
