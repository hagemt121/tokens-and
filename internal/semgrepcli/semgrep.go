// Package semgrepcli resolves and runs the Semgrep command.
package semgrepcli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

func Resolve() (string, error) {
	if configured := os.Getenv("SEMGREP_CLI"); configured != "" {
		path, err := exec.LookPath(configured)
		if err != nil {
			return "", fmt.Errorf("SEMGREP_CLI %q: %w", configured, err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("/opt/homebrew/bin/semgrep"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("semgrep"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("semgrep not found at /opt/homebrew/bin/semgrep or on PATH; set SEMGREP_CLI")
}

func Scan(ctx context.Context, config, target string) ([]byte, error) {
	cli, err := Resolve()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, cli, "scan", "--config", config, "--json", target)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run semgrep: %w", err)
	}
	return output, nil
}
