package sflib

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ToolResult holds the output of an external tool execution.
type ToolResult struct {
	// Stdout is the standard output.
	Stdout string
	// Stderr is the standard error output.
	Stderr string
	// ExitCode is the process exit code.
	ExitCode int
}

// RunTool executes an external binary with the given arguments and timeout.
// Returns an error if the binary is not found or the context is cancelled.
func RunTool(ctx context.Context, binary string, args []string, timeout time.Duration) (*ToolResult, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("tool %q not found: %w", binary, err)
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	result := &ToolResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			return result, nil // non-zero exit is not a Go error
		}
		return result, fmt.Errorf("run %s: %w", binary, err)
	}

	return result, nil
}

// ToolAvailable returns true if the named binary is on the PATH.
func ToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
