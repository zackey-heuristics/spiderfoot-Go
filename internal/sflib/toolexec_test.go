package sflib

import (
	"context"
	"testing"
	"time"
)

func TestRunToolEcho(t *testing.T) {
	if !ToolAvailable("echo") {
		t.Skip("echo not available")
	}

	result, err := RunTool(context.Background(), "echo", []string{"hello"}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stdout != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", result.Stdout)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", result.ExitCode)
	}
}

func TestRunToolNotFound(t *testing.T) {
	_, err := RunTool(context.Background(), "nonexistent-tool-xyz", nil, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for missing tool")
	}
}

func TestToolAvailable(t *testing.T) {
	if !ToolAvailable("echo") {
		t.Fatal("echo should be available")
	}
	if ToolAvailable("nonexistent-tool-xyz") {
		t.Fatal("should not find nonexistent tool")
	}
}
