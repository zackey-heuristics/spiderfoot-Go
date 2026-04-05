package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestStorStdoutMeta(t *testing.T) {
	m := &StorStdout{}
	meta := m.Meta()
	if meta.Name != "stor_stdout" {
		t.Fatalf("expected name stor_stdout, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestStorStdoutWatchedEvents(t *testing.T) {
	m := &StorStdout{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
	if w[0] != event.Wildcard {
		t.Fatalf("expected Wildcard, got %s", w[0])
	}
}

func TestStorStdoutProducedEvents(t *testing.T) {
	m := &StorStdout{}
	p := m.ProducedEvents()
	if p != nil {
		t.Fatalf("expected nil produced events, got %v", p)
	}
}

func TestStorStdoutHandleNilEvent(t *testing.T) {
	m := &StorStdout{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestStorStdoutSetup(t *testing.T) {
	m := &StorStdout{}
	err := m.Setup(map[string]any{
		"format":       "json",
		"stripnewline": true,
		"showsource":   true,
		"maxlength":    100,
		"delimiter":    "|",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.format != "json" {
		t.Fatalf("expected json format, got %s", m.format)
	}
	if !m.stripNewline {
		t.Fatal("expected stripNewline true")
	}
	if !m.showSource {
		t.Fatal("expected showSource true")
	}
	if m.maxLength != 100 {
		t.Fatalf("expected maxLength 100, got %d", m.maxLength)
	}
	if m.delimiter != "|" {
		t.Fatalf("expected delimiter |, got %s", m.delimiter)
	}
}

func TestStorStdoutSkipsRoot(t *testing.T) {
	m := &StorStdout{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	results, err := m.HandleEvent(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for ROOT event")
	}
}

func TestStorStdoutHandleEvent(t *testing.T) {
	m := &StorStdout{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.IP_ADDRESS, "1.2.3.4", "test_mod", root)

	// This will print to stdout; just verify no error.
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results from output module")
	}
}

func TestStorStdoutFinish(t *testing.T) {
	m := &StorStdout{}
	_ = m.Setup(nil)
	if err := m.Finish(); err != nil {
		t.Fatal(err)
	}
}
