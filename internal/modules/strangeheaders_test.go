package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestStrangeHeadersMeta(t *testing.T) {
	m := &StrangeHeaders{}
	meta := m.Meta()
	if meta.Name != "strangeheaders" {
		t.Fatalf("expected name strangeheaders, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestStrangeHeadersWatchedEvents(t *testing.T) {
	m := &StrangeHeaders{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
}

func TestStrangeHeadersProducedEvents(t *testing.T) {
	m := &StrangeHeaders{}
	p := m.ProducedEvents()
	if len(p) != 1 {
		t.Fatalf("expected 1 produced event, got %d", len(p))
	}
}

func TestStrangeHeadersHandleNilEvent(t *testing.T) {
	m := &StrangeHeaders{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestStrangeHeadersSetup(t *testing.T) {
	m := &StrangeHeaders{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
}

func TestStrangeHeadersDetectsNonStandard(t *testing.T) {
	m := &StrangeHeaders{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	headers := "Server: nginx\nX-Custom-Debug: true\nContent-Type: text/html\nX-Backend-Server: app01"
	evt, _ := event.New(event.WEBSERVER_HTTPHEADERS, headers, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	// Server and Content-Type are standard; X-Custom-Debug and X-Backend-Server are not.
	if len(results) != 2 {
		t.Fatalf("expected 2 strange headers, got %d", len(results))
	}

	found := make(map[string]bool)
	for _, r := range results {
		if r.Type != event.WEBSERVER_STRANGEHEADER {
			t.Fatalf("expected WEBSERVER_STRANGEHEADER, got %s", r.Type)
		}
		found[r.Data] = true
	}
	if !found["X-Custom-Debug: true"] {
		t.Fatal("expected X-Custom-Debug to be reported")
	}
	if !found["X-Backend-Server: app01"] {
		t.Fatal("expected X-Backend-Server to be reported")
	}
}

func TestStrangeHeadersIgnoresStandard(t *testing.T) {
	m := &StrangeHeaders{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	headers := "Server: apache\nContent-Type: text/html\nCache-Control: no-cache\nSet-Cookie: foo=bar"
	evt, _ := event.New(event.WEBSERVER_HTTPHEADERS, headers, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for all-standard headers, got %d", len(results))
	}
}

func TestStandardHeadersCount(t *testing.T) {
	if len(standardHeaders) < 40 {
		t.Fatalf("expected at least 40 standard headers, got %d", len(standardHeaders))
	}
}
