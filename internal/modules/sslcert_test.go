package modules

import (
	"context"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestSSLCertMeta(t *testing.T) {
	m := &SSLCert{}
	meta := m.Meta()
	if meta.Name != "sslcert" {
		t.Fatalf("expected name sslcert, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestSSLCertWatchedEvents(t *testing.T) {
	m := &SSLCert{}
	w := m.WatchedEvents()
	if len(w) != 2 {
		t.Fatalf("expected 2 watched events, got %d", len(w))
	}
}

func TestSSLCertProducedEvents(t *testing.T) {
	m := &SSLCert{}
	p := m.ProducedEvents()
	if len(p) != 8 {
		t.Fatalf("expected 8 produced events, got %d", len(p))
	}
}

func TestSSLCertHandleNilEvent(t *testing.T) {
	m := &SSLCert{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestSSLCertSetup(t *testing.T) {
	m := &SSLCert{}
	err := m.Setup(map[string]any{
		"timeout":          20,
		"certexpiringdays": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.timeout != 20*time.Second {
		t.Fatalf("expected 20s timeout, got %v", m.timeout)
	}
	if m.expiringDays != 60 {
		t.Fatalf("expected 60 expiring days, got %d", m.expiringDays)
	}
}

func TestSSLCertDedup(t *testing.T) {
	m := &SSLCert{}
	_ = m.Setup(nil)
	if m.markSeen("example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("example.com") {
		t.Fatal("second call should return true")
	}
}

func TestSSLCertEmptyHost(t *testing.T) {
	m := &SSLCert{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.INTERNET_NAME, "", "test", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty host, got %d", len(results))
	}
}
