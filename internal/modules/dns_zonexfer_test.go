package modules

import (
	"context"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestDNSZoneXferMeta(t *testing.T) {
	m := &DNSZoneXfer{}
	meta := m.Meta()
	if meta.Name != "dns_zonexfer" {
		t.Fatalf("expected name dns_zonexfer, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestDNSZoneXferWatchedEvents(t *testing.T) {
	m := &DNSZoneXfer{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
	if w[0] != event.PROVIDER_DNS {
		t.Fatalf("expected PROVIDER_DNS, got %s", w[0])
	}
}

func TestDNSZoneXferProducedEvents(t *testing.T) {
	m := &DNSZoneXfer{}
	p := m.ProducedEvents()
	if len(p) != 2 {
		t.Fatalf("expected 2 produced events, got %d", len(p))
	}
}

func TestDNSZoneXferHandleNilEvent(t *testing.T) {
	m := &DNSZoneXfer{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestDNSZoneXferSetup(t *testing.T) {
	m := &DNSZoneXfer{}
	if err := m.Setup(map[string]any{"timeout": 15}); err != nil {
		t.Fatal(err)
	}
	if m.timeout != 15*time.Second {
		t.Fatalf("expected 15s timeout, got %v", m.timeout)
	}
}

func TestDNSZoneXferDedup(t *testing.T) {
	m := &DNSZoneXfer{}
	_ = m.Setup(nil)

	if m.markSeen("ns1.example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("ns1.example.com") {
		t.Fatal("second call should return true")
	}
}
