package modules

import (
	"context"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestPortscanTCPMeta(t *testing.T) {
	m := &PortscanTCP{}
	meta := m.Meta()
	if meta.Name != "portscan_tcp" {
		t.Fatalf("expected name portscan_tcp, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestPortscanTCPWatchedEvents(t *testing.T) {
	m := &PortscanTCP{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
	if w[0] != event.IP_ADDRESS {
		t.Fatalf("expected IP_ADDRESS, got %s", w[0])
	}
}

func TestPortscanTCPProducedEvents(t *testing.T) {
	m := &PortscanTCP{}
	p := m.ProducedEvents()
	if len(p) != 2 {
		t.Fatalf("expected 2 produced events, got %d", len(p))
	}
}

func TestPortscanTCPHandleNilEvent(t *testing.T) {
	m := &PortscanTCP{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestPortscanTCPSetup(t *testing.T) {
	m := &PortscanTCP{}
	err := m.Setup(map[string]any{
		"timeout":    5,
		"maxworkers": 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %v", m.timeout)
	}
	if m.maxWorkers != 20 {
		t.Fatalf("expected 20 workers, got %d", m.maxWorkers)
	}
}

func TestPortscanTCPDedup(t *testing.T) {
	m := &PortscanTCP{}
	_ = m.Setup(nil)
	if m.markSeen("1.2.3.4") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("1.2.3.4") {
		t.Fatal("second call should return true")
	}
}

func TestPortscanTCPInvalidIP(t *testing.T) {
	m := &PortscanTCP{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.IP_ADDRESS, "not-an-ip", "test", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results for invalid IP, got %d", len(results))
	}
}

func TestDefaultPorts(t *testing.T) {
	if len(defaultPorts) < 40 {
		t.Fatalf("expected at least 40 default ports, got %d", len(defaultPorts))
	}
}
