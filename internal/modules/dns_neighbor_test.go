package modules

import (
	"context"
	"net"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestDNSNeighborMeta(t *testing.T) {
	m := &DNSNeighbor{}
	meta := m.Meta()
	if meta.Name != "dns_neighbor" {
		t.Fatalf("expected name dns_neighbor, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestDNSNeighborWatchedEvents(t *testing.T) {
	m := &DNSNeighbor{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
	if w[0] != event.IP_ADDRESS {
		t.Fatalf("expected IP_ADDRESS, got %s", w[0])
	}
}

func TestDNSNeighborProducedEvents(t *testing.T) {
	m := &DNSNeighbor{}
	p := m.ProducedEvents()
	if len(p) != 2 {
		t.Fatalf("expected 2 produced events, got %d", len(p))
	}
}

func TestDNSNeighborHandleNilEvent(t *testing.T) {
	m := &DNSNeighbor{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestDNSNeighborSetup(t *testing.T) {
	m := &DNSNeighbor{}
	if err := m.Setup(map[string]any{"lookasidebits": 3}); err != nil {
		t.Fatal(err)
	}
	if m.lookasideBits != 3 {
		t.Fatalf("expected lookasideBits 3, got %d", m.lookasideBits)
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	ip = incrementIP(ip)
	if ip.String() != "192.168.1.2" {
		t.Fatalf("expected 192.168.1.2, got %s", ip.String())
	}

	ip = net.ParseIP("192.168.1.255").To4()
	ip = incrementIP(ip)
	if ip.String() != "192.168.2.0" {
		t.Fatalf("expected 192.168.2.0, got %s", ip.String())
	}
}

func TestCopyIP(t *testing.T) {
	orig := net.ParseIP("10.0.0.1").To4()
	dup := copyIP(orig)
	dup[3] = 99
	if orig[3] == 99 {
		t.Fatal("copyIP should not modify the original")
	}
}

func TestDNSNeighborDedup(t *testing.T) {
	m := &DNSNeighbor{}
	_ = m.Setup(nil)

	if m.markSeen("10.0.0.1") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("10.0.0.1") {
		t.Fatal("second call should return true")
	}
}
