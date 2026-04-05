package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestDNSResolveMeta(t *testing.T) {
	d := &DNSResolve{}
	m := d.Meta()
	if m.Name != "dns_resolve" {
		t.Fatalf("expected name dns_resolve, got %s", m.Name)
	}
}

func TestDNSResolveWatchedEvents(t *testing.T) {
	d := &DNSResolve{}
	watched := d.WatchedEvents()
	if len(watched) != 3 {
		t.Fatalf("expected 3 watched events, got %d", len(watched))
	}
	expected := map[event.Type]bool{
		event.INTERNET_NAME: true,
		event.IP_ADDRESS:    true,
		event.DOMAIN_NAME:   true,
	}
	for _, w := range watched {
		if !expected[w] {
			t.Fatalf("unexpected watched event: %s", w)
		}
	}
}

func TestDNSResolveProducedEvents(t *testing.T) {
	d := &DNSResolve{}
	produced := d.ProducedEvents()
	if len(produced) != 3 {
		t.Fatalf("expected 3 produced events, got %d", len(produced))
	}
}

func TestDNSResolveDedup(t *testing.T) {
	d := &DNSResolve{}
	_ = d.Setup(nil)

	if d.markSeen("1.2.3.4") {
		t.Fatal("first call should return false")
	}
	if !d.markSeen("1.2.3.4") {
		t.Fatal("second call should return true")
	}
}

func TestDNSResolveHandleNilEvent(t *testing.T) {
	d := &DNSResolve{}
	_ = d.Setup(nil)

	results, err := d.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}
