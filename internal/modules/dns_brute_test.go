package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestDNSBruteMeta(t *testing.T) {
	m := &DNSBrute{}
	meta := m.Meta()
	if meta.Name != "dns_brute" {
		t.Fatalf("expected name dns_brute, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestDNSBruteWatchedEvents(t *testing.T) {
	m := &DNSBrute{}
	w := m.WatchedEvents()
	if len(w) != 2 {
		t.Fatalf("expected 2 watched events, got %d", len(w))
	}
}

func TestDNSBruteProducedEvents(t *testing.T) {
	m := &DNSBrute{}
	p := m.ProducedEvents()
	if len(p) != 1 {
		t.Fatalf("expected 1 produced event, got %d", len(p))
	}
	if p[0] != event.INTERNET_NAME {
		t.Fatalf("expected INTERNET_NAME, got %s", p[0])
	}
}

func TestDNSBruteHandleNilEvent(t *testing.T) {
	m := &DNSBrute{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestDNSBruteSetup(t *testing.T) {
	m := &DNSBrute{}
	err := m.Setup(map[string]any{
		"maxworkers":   10,
		"domainonly":   false,
		"numbersuffix": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.maxWorkers != 10 {
		t.Fatalf("expected maxWorkers 10, got %d", m.maxWorkers)
	}
	if m.domainOnly {
		t.Fatal("expected domainOnly false")
	}
	if m.numSuffix {
		t.Fatal("expected numSuffix false")
	}
}

func TestDNSBruteDedup(t *testing.T) {
	m := &DNSBrute{}
	_ = m.Setup(nil)

	if m.markSeen("example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("example.com") {
		t.Fatal("second call should return true")
	}
}

func TestDNSBruteDomainOnlySkipsInternetName(t *testing.T) {
	m := &DNSBrute{}
	_ = m.Setup(nil) // domainOnly defaults to true

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.INTERNET_NAME, "www.example.com", "test", root)
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results when domainOnly=true and type=INTERNET_NAME, got %d", len(results))
	}
}
