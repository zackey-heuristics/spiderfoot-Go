package modules

import (
	"context"
	"testing"
)

func TestDNSRawMeta(t *testing.T) {
	m := &DNSRaw{}
	meta := m.Meta()
	if meta.Name != "dns_raw" {
		t.Fatalf("expected name dns_raw, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestDNSRawWatchedEvents(t *testing.T) {
	m := &DNSRaw{}
	w := m.WatchedEvents()
	if len(w) != 3 {
		t.Fatalf("expected 3 watched events, got %d", len(w))
	}
}

func TestDNSRawProducedEvents(t *testing.T) {
	m := &DNSRaw{}
	p := m.ProducedEvents()
	if len(p) != 6 {
		t.Fatalf("expected 6 produced events, got %d", len(p))
	}
}

func TestDNSRawHandleNilEvent(t *testing.T) {
	m := &DNSRaw{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestDNSRawSetup(t *testing.T) {
	m := &DNSRaw{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
	if m.seen == nil {
		t.Fatal("seen map should be initialized")
	}
}

func TestDNSRawDedup(t *testing.T) {
	m := &DNSRaw{}
	_ = m.Setup(nil)

	if m.markSeen("example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("example.com") {
		t.Fatal("second call should return true")
	}
}

func TestSPFIncludeRegex(t *testing.T) {
	txt := "v=spf1 include:_spf.google.com include:mail.example.com ~all"
	matches := spfIncludeRe.FindAllStringSubmatch(txt, -1)
	if len(matches) != 2 {
		t.Fatalf("expected 2 SPF includes, got %d", len(matches))
	}
	if matches[0][1] != "_spf.google.com" {
		t.Fatalf("expected _spf.google.com, got %s", matches[0][1])
	}
	if matches[1][1] != "mail.example.com" {
		t.Fatalf("expected mail.example.com, got %s", matches[1][1])
	}
}
