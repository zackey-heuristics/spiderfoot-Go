package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestWhoisMeta(t *testing.T) {
	m := &Whois{}
	meta := m.Meta()
	if meta.Name != "whois" {
		t.Fatalf("expected name whois, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestWhoisWatchedEvents(t *testing.T) {
	m := &Whois{}
	w := m.WatchedEvents()
	if len(w) != 4 {
		t.Fatalf("expected 4 watched events, got %d", len(w))
	}
}

func TestWhoisProducedEvents(t *testing.T) {
	m := &Whois{}
	p := m.ProducedEvents()
	if len(p) != 4 {
		t.Fatalf("expected 4 produced events, got %d", len(p))
	}
}

func TestWhoisHandleNilEvent(t *testing.T) {
	m := &Whois{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestWhoisSetup(t *testing.T) {
	m := &Whois{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
	if m.seen == nil {
		t.Fatal("seen map should be initialized")
	}
}

func TestWhoisServer(t *testing.T) {
	tests := map[string]string{
		"example.com": "whois.verisign-grs.com",
		"example.org": "whois.pir.org",
		"example.io":  "whois.nic.io",
		"example.xyz": "", // unknown TLD
	}
	for domain, expected := range tests {
		got := whoisServer(domain)
		if got != expected {
			t.Errorf("whoisServer(%s) = %s, want %s", domain, got, expected)
		}
	}
}

func TestExtractWhoisField(t *testing.T) {
	data := `Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Updated Date: 2024-01-01
`
	registrar := extractWhoisField(data, "Registrar:")
	if registrar != "Example Registrar, Inc." {
		t.Fatalf("expected 'Example Registrar, Inc.', got '%s'", registrar)
	}

	missing := extractWhoisField(data, "Admin Email:")
	if missing != "" {
		t.Fatalf("expected empty string for missing field, got '%s'", missing)
	}
}

func TestWhoisDedup(t *testing.T) {
	m := &Whois{}
	_ = m.Setup(nil)
	if m.markSeen("example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("example.com") {
		t.Fatal("second call should return true")
	}
}

func TestWhoisEventMap(t *testing.T) {
	if whoisEventMap[event.DOMAIN_NAME] != event.DOMAIN_WHOIS {
		t.Fatal("DOMAIN_NAME should map to DOMAIN_WHOIS")
	}
	if whoisEventMap[event.AFFILIATE_DOMAIN_NAME] != event.AFFILIATE_DOMAIN_WHOIS {
		t.Fatal("AFFILIATE_DOMAIN_NAME should map to AFFILIATE_DOMAIN_WHOIS")
	}
}
