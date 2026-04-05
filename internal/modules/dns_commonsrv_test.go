package modules

import (
	"context"
	"testing"
)

func TestDNSCommonSRVMeta(t *testing.T) {
	m := &DNSCommonSRV{}
	meta := m.Meta()
	if meta.Name != "dns_commonsrv" {
		t.Fatalf("expected name dns_commonsrv, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestDNSCommonSRVWatchedEvents(t *testing.T) {
	m := &DNSCommonSRV{}
	w := m.WatchedEvents()
	if len(w) != 2 {
		t.Fatalf("expected 2 watched events, got %d", len(w))
	}
}

func TestDNSCommonSRVProducedEvents(t *testing.T) {
	m := &DNSCommonSRV{}
	p := m.ProducedEvents()
	if len(p) != 2 {
		t.Fatalf("expected 2 produced events, got %d", len(p))
	}
}

func TestDNSCommonSRVHandleNilEvent(t *testing.T) {
	m := &DNSCommonSRV{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestDNSCommonSRVSetup(t *testing.T) {
	m := &DNSCommonSRV{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
	if m.seen == nil {
		t.Fatal("seen map should be initialized")
	}
}

func TestDNSCommonSRVDedup(t *testing.T) {
	m := &DNSCommonSRV{}
	_ = m.Setup(nil)

	if m.markSeen("example.com") {
		t.Fatal("first call should return false")
	}
	if !m.markSeen("example.com") {
		t.Fatal("second call should return true")
	}
}

func TestSRVRecordsList(t *testing.T) {
	if len(srvRecords) < 20 {
		t.Fatalf("expected at least 20 SRV records, got %d", len(srvRecords))
	}
}
