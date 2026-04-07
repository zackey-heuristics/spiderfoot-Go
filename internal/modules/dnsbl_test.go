package modules

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestIsDNSNotFoundErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"not-found DNS error", &net.DNSError{IsNotFound: true}, true},
		{"transient DNS error", &net.DNSError{IsNotFound: false}, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := isDNSNotFoundErr(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

var dnsblNames = []string{"spamhaus", "sorbs", "spamcop", "uceprotect", "dronebl", "surbl"}

func TestDNSBLRegistered(t *testing.T) {
	for _, name := range dnsblNames {
		if getModule(name) == nil {
			t.Errorf("module %s not registered", name)
		}
	}
}

func TestDNSBLMeta(t *testing.T) {
	for _, name := range dnsblNames {
		m := getModule(name)()
		meta := m.Meta()
		if meta.Name != name {
			t.Errorf("%s: wrong name %s", name, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", name)
		}
	}
}

func TestDNSBLWatchedEvents(t *testing.T) {
	m := getModule("spamhaus")()
	if len(m.WatchedEvents()) != 2 {
		t.Fatalf("expected 2 watched events, got %d", len(m.WatchedEvents()))
	}
	m2 := getModule("surbl")()
	if len(m2.WatchedEvents()) != 5 {
		t.Fatalf("expected 5 watched events for surbl, got %d", len(m2.WatchedEvents()))
	}
}

func TestDNSBLProducedEvents(t *testing.T) {
	m := getModule("spamhaus")()
	if len(m.ProducedEvents()) != 4 {
		t.Fatalf("expected 4 produced events, got %d", len(m.ProducedEvents()))
	}
	m2 := getModule("surbl")()
	if len(m2.ProducedEvents()) != 10 {
		t.Fatalf("expected 10 produced events for surbl, got %d", len(m2.ProducedEvents()))
	}
}

func TestDNSBLSetup(t *testing.T) {
	for _, name := range dnsblNames {
		m := getModule(name)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup failed: %v", name, err)
		}
	}
}

func TestDNSBLHandleNilEvent(t *testing.T) {
	m := getModule("spamhaus")()
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil || results != nil {
		t.Fatalf("expected nil,nil got %v,%v", results, err)
	}
}

func TestDNSBLHandleInvalidIP(t *testing.T) {
	m := getModule("spamhaus")()
	_ = m.Setup(nil)
	evt, _ := event.New(event.IP_ADDRESS, "not-an-ip", "test", nil)
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil for invalid IP")
	}
}

func TestDNSBLHandleUnsupportedEventType(t *testing.T) {
	m := getModule("spamhaus")()
	_ = m.Setup(nil)
	evt, _ := event.New(event.INTERNET_NAME, "example.com", "test", nil)
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil for domain on IP-only DNSBL")
	}
}

func TestReverseIPv4(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":     "4.3.2.1",
		"127.0.0.1":   "1.0.0.127",
		"not-an-ip":   "",
		"::1":         "",
		"256.0.0.1":   "",
	}
	for in, want := range cases {
		if got := reverseIPv4(in); got != want {
			t.Errorf("reverseIPv4(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDNSBLFinish(t *testing.T) {
	m := getModule("spamhaus")()
	_ = m.Setup(nil)
	if err := m.Finish(); err != nil {
		t.Fatal(err)
	}
}
