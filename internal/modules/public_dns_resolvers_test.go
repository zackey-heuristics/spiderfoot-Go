package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

var publicDNSResolverNames = []string{
	"adguard_dns",
	"cleanbrowsing",
	"cloudflaredns",
	"comodo",
	"opendns",
	"quad9",
	"yandexdns",
}

func getModule(name string) func() module.Module {
	f, ok := module.Get(name)
	if !ok {
		return nil
	}
	return f
}

func TestPublicDNSResolversRegistered(t *testing.T) {
	for _, name := range publicDNSResolverNames {
		if getModule(name) == nil {
			t.Errorf("module %s not registered", name)
		}
	}
}

func TestPublicDNSResolverMeta(t *testing.T) {
	for _, name := range publicDNSResolverNames {
		factory := getModule(name)
		if factory == nil {
			t.Fatalf("module %s not registered", name)
		}
		m := factory()
		meta := m.Meta()
		if meta.Name != name {
			t.Errorf("%s: expected name %s, got %s", name, name, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", name)
		}
	}
}

func TestPublicDNSResolverWatchedEvents(t *testing.T) {
	m := getModule("quad9")()
	w := m.WatchedEvents()
	if len(w) != 3 {
		t.Fatalf("expected 3 watched events, got %d", len(w))
	}
}

func TestPublicDNSResolverProducedEvents(t *testing.T) {
	m := getModule("quad9")()
	p := m.ProducedEvents()
	if len(p) != 6 {
		t.Fatalf("expected 6 produced events, got %d", len(p))
	}
}

func TestPublicDNSResolverSetup(t *testing.T) {
	for _, name := range publicDNSResolverNames {
		m := getModule(name)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: Setup failed: %v", name, err)
		}
	}
}

func TestPublicDNSResolverHandleNilEvent(t *testing.T) {
	m := getModule("quad9")()
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil for nil event")
	}
}

func TestPublicDNSResolverHandleUnknownEventType(t *testing.T) {
	m := getModule("quad9")()
	_ = m.Setup(nil)
	evt, _ := event.New(event.IP_ADDRESS, "8.8.8.8", "test", nil)
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil for unsupported event type")
	}
}

func TestPublicDNSResolverHandleEmptyData(t *testing.T) {
	m := getModule("quad9")()
	_ = m.Setup(nil)
	evt := &event.Event{Type: event.INTERNET_NAME, Data: ""}
	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil for empty data")
	}
}

func TestPublicDNSResolverFinish(t *testing.T) {
	m := getModule("quad9")()
	_ = m.Setup(nil)
	if err := m.Finish(); err != nil {
		t.Fatal(err)
	}
}
