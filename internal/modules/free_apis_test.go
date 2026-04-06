package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

var freeAPINames = []string{
	"hackertarget", "crt", "certspotter", "dnsdumpster",
	"commoncrawl", "archiveorg", "bgpview", "ripe", "robtex",
}

func TestFreeAPIsRegistered(t *testing.T) {
	for _, n := range freeAPINames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestFreeAPIsMeta(t *testing.T) {
	for _, n := range freeAPINames {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %s", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
	}
}

func TestFreeAPIsSetup(t *testing.T) {
	for _, n := range freeAPINames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
		}
	}
}

func TestFreeAPIsWatchedProduced(t *testing.T) {
	for _, n := range freeAPINames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

func TestFreeAPIsHandleNilEvent(t *testing.T) {
	for _, n := range freeAPINames {
		m := getModule(n)()
		_ = m.Setup(nil)
		results, err := m.HandleEvent(context.Background(), nil)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if results != nil {
			t.Errorf("%s: expected nil results for nil event", n)
		}
	}
}

func TestFreeAPIsFinish(t *testing.T) {
	for _, n := range freeAPINames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

func TestRobtexInvalidIP(t *testing.T) {
	m := getModule("robtex")()
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

func TestArchiveOrgUnsupportedType(t *testing.T) {
	m := getModule("archiveorg")()
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
