package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestPageInfoMeta(t *testing.T) {
	m := &PageInfo{}
	meta := m.Meta()
	if meta.Name != "pageinfo" {
		t.Fatalf("expected name pageinfo, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestPageInfoWatchedEvents(t *testing.T) {
	m := &PageInfo{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
}

func TestPageInfoProducedEvents(t *testing.T) {
	m := &PageInfo{}
	p := m.ProducedEvents()
	if len(p) != 8 {
		t.Fatalf("expected 8 produced events, got %d", len(p))
	}
}

func TestPageInfoHandleNilEvent(t *testing.T) {
	m := &PageInfo{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestPageInfoSetup(t *testing.T) {
	m := &PageInfo{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
}

func TestPageInfoDetectsForm(t *testing.T) {
	m := &PageInfo{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<html><body><form method="POST"><input type="text" name="q"></form></body></html>`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_FORM {
			found = true
		}
	}
	if !found {
		t.Fatal("expected URL_FORM event for page with form")
	}
}

func TestPageInfoDetectsPassword(t *testing.T) {
	m := &PageInfo{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<html><body><input type="password" name="pass"></body></html>`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_PASSWORD {
			found = true
		}
	}
	if !found {
		t.Fatal("expected URL_PASSWORD event")
	}
}

func TestPageInfoStaticPage(t *testing.T) {
	m := &PageInfo{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<html><body><p>Just text content.</p></body></html>`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_STATIC {
			found = true
		}
	}
	if !found {
		t.Fatal("expected URL_STATIC event for plain page")
	}
}

func TestPageInfoDetectsExternalJS(t *testing.T) {
	m := &PageInfo{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<html><script src="https://cdn.example.com/lib.js"></script></html>`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.PROVIDER_JAVASCRIPT {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PROVIDER_JAVASCRIPT event for external script")
	}
}
