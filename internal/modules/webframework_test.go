package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestWebFrameworkMeta(t *testing.T) {
	m := &WebFramework{}
	meta := m.Meta()
	if meta.Name != "webframework" {
		t.Fatalf("expected name webframework, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestWebFrameworkWatchedEvents(t *testing.T) {
	m := &WebFramework{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
	if w[0] != event.TARGET_WEB_CONTENT {
		t.Fatalf("expected TARGET_WEB_CONTENT, got %s", w[0])
	}
}

func TestWebFrameworkProducedEvents(t *testing.T) {
	m := &WebFramework{}
	p := m.ProducedEvents()
	if len(p) != 1 {
		t.Fatalf("expected 1 produced event, got %d", len(p))
	}
}

func TestWebFrameworkHandleNilEvent(t *testing.T) {
	m := &WebFramework{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestWebFrameworkSetup(t *testing.T) {
	m := &WebFramework{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
}

func TestWebFrameworkDetectsJQuery(t *testing.T) {
	m := &WebFramework{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<html><script src="/js/jquery.min.js"></script></html>`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_WEB_FRAMEWORK && r.Data == "jQuery" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected jQuery framework to be detected")
	}
}

func TestWebFrameworkDetectsBootstrap(t *testing.T) {
	m := &WebFramework{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<link rel="stylesheet" href="/bootstrap/css/bootstrap.css">`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_WEB_FRAMEWORK && r.Data == "Bootstrap" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected Bootstrap framework to be detected")
	}
}

func TestWebFrameworkDetectsWordpress(t *testing.T) {
	m := &WebFramework{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	content := `<link rel="stylesheet" href="/wp-content/themes/style.css">`
	evt, _ := event.New(event.TARGET_WEB_CONTENT, content, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.URL_WEB_FRAMEWORK && r.Data == "Wordpress" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected Wordpress to be detected")
	}
}
