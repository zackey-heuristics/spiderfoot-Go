package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestWebServerMeta(t *testing.T) {
	m := &WebServer{}
	meta := m.Meta()
	if meta.Name != "webserver" {
		t.Fatalf("expected name webserver, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestWebServerWatchedEvents(t *testing.T) {
	m := &WebServer{}
	w := m.WatchedEvents()
	if len(w) != 1 {
		t.Fatalf("expected 1 watched event, got %d", len(w))
	}
}

func TestWebServerProducedEvents(t *testing.T) {
	m := &WebServer{}
	p := m.ProducedEvents()
	if len(p) != 2 {
		t.Fatalf("expected 2 produced events, got %d", len(p))
	}
}

func TestWebServerHandleNilEvent(t *testing.T) {
	m := &WebServer{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestWebServerSetup(t *testing.T) {
	m := &WebServer{}
	if err := m.Setup(nil); err != nil {
		t.Fatal(err)
	}
}

func TestWebServerExtractsBanner(t *testing.T) {
	m := &WebServer{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	headers := "Server: nginx/1.18.0\nContent-Type: text/html\nX-Powered-By: PHP/7.4"
	evt, _ := event.New(event.WEBSERVER_HTTPHEADERS, headers, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	var foundBanner, foundTech bool
	for _, r := range results {
		if r.Type == event.WEBSERVER_BANNER && r.Data == "nginx/1.18.0" {
			foundBanner = true
		}
		if r.Type == event.WEBSERVER_TECHNOLOGY && r.Data == "PHP/7.4" {
			foundTech = true
		}
	}
	if !foundBanner {
		t.Fatal("expected WEBSERVER_BANNER event for nginx")
	}
	if !foundTech {
		t.Fatal("expected WEBSERVER_TECHNOLOGY event for PHP")
	}
}

func TestWebServerDetectsPHPFromCookie(t *testing.T) {
	m := &WebServer{}
	_ = m.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	headers := "Set-Cookie: PHPSESSID=abc123; path=/"
	evt, _ := event.New(event.WEBSERVER_HTTPHEADERS, headers, "spider", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range results {
		if r.Type == event.WEBSERVER_TECHNOLOGY && r.Data == "PHP" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PHP detection from PHPSESSID cookie")
	}
}
