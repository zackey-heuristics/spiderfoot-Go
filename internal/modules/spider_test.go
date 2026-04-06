package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestSpiderMeta(t *testing.T) {
	m := &Spider{}
	meta := m.Meta()
	if meta.Name != "spider" {
		t.Fatalf("expected name spider, got %s", meta.Name)
	}
	if meta.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestSpiderWatchedEvents(t *testing.T) {
	m := &Spider{}
	w := m.WatchedEvents()
	if len(w) != 2 {
		t.Fatalf("expected 2 watched events, got %d", len(w))
	}
}

func TestSpiderProducedEvents(t *testing.T) {
	m := &Spider{}
	p := m.ProducedEvents()
	if len(p) != 6 {
		t.Fatalf("expected 6 produced events, got %d", len(p))
	}
}

func TestSpiderHandleNilEvent(t *testing.T) {
	m := &Spider{}
	_ = m.Setup(nil)
	results, err := m.HandleEvent(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("expected nil results for nil event")
	}
}

func TestSpiderSetup(t *testing.T) {
	m := &Spider{}
	err := m.Setup(map[string]any{
		"maxpages":  50,
		"maxlevels": 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.maxPages != 50 {
		t.Fatalf("expected maxPages 50, got %d", m.maxPages)
	}
	if m.maxLevels != 2 {
		t.Fatalf("expected maxLevels 2, got %d", m.maxLevels)
	}
}

func TestSpiderShouldSkip(t *testing.T) {
	m := &Spider{}
	_ = m.Setup(nil)

	if !m.shouldSkip("http://example.com/image.png") {
		t.Fatal("should skip .png files")
	}
	if !m.shouldSkip("http://example.com/doc.PDF") {
		t.Fatal("should skip .PDF files (case insensitive)")
	}
	if m.shouldSkip("http://example.com/page.html") {
		t.Fatal("should not skip .html files")
	}
}

func TestSpiderCrawlHTTPTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>
			<a href="/about">About</a>
			<a href="https://external.com/link">External</a>
		</body></html>`))
	}))
	defer srv.Close()

	m := &Spider{}
	_ = m.Setup(map[string]any{"maxpages": 5, "maxlevels": 1})

	root, _ := event.New(event.ROOT, "test", "", nil)
	evt, _ := event.New(event.LINKED_URL_INTERNAL, srv.URL, "test", root)

	results, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}

	// Should get at least: HTTP_CODE, WEBSERVER_HTTPHEADERS, TARGET_WEB_CONTENT_TYPE, TARGET_WEB_CONTENT
	if len(results) < 4 {
		t.Fatalf("expected at least 4 results, got %d", len(results))
	}

	types := make(map[event.Type]bool)
	for _, r := range results {
		types[r.Type] = true
	}
	if !types[event.HTTP_CODE] {
		t.Fatal("expected HTTP_CODE event")
	}
	if !types[event.TARGET_WEB_CONTENT] {
		t.Fatal("expected TARGET_WEB_CONTENT event")
	}
}
