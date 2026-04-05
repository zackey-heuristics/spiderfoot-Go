package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func setup(t *testing.T) (*Server, *db.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	cfg := config.Defaults()
	cfg.NoAuth = true // Tests run without authentication.
	srv := New(database, cfg)
	return srv, database
}

func TestPing(t *testing.T) {
	srv, _ := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "OK" {
		t.Fatalf("expected OK, got %q", w.Body.String())
	}
}

func TestListScans(t *testing.T) {
	srv, database := setup(t)

	if err := database.ScanCreate("s1", "test scan", "example.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var scans []db.ScanInstance
	if err := json.NewDecoder(w.Body).Decode(&scans); err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}
}

func TestGetScan(t *testing.T) {
	srv, database := setup(t)

	if err := database.ScanCreate("s1", "test scan", "example.com"); err != nil {
		t.Fatal(err)
	}

	// Existing scan.
	req := httptest.NewRequest(http.MethodGet, "/api/scans/s1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Non-existent scan.
	req = httptest.NewRequest(http.MethodGet, "/api/scans/nonexistent", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetResults(t *testing.T) {
	srv, database := setup(t)

	if err := database.ScanCreate("s1", "test scan", "example.com"); err != nil {
		t.Fatal(err)
	}

	rootEvt, err := event.New(event.ROOT, "example.com", "SpiderFoot", nil)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := event.New(event.DOMAIN_NAME, "example.com", "test", rootEvt)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EventStore("s1", evt); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/s1/results", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var events []db.StoredEvent
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestGetSummary(t *testing.T) {
	srv, database := setup(t)

	if err := database.ScanCreate("s1", "test scan", "example.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/s1/summary", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDeleteScan(t *testing.T) {
	srv, database := setup(t)

	if err := database.ScanCreate("s1", "test scan", "example.com"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/scans/s1/delete", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	scan, err := database.ScanGet("s1")
	if err != nil {
		t.Fatal(err)
	}
	if scan != nil {
		t.Fatal("scan should be deleted")
	}
}

func TestConfigRoundTrip(t *testing.T) {
	srv, _ := setup(t)

	body := `{"key1":"value1","key2":"value2"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", w.Code)
	}

	var cfg map[string]string
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["key1"] != "value1" {
		t.Fatalf("expected value1, got %s", cfg["key1"])
	}
}

func TestIndexHTML(t *testing.T) {
	srv, _ := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html, got %s", ct)
	}
}

func TestIndexJSON(t *testing.T) {
	srv, _ := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}
}

func TestAuthMiddlewareRejectsWithoutKey(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	cfg := config.Defaults()
	cfg.APIKey = "secret123"
	srv := New(database, cfg)

	// Non-API routes are accessible without auth.
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for /ping without auth, got %d", w.Code)
	}

	// API route without auth → 401.
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for /api/ without auth, got %d", w.Code)
	}

	// API route with wrong key → 401.
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer wrongkey")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong key, got %d", w.Code)
	}

	// API route with correct key → 200.
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct key, got %d", w.Code)
	}
}

func TestSetConfigEmptyKeyRejected(t *testing.T) {
	srv, _ := setup(t)

	body := `{"":"value","  ":"value2"}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty key, got %d", w.Code)
	}
}

func TestDeleteScanNotFound(t *testing.T) {
	srv, _ := setup(t)

	req := httptest.NewRequest(http.MethodPost, "/api/scans/nonexistent/delete", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent scan delete, got %d", w.Code)
	}
}

func TestCSRFBlocksCrossOriginPost(t *testing.T) {
	srv, _ := setup(t)

	// POST with a foreign Origin should be rejected.
	req := httptest.NewRequest(http.MethodPost, "/api/scans/x/delete", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST, got %d", w.Code)
	}
}

func TestCSRFAllowsNoOrigin(t *testing.T) {
	srv, _ := setup(t)

	// POST without Origin (e.g. curl) should pass through.
	req := httptest.NewRequest(http.MethodPost, "/api/scans/nonexistent/delete", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should reach the handler (404 because scan doesn't exist, not 403).
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (not CSRF block), got %d", w.Code)
	}
}

func TestCSRFAllowsSameOrigin(t *testing.T) {
	srv, _ := setup(t)

	// POST with matching Origin should pass.
	req := httptest.NewRequest(http.MethodPost, "/api/scans/nonexistent/delete", nil)
	req.Header.Set("Origin", "http://127.0.0.1:5001")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (not CSRF block), got %d", w.Code)
	}
}
