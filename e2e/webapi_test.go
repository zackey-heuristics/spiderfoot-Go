//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/webui"
)

func TestWebAPIScans(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	cfg := config.Defaults()
	cfg.NoAuth = true
	srv := webui.New(database, cfg)

	// Health check.
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "OK" {
		t.Fatalf("ping: got %d %q", w.Code, w.Body.String())
	}

	// Create a scan directly in DB.
	if err := database.ScanCreate("e2e-api-1", "api test", "example.com"); err != nil {
		t.Fatal(err)
	}

	// List scans.
	req = httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list scans: got %d", w.Code)
	}

	var scans []db.ScanInstance
	if err := json.NewDecoder(w.Body).Decode(&scans); err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 scan, got %d", len(scans))
	}

	// Get scan.
	req = httptest.NewRequest(http.MethodGet, "/api/scans/e2e-api-1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get scan: got %d", w.Code)
	}

	// Delete scan.
	req = httptest.NewRequest(http.MethodPost, "/api/scans/e2e-api-1/delete", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete scan: got %d", w.Code)
	}

	// Verify deleted.
	req = httptest.NewRequest(http.MethodGet, "/api/scans/e2e-api-1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", w.Code)
	}
}
