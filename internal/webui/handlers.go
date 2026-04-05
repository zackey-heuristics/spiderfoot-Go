package webui

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
)

func (s *Server) routes() {
	s.mux.HandleFunc("GET /ping", s.handlePing)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/results", s.handleGetResults)
	s.mux.HandleFunc("GET /api/scans/{id}/summary", s.handleGetSummary)
	s.mux.HandleFunc("POST /api/scans/{id}/delete", s.handleDeleteScan)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("POST /api/config", s.handleSetConfig)
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) handleListScans(w http.ResponseWriter, _ *http.Request) {
	scans, err := s.database.ScanList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scans == nil {
		scans = []db.ScanInstance{}
	}
	writeJSON(w, scans)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	scan, err := s.database.ScanGet(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scan == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	writeJSON(w, scan)
}

func (s *Server) handleGetResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	eventType := r.URL.Query().Get("type")
	events, err := s.database.EventsGet(id, eventType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []db.StoredEvent{}
	}
	writeJSON(w, events)
}

func (s *Server) handleGetSummary(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	summary, err := s.database.ScanResultSummary(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if summary == nil {
		summary = []db.ResultSummary{}
	}
	writeJSON(w, summary)
}

func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.database.ScanDelete(id); err != nil {
		if errors.Is(err, db.ErrScanNotFound) {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.database.ConfigGet()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, cfg)
}

func (s *Server) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit

	var opts map[string]string
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	for key := range opts {
		if strings.TrimSpace(key) == "" {
			http.Error(w, "config key must not be empty", http.StatusBadRequest)
			return
		}
	}
	if err := s.database.ConfigSet(opts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		s.handleListScans(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><title>SpiderFoot</title></head>
<body><h1>SpiderFoot</h1><p>Phase 1 &mdash; <a href="/api/scans">View Scans (JSON)</a></p></body>
</html>`))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
