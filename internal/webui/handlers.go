package webui

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
)

func (s *Server) routes() {
	// Static assets (embedded via go:embed).
	staticSub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	// HTML pages.
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.HandleFunc("GET /newscan", s.handleNewScanPage)
	s.mux.HandleFunc("GET /scaninfo", s.handleScanInfoPage)
	s.mux.HandleFunc("GET /opts", s.handleSettingsPage)

	// API endpoints.
	s.mux.HandleFunc("GET /ping", s.handlePing)
	s.mux.HandleFunc("GET /api/scans", s.handleListScans)
	s.mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/scans/{id}/results", s.handleGetResults)
	s.mux.HandleFunc("GET /api/scans/{id}/summary", s.handleGetSummary)
	s.mux.HandleFunc("GET /api/scans/{id}/log", s.handleGetScanLog)
	s.mux.HandleFunc("GET /api/scans/{id}/search", s.handleSearchResults)
	s.mux.HandleFunc("GET /api/scans/{id}/export", s.handleExportResults)
	s.mux.HandleFunc("POST /api/scans/{id}/delete", s.handleDeleteScan)
	s.mux.HandleFunc("POST /api/scans/{id}/falsepositive", s.handleSetFalsePositive)
	s.mux.HandleFunc("POST /api/startscan", s.handleStartScan)
	s.mux.HandleFunc("POST /api/rerunscan", s.handleRerunScan)
	s.mux.HandleFunc("POST /api/stopscan", s.handleStopScan)
	s.mux.HandleFunc("GET /api/scanstatus", s.handleScanStatus)
	s.mux.HandleFunc("GET /api/modules", s.handleListModules)
	s.mux.HandleFunc("GET /api/eventtypes", s.handleListEventTypes)
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("POST /api/config", s.handleSetConfig)
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

	// If this server owns the scan, abort and wait for shutdown.
	if val, ok := s.scanners.Load(id); ok {
		as := val.(*activeScan)
		as.scanner.Abort()
		as.cancel()
		exited := false
		for i := 0; i < 100; i++ {
			if _, stillRunning := s.scanners.Load(id); !stillRunning {
				exited = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !exited {
			http.Error(w, "scan is still shutting down; try again shortly", http.StatusConflict)
			return
		}
	} else {
		// Not owned by this server — check DB status before deleting.
		si, err := s.database.ScanGet(id)
		if err != nil || si == nil {
			// Doesn't exist — let ScanDelete return ErrScanNotFound below.
		} else if si.Status == "RUNNING" || si.Status == "CREATED" || si.Status == "ABORT-REQUESTED" {
			http.Error(w, "scan is in non-terminal state "+si.Status+" and not managed by this server; stop it first", http.StatusConflict)
			return
		}
	}

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
	s.renderPage(w, "scanlist.html", pageData{PageID: "SCANLIST"})
}

func (s *Server) handleNewScanPage(w http.ResponseWriter, _ *http.Request) {
	s.renderPage(w, "newscan.html", pageData{PageID: "NEWSCAN"})
}

// scanInfoData carries data for the scan info template.
type scanInfoData struct {
	ID     string
	Name   string
	Target string
	Status string
}

func (s *Server) handleScanInfoPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	si, err := s.database.ScanGet(id)
	if err != nil || si == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	s.renderPage(w, "scaninfo.html", pageData{
		PageID: "SCANINFO",
		Data: scanInfoData{
			ID:     si.GUID,
			Name:   si.Name,
			Target: si.SeedTarget,
			Status: si.Status,
		},
	})
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, _ *http.Request) {
	s.renderPage(w, "settings.html", pageData{PageID: "SETTINGS"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
