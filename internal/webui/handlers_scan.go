package webui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/scan"
)

// startScanRequest is the JSON body for POST /api/startscan.
type startScanRequest struct {
	ScanName   string `json:"scanname"`
	ScanTarget string `json:"scantarget"`
	ModuleList string `json:"modulelist"`
	TypeList   string `json:"typelist"`
	UseCase    string `json:"usecase"`
}

// handleStartScan creates and launches a new scan.
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	target := strings.TrimSpace(req.ScanTarget)
	if target == "" {
		http.Error(w, "scantarget is required", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.ScanName)
	if name == "" {
		name = target
	}

	// Build module list. Only use all modules when explicitly requested.
	mods := s.resolveModules(req)
	if len(mods) == 0 {
		// Explicit "all" use case — use all modules.
		if req.UseCase == "all" || req.UseCase == "" && req.ModuleList == "" && req.TypeList == "" {
			mods = module.All()
		} else {
			http.Error(w, "no modules matched the requested selection", http.StatusBadRequest)
			return
		}
	}

	// Always include stor_db for persistence.
	hasStor := false
	for _, m := range mods {
		if m == "stor_db" {
			hasStor = true
			break
		}
	}
	if !hasStor {
		mods = append([]string{"stor_db"}, mods...)
	}

	scanID := uuid.New().String()
	if err := s.database.ScanCreate(scanID, name, target); err != nil {
		http.Error(w, "failed to create scan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Persist the module list so rerun can replay the exact configuration.
	_ = s.database.ScanConfigSet(scanID, map[string]string{
		"__modulelist": strings.Join(mods, ","),
	})

	bus := event.NewBus()
	scanner := scan.New(s.database, bus, s.cfg, scanID, target, mods)

	ctx, cancel := context.WithCancel(context.Background())
	s.scanners.Store(scanID, &activeScan{scanner: scanner, cancel: cancel})

	go func() {
		defer s.scanners.Delete(scanID)
		defer cancel()
		if err := scanner.Start(ctx); err != nil {
			slog.Info("scan completed", "id", scanID, "result", err.Error())
		}
	}()

	// Wait briefly for scan to reach RUNNING.
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		si, _ := s.database.ScanGet(scanID)
		if si != nil && si.Status != "CREATED" {
			break
		}
	}

	writeJSON(w, map[string]string{"status": "ok", "scanId": scanID})
}

// resolveModules determines which modules to use based on the request.
func (s *Server) resolveModules(req startScanRequest) []string {
	if req.ModuleList != "" {
		var mods []string
		for _, m := range strings.Split(req.ModuleList, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				mods = append(mods, m)
			}
		}
		return mods
	}

	if req.TypeList != "" {
		// Filter modules by produced event types.
		wanted := make(map[event.Type]bool)
		for _, t := range strings.Split(req.TypeList, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				wanted[event.Type(t)] = true
			}
		}
		var mods []string
		for _, name := range module.All() {
			factory, ok := module.Get(name)
			if !ok {
				continue
			}
			mod := factory()
			for _, produced := range mod.ProducedEvents() {
				if wanted[produced] {
					mods = append(mods, name)
					break
				}
			}
		}
		return mods
	}

	if req.UseCase != "" && req.UseCase != "all" {
		// Filter modules by use case category.
		var mods []string
		for _, name := range module.All() {
			factory, ok := module.Get(name)
			if !ok {
				continue
			}
			mod := factory()
			meta := mod.Meta()
			for _, cat := range meta.Categories {
				if strings.EqualFold(cat, req.UseCase) {
					mods = append(mods, name)
					break
				}
			}
		}
		return mods
	}

	// No filters provided — return nil so the caller decides.
	return nil
}

// handleStopScan aborts a running scan.
func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	id := strings.TrimSpace(req.ID)
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	val, ok := s.scanners.Load(id)
	if ok {
		as := val.(*activeScan)
		as.scanner.Abort()
		writeJSON(w, map[string]string{"status": "ok"})
		return
	}

	// Not in active map — check DB.
	si, err := s.database.ScanGet(id)
	if err != nil || si == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if si.Status == "FINISHED" || si.Status == "ABORTED" || si.Status == "ERROR-FAILED" {
		writeJSON(w, map[string]string{"status": "already_completed", "scanStatus": si.Status})
		return
	}

	// Scan in DB as RUNNING but not owned by this server — cannot confirm
	// execution state. Return conflict instead of synthesizing ABORTED.
	http.Error(w, "scan is in state "+si.Status+" but not managed by this server; cannot stop", http.StatusConflict)
}

// handleScanStatus returns the live status of a scan.
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id parameter required", http.StatusBadRequest)
		return
	}

	// Check active scanner first.
	if val, ok := s.scanners.Load(id); ok {
		as := val.(*activeScan)
		writeJSON(w, map[string]string{"status": string(as.scanner.GetStatus())})
		return
	}

	// Fall back to DB.
	si, err := s.database.ScanGet(id)
	if err != nil || si == nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{"status": si.Status})
}

// handleListModules returns all registered modules with metadata.
func (s *Server) handleListModules(w http.ResponseWriter, _ *http.Request) {
	names := module.All()
	type modInfo struct {
		Name       string   `json:"Name"`
		Summary    string   `json:"Summary"`
		Categories []string `json:"Categories"`
	}
	var result []modInfo
	for _, name := range names {
		factory, ok := module.Get(name)
		if !ok {
			continue
		}
		mod := factory()
		meta := mod.Meta()
		result = append(result, modInfo{
			Name:       meta.Name,
			Summary:    meta.Summary,
			Categories: meta.Categories,
		})
	}
	writeJSON(w, result)
}

// handleListEventTypes returns the event type registry.
func (s *Server) handleListEventTypes(w http.ResponseWriter, _ *http.Request) {
	registry := event.Registry()
	writeJSON(w, registry)
}

// handleGetScanLog returns log entries for a scan.
func (s *Server) handleGetScanLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	entries, err := s.database.ScanLogGet(id, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, entries)
}

// handleSearchResults searches scan events by data value.
func (s *Server) handleSearchResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	value := r.URL.Query().Get("value")
	eventType := r.URL.Query().Get("type")

	events, err := s.database.EventsSearch(id, value, eventType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

// safeIDPrefix returns up to the first 8 characters of an ID for filenames.
func safeIDPrefix(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// handleExportResults exports scan results as CSV or JSON.
func (s *Server) handleExportResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	format := r.URL.Query().Get("format")

	events, err := s.database.EventsGet(id, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	prefix := safeIDPrefix(id)

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=spiderfoot-%s.csv", prefix))
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Type", "Module", "Data", "SourceEventHash", "Generated", "FalsePositive"})
		for _, evt := range events {
			fp := "false"
			if evt.FalsePositive {
				fp = "true"
			}
			_ = cw.Write([]string{
				evt.Type,
				evt.Module,
				evt.Data,
				evt.SourceEventHash,
				time.UnixMilli(evt.Generated).UTC().Format(time.RFC3339),
				fp,
			})
		}
		cw.Flush()

	default: // JSON
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=spiderfoot-%s.json", prefix))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(events)
	}
}

// handleSetFalsePositive toggles the false positive flag on scan events.
func (s *Server) handleSetFalsePositive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		Hashes []string `json:"hashes"`
		FP     bool     `json:"fp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := s.database.EventSetFalsePositive(id, req.Hashes, req.FP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// handleRerunScan clones an existing scan's config and starts a new scan.
func (s *Server) handleRerunScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	origID := strings.TrimSpace(req.ID)
	if origID == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}

	orig, err := s.database.ScanGet(origID)
	if err != nil || orig == nil {
		http.Error(w, "original scan not found", http.StatusNotFound)
		return
	}

	// Retrieve the original scan's module list.
	origConfig, err := s.database.ScanConfigGet(origID)
	if err != nil {
		http.Error(w, "failed to read original scan config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	startReq := startScanRequest{
		ScanName:   orig.Name + " (rerun)",
		ScanTarget: orig.SeedTarget,
	}

	if modList, ok := origConfig["__modulelist"]; ok && modList != "" {
		startReq.ModuleList = modList
	} else {
		// Original config unavailable — reject instead of silently widening scope.
		http.Error(w, "original scan configuration not available; cannot rerun", http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(startReq)
	fakeReq, _ := http.NewRequest(http.MethodPost, "/api/startscan", strings.NewReader(string(body)))
	fakeReq.Header.Set("Content-Type", "application/json")
	s.handleStartScan(w, fakeReq)
}
