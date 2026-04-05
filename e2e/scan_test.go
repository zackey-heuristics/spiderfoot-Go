//go:build e2e

// Package e2e contains end-to-end tests for SpiderFoot-Go.
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	_ "github.com/zackey-heuristics/spiderfoot-Go/internal/modules"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/scan"
)

func TestScanLifecycle(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	scanID := "e2e-scan-1"
	if err := database.ScanCreate(scanID, "e2e test", "example.com"); err != nil {
		t.Fatal(err)
	}

	// Verify modules are registered.
	allMods := module.All()
	if len(allMods) < 2 {
		t.Fatalf("expected at least 2 registered modules, got %d: %v", len(allMods), allMods)
	}

	bus := event.NewBus()
	cfg := config.Defaults()

	// Use stor_db only (dns_resolve would make real DNS queries).
	s := scan.New(database, bus, cfg, scanID, "example.com", []string{"stor_db"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	if s.GetStatus() != scan.StatusFinished {
		t.Fatalf("expected FINISHED, got %s", s.GetStatus())
	}

	// Verify DB record is updated.
	si, err := database.ScanGet(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if si.Status != string(scan.StatusFinished) {
		t.Fatalf("DB status expected FINISHED, got %s", si.Status)
	}
	if si.Started == 0 {
		t.Fatal("expected non-zero started time")
	}
	if si.Ended == 0 {
		t.Fatal("expected non-zero ended time")
	}

	// Verify events were stored (at least ROOT).
	events, err := database.EventsGet(scanID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 1 {
		t.Fatal("expected at least 1 stored event")
	}
}
