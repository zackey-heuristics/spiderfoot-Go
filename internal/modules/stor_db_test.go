package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func TestStorDBMeta(t *testing.T) {
	s := &StorDB{}
	m := s.Meta()
	if m.Name != "stor_db" {
		t.Fatalf("expected name stor_db, got %s", m.Name)
	}
	if len(m.Categories) == 0 || m.Categories[0] != "internal" {
		t.Fatal("expected category internal")
	}
}

func TestStorDBSetupMissingDB(t *testing.T) {
	s := &StorDB{}
	if err := s.Setup(map[string]any{"__scanid": "x"}); err == nil {
		t.Fatal("expected error for missing __db")
	}
}

func TestStorDBSetupMissingScanID(t *testing.T) {
	s := &StorDB{}
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := s.Setup(map[string]any{"__db": database}); err == nil {
		t.Fatal("expected error for missing __scanid")
	}
}

func TestStorDBHandleEvent(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	scanID := "stor-test-1"
	if err := database.ScanCreate(scanID, "test", "example.com"); err != nil {
		t.Fatal(err)
	}

	s := &StorDB{}
	if err := s.Setup(map[string]any{"__db": database, "__scanid": scanID}); err != nil {
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

	results, err := s.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if results != nil {
		t.Fatal("stor_db should not produce events")
	}

	stored, err := database.EventsGet(scanID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored event, got %d", len(stored))
	}
	if stored[0].Type != string(event.DOMAIN_NAME) {
		t.Fatalf("expected DOMAIN_NAME, got %s", stored[0].Type)
	}
}
