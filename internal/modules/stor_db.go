// Package modules contains built-in SpiderFoot-Go module implementations.
package modules

import (
	"context"
	"fmt"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("stor_db", func() module.Module { return &StorDB{} })
}

// StorDB persists all scan events to the database.
type StorDB struct {
	database *db.DB
	scanID   string
}

// Meta returns module metadata.
func (s *StorDB) Meta() module.Meta {
	return module.Meta{
		Name:       "stor_db",
		Summary:    "Stores all events to the database",
		Categories: []string{"internal"},
	}
}

// Setup extracts the database handle and scan ID from options.
func (s *StorDB) Setup(opts map[string]any) error {
	d, ok := opts["__db"]
	if !ok {
		return fmt.Errorf("stor_db: missing __db option")
	}
	s.database, ok = d.(*db.DB)
	if !ok {
		return fmt.Errorf("stor_db: __db is not *db.DB")
	}
	id, ok := opts["__scanid"]
	if !ok {
		return fmt.Errorf("stor_db: missing __scanid option")
	}
	s.scanID, ok = id.(string)
	if !ok {
		return fmt.Errorf("stor_db: __scanid is not string")
	}
	return nil
}

// WatchedEvents returns wildcard to receive all events.
func (s *StorDB) WatchedEvents() []event.Type { return []event.Type{event.Wildcard} }

// ProducedEvents returns nil as this module produces no events.
func (s *StorDB) ProducedEvents() []event.Type { return nil }

// HandleEvent stores the event in the database.
// Context is intentionally ignored: we always persist events, even during
// abort, so that partial scan results are not lost.
func (s *StorDB) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if err := s.database.EventStore(s.scanID, evt); err != nil {
		return nil, fmt.Errorf("stor_db: store event: %w", err)
	}
	return nil, nil
}

// Finish is a no-op for the storage module.
func (s *StorDB) Finish() error { return nil }
