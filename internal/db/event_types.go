package db

import (
	"fmt"
	"sort"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func (d *DB) seedEventTypes() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	registry := event.Registry()
	keys := make([]string, 0, len(registry))
	for typ := range registry {
		keys = append(keys, string(typ))
	}
	sort.Strings(keys)

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin event type seed transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO tbl_event_types (event, event_descr, event_raw, event_type) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare event type seed: %w", err)
	}
	defer stmt.Close()

	for _, key := range keys {
		info := registry[event.Type(key)]
		raw := 0
		if info.IsRaw {
			raw = 1
		}

		if _, err := stmt.Exec(key, info.Description, raw, info.Category); err != nil {
			return fmt.Errorf("seed event type %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event type seed: %w", err)
	}

	return nil
}
