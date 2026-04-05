package db

import (
	"fmt"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

// StoredEvent is the persisted representation of a SpiderFoot event.
type StoredEvent struct {
	// ScanID is the owning scan instance identifier.
	ScanID string
	// Hash is the event hash.
	Hash string
	// Type is the event type identifier.
	Type string
	// Generated is the event timestamp in Unix milliseconds.
	Generated int64
	// Confidence is the event confidence score.
	Confidence int
	// Visibility is the event visibility score.
	Visibility int
	// Risk is the event risk score.
	Risk int
	// Module is the module that produced the event.
	Module string
	// Data is the event payload.
	Data string
	// FalsePositive reports whether the event is flagged as a false positive.
	FalsePositive bool
	// SourceEventHash is the parent event hash, or ROOT.
	SourceEventHash string
}

// EventStore persists a scan event.
func (d *DB) EventStore(scanID string, evt *event.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	falsePositive := 0
	_, err := d.db.Exec(
		`INSERT INTO tbl_scan_results
		 (scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID,
		evt.Hash(),
		string(evt.Type),
		evt.Generated.UTC().UnixMilli(),
		evt.Confidence,
		evt.Visibility,
		evt.Risk,
		evt.Module,
		evt.Data,
		falsePositive,
		evt.SourceEventHash(),
	)
	if err != nil {
		return fmt.Errorf("store event: %w", err)
	}

	return nil
}

// EventsGet returns stored events for a scan, optionally filtered by event type.
func (d *DB) EventsGet(scanID string, eventType string) ([]StoredEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash
		FROM tbl_scan_results
		WHERE scan_instance_id = ?`
	args := []any{scanID}
	if eventType != "" {
		query += ` AND type = ?`
		args = append(args, eventType)
	}
	query += ` ORDER BY generated ASC, hash ASC`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query stored events: %w", err)
	}
	defer rows.Close()

	var events []StoredEvent
	for rows.Next() {
		var evt StoredEvent
		var falsePositive int
		if err := rows.Scan(
			&evt.ScanID,
			&evt.Hash,
			&evt.Type,
			&evt.Generated,
			&evt.Confidence,
			&evt.Visibility,
			&evt.Risk,
			&evt.Module,
			&evt.Data,
			&falsePositive,
			&evt.SourceEventHash,
		); err != nil {
			return nil, fmt.Errorf("scan stored event row: %w", err)
		}

		evt.FalsePositive = falsePositive != 0
		events = append(events, evt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stored events: %w", err)
	}

	return events, nil
}

// EventsGetUnique returns unique event data values for a scan, optionally filtered by event type.
func (d *DB) EventsGetUnique(scanID, eventType string) ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT DISTINCT data
		FROM tbl_scan_results
		WHERE scan_instance_id = ?`
	args := []any{scanID}
	if eventType != "" {
		query += ` AND type = ?`
		args = append(args, eventType)
	}
	query += ` ORDER BY data ASC`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query unique event data: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, fmt.Errorf("scan unique event row: %w", err)
		}

		values = append(values, value)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unique event rows: %w", err)
	}

	return values, nil
}

// EventsSearch returns stored events whose data matches the search value.
func (d *DB) EventsSearch(scanID, value, eventType string) ([]StoredEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT scan_instance_id, hash, type, generated, confidence, visibility, risk, module, data, false_positive, source_event_hash
		FROM tbl_scan_results
		WHERE scan_instance_id = ? AND data LIKE ?`
	args := []any{scanID, "%" + value + "%"}
	if eventType != "" {
		query += ` AND type = ?`
		args = append(args, eventType)
	}
	query += ` ORDER BY generated ASC, hash ASC`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("search stored events: %w", err)
	}
	defer rows.Close()

	var events []StoredEvent
	for rows.Next() {
		var evt StoredEvent
		var falsePositive int
		if err := rows.Scan(
			&evt.ScanID, &evt.Hash, &evt.Type, &evt.Generated,
			&evt.Confidence, &evt.Visibility, &evt.Risk,
			&evt.Module, &evt.Data, &falsePositive, &evt.SourceEventHash,
		); err != nil {
			return nil, fmt.Errorf("scan search result row: %w", err)
		}
		evt.FalsePositive = falsePositive != 0
		events = append(events, evt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate search results: %w", err)
	}

	return events, nil
}

// EventSetFalsePositive updates the false positive flag for events matching the given hashes.
func (d *DB) EventSetFalsePositive(scanID string, hashes []string, fp bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(hashes) == 0 {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin false positive transaction: %w", err)
	}
	defer tx.Rollback()

	fpVal := 0
	if fp {
		fpVal = 1
	}

	stmt, err := tx.Prepare(`UPDATE tbl_scan_results SET false_positive = ? WHERE scan_instance_id = ? AND hash = ?`)
	if err != nil {
		return fmt.Errorf("prepare false positive update: %w", err)
	}
	defer stmt.Close()

	for _, hash := range hashes {
		if _, err := stmt.Exec(fpVal, scanID, hash); err != nil {
			return fmt.Errorf("update false positive for %s: %w", hash, err)
		}
	}

	return tx.Commit()
}
