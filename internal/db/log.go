package db

import (
	"fmt"
	"time"
)

// LogEntry represents a stored scan log message.
type LogEntry struct {
	// ScanID is the owning scan instance identifier.
	ScanID string
	// Generated is the log timestamp in Unix milliseconds.
	Generated int64
	// Component is the emitting component or module.
	Component string
	// Type is the log classification.
	Type string
	// Message is the log payload.
	Message string
}

// ScanLogEvent stores a log event for a scan.
func (d *DB) ScanLogEvent(scanID string, component, logType, message string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if component == "" {
		component = "SpiderFoot"
	}

	_, err := d.db.Exec(
		`INSERT INTO tbl_scan_log (scan_instance_id, generated, component, type, message) VALUES (?, ?, ?, ?, ?)`,
		scanID,
		time.Now().UTC().UnixMilli(),
		component,
		logType,
		message,
	)
	if err != nil {
		return fmt.Errorf("store scan log event: %w", err)
	}

	return nil
}

// ScanLogGet returns stored log entries for a scan, ordered newest first.
func (d *DB) ScanLogGet(scanID string, limit int) ([]LogEntry, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT scan_instance_id, generated, component, type, message
		FROM tbl_scan_log
		WHERE scan_instance_id = ?
		ORDER BY generated DESC, rowid DESC`
	args := []any{scanID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query scan logs: %w", err)
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var entry LogEntry
		if err := rows.Scan(&entry.ScanID, &entry.Generated, &entry.Component, &entry.Type, &entry.Message); err != nil {
			return nil, fmt.Errorf("scan log row: %w", err)
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan logs: %w", err)
	}

	return entries, nil
}
