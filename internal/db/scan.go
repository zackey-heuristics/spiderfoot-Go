package db

import (
	"database/sql"
	"fmt"
	"time"
)

// ScanInstance describes a stored SpiderFoot scan instance.
type ScanInstance struct {
	// GUID is the scan identifier.
	GUID string
	// Name is the user-facing scan name.
	Name string
	// SeedTarget is the initial target submitted for the scan.
	SeedTarget string
	// Created is the scan creation time in Unix milliseconds.
	Created int64
	// Started is the scan start time in Unix milliseconds.
	Started int64
	// Ended is the scan end time in Unix milliseconds.
	Ended int64
	// Status is the scan lifecycle state.
	Status string
}

// ResultSummary describes a grouped count of scan results by event type.
type ResultSummary struct {
	// Type is the event type identifier.
	Type string
	// Count is the number of results for the type.
	Count int
}

// ScanCreate inserts a new scan instance with CREATED status.
func (d *DB) ScanCreate(guid, name, seedTarget string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		`INSERT INTO tbl_scan_instance (guid, name, seed_target, created, status) VALUES (?, ?, ?, ?, ?)`,
		guid,
		name,
		seedTarget,
		time.Now().UTC().UnixMilli(),
		"CREATED",
	)
	if err != nil {
		return fmt.Errorf("create scan instance: %w", err)
	}

	return nil
}

// ScanGet retrieves a scan instance by GUID, returning nil when it does not exist.
func (d *DB) ScanGet(guid string) (*ScanInstance, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRow(
		`SELECT guid, name, seed_target, created, started, ended, status
		 FROM tbl_scan_instance
		 WHERE guid = ?`,
		guid,
	)

	var scan ScanInstance
	if err := row.Scan(
		&scan.GUID,
		&scan.Name,
		&scan.SeedTarget,
		&scan.Created,
		&scan.Started,
		&scan.Ended,
		&scan.Status,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}

		return nil, fmt.Errorf("get scan instance: %w", err)
	}

	return &scan, nil
}

// ScanUpdateStatus updates the status of an existing scan.
func (d *DB) ScanUpdateStatus(guid string, status string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.db.Exec(`UPDATE tbl_scan_instance SET status = ? WHERE guid = ?`, status, guid); err != nil {
		return fmt.Errorf("update scan status: %w", err)
	}

	return nil
}

// ScanUpdateTimes updates the started and ended timestamps of an existing scan.
func (d *DB) ScanUpdateTimes(guid string, started, ended int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, err := d.db.Exec(
		`UPDATE tbl_scan_instance SET started = ?, ended = ? WHERE guid = ?`,
		started,
		ended,
		guid,
	); err != nil {
		return fmt.Errorf("update scan times: %w", err)
	}

	return nil
}

// ScanList returns all stored scan instances ordered by creation time descending.
func (d *DB) ScanList() ([]ScanInstance, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(
		`SELECT guid, name, seed_target, created, started, ended, status
		 FROM tbl_scan_instance
		 ORDER BY created DESC, guid ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list scan instances: %w", err)
	}
	defer rows.Close()

	var scans []ScanInstance
	for rows.Next() {
		var scan ScanInstance
		if err := rows.Scan(
			&scan.GUID,
			&scan.Name,
			&scan.SeedTarget,
			&scan.Created,
			&scan.Started,
			&scan.Ended,
			&scan.Status,
		); err != nil {
			return nil, fmt.Errorf("scan scan instance row: %w", err)
		}

		scans = append(scans, scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan instances: %w", err)
	}

	return scans, nil
}

// ScanDelete deletes a scan instance and all related rows.
func (d *DB) ScanDelete(guid string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scan delete transaction: %w", err)
	}
	defer tx.Rollback()

	statements := []string{
		`DELETE FROM tbl_scan_correlation_results_events
		 WHERE correlation_id IN (
		 	SELECT id FROM tbl_scan_correlation_results WHERE scan_instance_id = ?
		 )`,
		`DELETE FROM tbl_scan_correlation_results WHERE scan_instance_id = ?`,
		`DELETE FROM tbl_scan_results WHERE scan_instance_id = ?`,
		`DELETE FROM tbl_scan_log WHERE scan_instance_id = ?`,
		`DELETE FROM tbl_scan_config WHERE scan_instance_id = ?`,
		`DELETE FROM tbl_scan_instance WHERE guid = ?`,
	}

	var lastResult sql.Result
	for i, stmt := range statements {
		res, err := tx.Exec(stmt, guid)
		if err != nil {
			return fmt.Errorf("delete scan %q: %w", guid, err)
		}
		if i == len(statements)-1 {
			lastResult = res
		}
	}

	rows, err := lastResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}
	if rows == 0 {
		return ErrScanNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan delete: %w", err)
	}

	return nil
}

// ScanResultSummary returns grouped counts of results for a scan by event type.
func (d *DB) ScanResultSummary(guid string) ([]ResultSummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(
		`SELECT type, COUNT(*)
		 FROM tbl_scan_results
		 WHERE scan_instance_id = ?
		 GROUP BY type
		 ORDER BY type ASC`,
		guid,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan result summary: %w", err)
	}
	defer rows.Close()

	var summaries []ResultSummary
	for rows.Next() {
		var summary ResultSummary
		if err := rows.Scan(&summary.Type, &summary.Count); err != nil {
			return nil, fmt.Errorf("scan result summary row: %w", err)
		}

		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate result summary rows: %w", err)
	}

	return summaries, nil
}
