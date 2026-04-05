package db

import "fmt"

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS tbl_event_types (
		event VARCHAR NOT NULL PRIMARY KEY,
		event_descr VARCHAR NOT NULL,
		event_raw INT NOT NULL DEFAULT 0,
		event_type VARCHAR NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_config (
		scope VARCHAR NOT NULL,
		opt VARCHAR NOT NULL,
		val VARCHAR NOT NULL,
		PRIMARY KEY (scope, opt)
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_instance (
		guid VARCHAR NOT NULL PRIMARY KEY,
		name VARCHAR NOT NULL,
		seed_target VARCHAR NOT NULL,
		created INT DEFAULT 0,
		started INT DEFAULT 0,
		ended INT DEFAULT 0,
		status VARCHAR NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_log (
		scan_instance_id VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid),
		generated INT NOT NULL,
		component VARCHAR,
		type VARCHAR NOT NULL,
		message VARCHAR
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_config (
		scan_instance_id VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid),
		component VARCHAR NOT NULL,
		opt VARCHAR NOT NULL,
		val VARCHAR NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_results (
		scan_instance_id VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid),
		hash VARCHAR NOT NULL,
		type VARCHAR NOT NULL REFERENCES tbl_event_types(event),
		generated INT NOT NULL,
		confidence INT NOT NULL DEFAULT 100,
		visibility INT NOT NULL DEFAULT 100,
		risk INT NOT NULL DEFAULT 0,
		module VARCHAR NOT NULL,
		data VARCHAR,
		false_positive INT NOT NULL DEFAULT 0,
		source_event_hash VARCHAR DEFAULT 'ROOT'
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_correlation_results (
		id VARCHAR NOT NULL PRIMARY KEY,
		scan_instance_id VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid),
		title VARCHAR NOT NULL,
		rule_risk VARCHAR NOT NULL,
		rule_id VARCHAR NOT NULL,
		rule_name VARCHAR NOT NULL,
		rule_descr VARCHAR NOT NULL,
		rule_logic VARCHAR NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS tbl_scan_correlation_results_events (
		correlation_id VARCHAR NOT NULL REFERENCES tbl_scan_correlation_results(id),
		event_hash VARCHAR NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_results_id ON tbl_scan_results (scan_instance_id)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_results_module ON tbl_scan_results (scan_instance_id, module)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)`,
	`CREATE INDEX IF NOT EXISTS idx_scan_log_id ON tbl_scan_log (scan_instance_id)`,
}

func (d *DB) createSchema() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, stmt := range schemaStatements {
		if _, err := d.db.Exec(stmt); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}

	return nil
}
