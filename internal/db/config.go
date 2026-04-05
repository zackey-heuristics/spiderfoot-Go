package db

import "fmt"

// ConfigSet stores global configuration options.
func (d *DB) ConfigSet(opts map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin global config transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`REPLACE INTO tbl_config (scope, opt, val) VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare global config statement: %w", err)
	}
	defer stmt.Close()

	for key, value := range opts {
		scope, opt := splitConfigKey(key)
		if _, err := stmt.Exec(scope, opt, value); err != nil {
			return fmt.Errorf("store global config %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit global config: %w", err)
	}

	return nil
}

// ConfigGet returns all global configuration options.
func (d *DB) ConfigGet() (map[string]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`SELECT scope, opt, val FROM tbl_config ORDER BY scope ASC, opt ASC`)
	if err != nil {
		return nil, fmt.Errorf("query global config: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var scope, opt, val string
		if err := rows.Scan(&scope, &opt, &val); err != nil {
			return nil, fmt.Errorf("scan global config row: %w", err)
		}

		if scope == "GLOBAL" {
			out[opt] = val
		} else {
			out[scope+":"+opt] = val
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate global config rows: %w", err)
	}

	return out, nil
}

// ScanConfigSet stores configuration options for a specific scan.
func (d *DB) ScanConfigSet(scanID string, opts map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin scan config transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`REPLACE INTO tbl_scan_config (scan_instance_id, component, opt, val) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare scan config statement: %w", err)
	}
	defer stmt.Close()

	for key, value := range opts {
		component, opt := splitConfigKey(key)
		if _, err := stmt.Exec(scanID, component, opt, value); err != nil {
			return fmt.Errorf("store scan config %q: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit scan config: %w", err)
	}

	return nil
}

// ScanConfigGet returns configuration options for a specific scan.
func (d *DB) ScanConfigGet(scanID string) (map[string]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(
		`SELECT component, opt, val
		 FROM tbl_scan_config
		 WHERE scan_instance_id = ?
		 ORDER BY component ASC, opt ASC`,
		scanID,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan config: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var component, opt, val string
		if err := rows.Scan(&component, &opt, &val); err != nil {
			return nil, fmt.Errorf("scan scan config row: %w", err)
		}

		if component == "GLOBAL" {
			out[opt] = val
		} else {
			out[component+":"+opt] = val
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan config rows: %w", err)
	}

	return out, nil
}

func splitConfigKey(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}

	return "GLOBAL", key
}
