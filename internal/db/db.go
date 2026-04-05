// Package db provides SQLite-backed persistence for SpiderFoot-Go.
package db

import (
	"database/sql"
	"fmt"
	"errors"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrScanNotFound is returned when a scan operation targets a non-existent scan.
var ErrScanNotFound = errors.New("scan not found")

// DB wraps the underlying SQLite handle and serializes access with a read-write mutex.
type DB struct {
	db *sql.DB
	mu sync.RWMutex
}

// Open opens a SpiderFoot database, initializes the schema, and seeds event types.
func Open(dbPath string) (*DB, error) {
	dsn := dbPath
	if dsn == "" || dsn == ":memory:" {
		dsn = ":memory:"
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db := &DB{db: sqlDB}

	if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if _, err := sqlDB.Exec("PRAGMA journal_mode = WAL"); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("enable wal mode: %w", err)
	}

	if err := db.createSchema(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	if err := db.seedEventTypes(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	return db, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.db.Close()
}
