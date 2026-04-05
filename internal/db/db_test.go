package db

import (
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()

	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) error = %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})

	return db
}

func createScan(t *testing.T, db *DB, guid string) {
	t.Helper()

	if err := db.ScanCreate(guid, "scan "+guid, "example.com"); err != nil {
		t.Fatalf("ScanCreate(%q) error = %v", guid, err)
	}
}

func createRootEvent(t *testing.T) *event.Event {
	t.Helper()

	root, err := event.New(event.ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("event.New(ROOT) error = %v", err)
	}

	root.Generated = time.Unix(1700000000, 0).UTC()
	return root
}

func createChildEvent(t *testing.T, typ event.Type, data, module string, source *event.Event) *event.Event {
	t.Helper()

	evt, err := event.New(typ, data, module, source)
	if err != nil {
		t.Fatalf("event.New(%q) error = %v", typ, err)
	}

	evt.Generated = source.Generated.Add(time.Second)
	return evt
}

func TestOpen_CreatesSchema(t *testing.T) {
	db := openTestDB(t)

	var count int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tbl_scan_instance'`).Scan(&count); err != nil {
		t.Fatalf("schema table lookup error = %v", err)
	}
	if count != 1 {
		t.Fatalf("tbl_scan_instance count = %d, want 1", count)
	}

	if err := db.db.QueryRow(`SELECT COUNT(*) FROM tbl_event_types`).Scan(&count); err != nil {
		t.Fatalf("event type count error = %v", err)
	}
	if count == 0 {
		t.Fatal("tbl_event_types was not seeded")
	}
}

func TestScanCreate_And_Get(t *testing.T) {
	db := openTestDB(t)

	if err := db.ScanCreate("scan-1", "scan name", "example.com"); err != nil {
		t.Fatalf("ScanCreate() error = %v", err)
	}

	scan, err := db.ScanGet("scan-1")
	if err != nil {
		t.Fatalf("ScanGet() error = %v", err)
	}
	if scan == nil {
		t.Fatal("ScanGet() returned nil scan")
	}
	if scan.GUID != "scan-1" || scan.Name != "scan name" || scan.SeedTarget != "example.com" {
		t.Fatalf("unexpected scan = %+v", *scan)
	}
	if scan.Status != "CREATED" {
		t.Fatalf("scan.Status = %q, want CREATED", scan.Status)
	}
	if scan.Created <= 0 {
		t.Fatalf("scan.Created = %d, want > 0", scan.Created)
	}
}

func TestScanUpdateStatus(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	if err := db.ScanUpdateStatus("scan-1", "RUNNING"); err != nil {
		t.Fatalf("ScanUpdateStatus() error = %v", err)
	}

	scan, err := db.ScanGet("scan-1")
	if err != nil {
		t.Fatalf("ScanGet() error = %v", err)
	}
	if scan.Status != "RUNNING" {
		t.Fatalf("scan.Status = %q, want RUNNING", scan.Status)
	}

	if err := db.ScanUpdateTimes("scan-1", 1234, 5678); err != nil {
		t.Fatalf("ScanUpdateTimes() error = %v", err)
	}

	scan, err = db.ScanGet("scan-1")
	if err != nil {
		t.Fatalf("ScanGet() after ScanUpdateTimes error = %v", err)
	}
	if scan.Started != 1234 || scan.Ended != 5678 {
		t.Fatalf("scan times = (%d, %d), want (1234, 5678)", scan.Started, scan.Ended)
	}
}

func TestScanList(t *testing.T) {
	db := openTestDB(t)

	createScan(t, db, "scan-1")
	createScan(t, db, "scan-2")
	if _, err := db.db.Exec(`UPDATE tbl_scan_instance SET created = ? WHERE guid = ?`, 1000, "scan-1"); err != nil {
		t.Fatalf("set created for scan-1 error = %v", err)
	}
	if _, err := db.db.Exec(`UPDATE tbl_scan_instance SET created = ? WHERE guid = ?`, 2000, "scan-2"); err != nil {
		t.Fatalf("set created for scan-2 error = %v", err)
	}

	scans, err := db.ScanList()
	if err != nil {
		t.Fatalf("ScanList() error = %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("len(ScanList()) = %d, want 2", len(scans))
	}
	if scans[0].GUID != "scan-2" || scans[1].GUID != "scan-1" {
		t.Fatalf("scan order = [%s %s], want [scan-2 scan-1]", scans[0].GUID, scans[1].GUID)
	}
}

func TestScanDelete_Cascades(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	root := createRootEvent(t)
	child := createChildEvent(t, event.DOMAIN_NAME, "example.com", "mod_dns", root)

	if err := db.EventStore("scan-1", root); err != nil {
		t.Fatalf("EventStore(root) error = %v", err)
	}
	if err := db.EventStore("scan-1", child); err != nil {
		t.Fatalf("EventStore(child) error = %v", err)
	}
	if err := db.ScanConfigSet("scan-1", map[string]string{"GLOBAL_OPT": "1"}); err != nil {
		t.Fatalf("ScanConfigSet() error = %v", err)
	}
	if err := db.ScanLogEvent("scan-1", "mod_dns", "INFO", "logged"); err != nil {
		t.Fatalf("ScanLogEvent() error = %v", err)
	}

	if _, err := db.db.Exec(
		`INSERT INTO tbl_scan_correlation_results (id, scan_instance_id, title, rule_risk, rule_id, rule_name, rule_descr, rule_logic)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"corr-1", "scan-1", "corr title", "HIGH", "rule-1", "Rule", "Descr", "Logic",
	); err != nil {
		t.Fatalf("insert correlation result error = %v", err)
	}
	if _, err := db.db.Exec(
		`INSERT INTO tbl_scan_correlation_results_events (correlation_id, event_hash) VALUES (?, ?)`,
		"corr-1", child.Hash(),
	); err != nil {
		t.Fatalf("insert correlation event error = %v", err)
	}

	if err := db.ScanDelete("scan-1"); err != nil {
		t.Fatalf("ScanDelete() error = %v", err)
	}

	checks := map[string]string{
		"tbl_scan_instance":                   `SELECT COUNT(*) FROM tbl_scan_instance WHERE guid = 'scan-1'`,
		"tbl_scan_results":                    `SELECT COUNT(*) FROM tbl_scan_results WHERE scan_instance_id = 'scan-1'`,
		"tbl_scan_log":                        `SELECT COUNT(*) FROM tbl_scan_log WHERE scan_instance_id = 'scan-1'`,
		"tbl_scan_config":                     `SELECT COUNT(*) FROM tbl_scan_config WHERE scan_instance_id = 'scan-1'`,
		"tbl_scan_correlation_results":        `SELECT COUNT(*) FROM tbl_scan_correlation_results WHERE scan_instance_id = 'scan-1'`,
		"tbl_scan_correlation_results_events": `SELECT COUNT(*) FROM tbl_scan_correlation_results_events WHERE correlation_id = 'corr-1'`,
	}

	for name, query := range checks {
		var count int
		if err := db.db.QueryRow(query).Scan(&count); err != nil {
			t.Fatalf("%s count error = %v", name, err)
		}
		if count != 0 {
			t.Fatalf("%s remaining rows = %d, want 0", name, count)
		}
	}
}

func TestEventStore_And_Get(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	root := createRootEvent(t)
	child := createChildEvent(t, event.DOMAIN_NAME, "sub.example.com", "mod_dns", root)

	if err := db.EventStore("scan-1", root); err != nil {
		t.Fatalf("EventStore(root) error = %v", err)
	}
	if err := db.EventStore("scan-1", child); err != nil {
		t.Fatalf("EventStore(child) error = %v", err)
	}

	events, err := db.EventsGet("scan-1", "")
	if err != nil {
		t.Fatalf("EventsGet(all) error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(EventsGet(all)) = %d, want 2", len(events))
	}

	if events[0].Type != string(event.ROOT) || events[0].SourceEventHash != string(event.ROOT) {
		t.Fatalf("root stored event = %+v", events[0])
	}
	if events[1].Type != string(event.DOMAIN_NAME) {
		t.Fatalf("child type = %q, want %q", events[1].Type, event.DOMAIN_NAME)
	}
	if events[1].SourceEventHash != root.Hash() {
		t.Fatalf("child.SourceEventHash = %q, want %q", events[1].SourceEventHash, root.Hash())
	}

	filtered, err := db.EventsGet("scan-1", string(event.DOMAIN_NAME))
	if err != nil {
		t.Fatalf("EventsGet(filtered) error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].Data != "sub.example.com" {
		t.Fatalf("filtered events = %+v, want one DOMAIN_NAME event", filtered)
	}
}

func TestEventStore_EventsGetUnique(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	root := createRootEvent(t)
	child1 := createChildEvent(t, event.DOMAIN_NAME, "a.example.com", "mod_dns", root)
	child2 := createChildEvent(t, event.DOMAIN_NAME, "a.example.com", "mod_dns", root)
	child2.Generated = child1.Generated.Add(time.Second)
	child3 := createChildEvent(t, event.EMAILADDR, "user@example.com", "mod_email", root)
	child3.Generated = child2.Generated.Add(time.Second)

	for _, evt := range []*event.Event{root, child1, child2, child3} {
		if err := db.EventStore("scan-1", evt); err != nil {
			t.Fatalf("EventStore(%q) error = %v", evt.Type, err)
		}
	}

	values, err := db.EventsGetUnique("scan-1", string(event.DOMAIN_NAME))
	if err != nil {
		t.Fatalf("EventsGetUnique() error = %v", err)
	}
	if len(values) != 1 || values[0] != "a.example.com" {
		t.Fatalf("unique values = %#v, want [\"a.example.com\"]", values)
	}
}

func TestScanResultSummary(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	root := createRootEvent(t)
	domain1 := createChildEvent(t, event.DOMAIN_NAME, "a.example.com", "mod_dns", root)
	domain2 := createChildEvent(t, event.DOMAIN_NAME, "b.example.com", "mod_dns", root)
	domain2.Generated = domain1.Generated.Add(time.Second)
	email := createChildEvent(t, event.EMAILADDR, "user@example.com", "mod_email", root)
	email.Generated = domain2.Generated.Add(time.Second)

	for _, evt := range []*event.Event{root, domain1, domain2, email} {
		if err := db.EventStore("scan-1", evt); err != nil {
			t.Fatalf("EventStore(%q) error = %v", evt.Type, err)
		}
	}

	summary, err := db.ScanResultSummary("scan-1")
	if err != nil {
		t.Fatalf("ScanResultSummary() error = %v", err)
	}
	if len(summary) != 3 {
		t.Fatalf("len(summary) = %d, want 3", len(summary))
	}

	got := map[string]int{}
	for _, item := range summary {
		got[item.Type] = item.Count
	}
	if got[string(event.ROOT)] != 1 || got[string(event.DOMAIN_NAME)] != 2 || got[string(event.EMAILADDR)] != 1 {
		t.Fatalf("summary counts = %#v, want ROOT=1 DOMAIN_NAME=2 EMAILADDR=1", got)
	}
}

func TestConfigSet_And_Get(t *testing.T) {
	db := openTestDB(t)

	err := db.ConfigSet(map[string]string{
		"user_agent":        "SpiderFoot-Go",
		"mod_dns:timeout":   "5",
		"mod_email:enabled": "true",
	})
	if err != nil {
		t.Fatalf("ConfigSet() error = %v", err)
	}

	got, err := db.ConfigGet()
	if err != nil {
		t.Fatalf("ConfigGet() error = %v", err)
	}
	if got["user_agent"] != "SpiderFoot-Go" || got["mod_dns:timeout"] != "5" || got["mod_email:enabled"] != "true" {
		t.Fatalf("ConfigGet() = %#v", got)
	}
}

func TestScanConfigSet_And_Get(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	err := db.ScanConfigSet("scan-1", map[string]string{
		"user_agent":      "SpiderFoot-Go",
		"mod_dns:timeout": "5",
	})
	if err != nil {
		t.Fatalf("ScanConfigSet() error = %v", err)
	}

	got, err := db.ScanConfigGet("scan-1")
	if err != nil {
		t.Fatalf("ScanConfigGet() error = %v", err)
	}
	if got["user_agent"] != "SpiderFoot-Go" || got["mod_dns:timeout"] != "5" {
		t.Fatalf("ScanConfigGet() = %#v", got)
	}
}

func TestScanLogEvent_And_Get(t *testing.T) {
	db := openTestDB(t)
	createScan(t, db, "scan-1")

	if err := db.ScanLogEvent("scan-1", "", "INFO", "first"); err != nil {
		t.Fatalf("ScanLogEvent(first) error = %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := db.ScanLogEvent("scan-1", "mod_dns", "ERROR", "second"); err != nil {
		t.Fatalf("ScanLogEvent(second) error = %v", err)
	}

	logs, err := db.ScanLogGet("scan-1", 0)
	if err != nil {
		t.Fatalf("ScanLogGet(all) error = %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("len(ScanLogGet(all)) = %d, want 2", len(logs))
	}
	if logs[0].Message != "second" || logs[0].Component != "mod_dns" {
		t.Fatalf("latest log = %+v, want second/mod_dns", logs[0])
	}
	if logs[1].Component != "SpiderFoot" {
		t.Fatalf("default component = %q, want SpiderFoot", logs[1].Component)
	}

	limited, err := db.ScanLogGet("scan-1", 1)
	if err != nil {
		t.Fatalf("ScanLogGet(limit) error = %v", err)
	}
	if len(limited) != 1 || limited[0].Message != "second" {
		t.Fatalf("limited logs = %+v, want only second", limited)
	}
}
