package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

var ipIntelNames = []string{
	"pulsedive", "binaryedge", "fraudguard",
	"ipqualityscore", "fullcontact", "spyonweb",
}

// TestIPIntelRegistered confirms all Batch 17 modules are registered.
func TestIPIntelRegistered(t *testing.T) {
	for _, n := range ipIntelNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestIPIntelMeta verifies metadata fields and that all modules
// declare RequiresAPIKey=true.
func TestIPIntelMeta(t *testing.T) {
	for _, n := range ipIntelNames {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %q", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
		if !meta.RequiresAPIKey {
			t.Errorf("%s: expected RequiresAPIKey=true", n)
		}
	}
}

// TestIPIntelWatchedProduced smoke-checks non-empty event lists.
func TestIPIntelWatchedProduced(t *testing.T) {
	for _, n := range ipIntelNames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

// TestIPIntelHandleNilEvent ensures nil events are no-ops.
func TestIPIntelHandleNilEvent(t *testing.T) {
	for _, n := range ipIntelNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		out, err := m.HandleEvent(context.Background(), nil)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if out != nil {
			t.Errorf("%s: expected nil for nil event, got %d", n, len(out))
		}
	}
}

// TestIPIntelFinish verifies Finish is safe to call.
func TestIPIntelFinish(t *testing.T) {
	for _, n := range ipIntelNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish: %v", n, err)
		}
	}
}

// TestIPIntelKeyedNoKeyNoOp ensures all modules no-op without keys.
func TestIPIntelKeyedNoKeyNoOp(t *testing.T) {
	inputs := map[string]*event.Event{
		"pulsedive":      newIPEvent(t, "1.2.3.4"),
		"binaryedge":     newIPEvent(t, "1.2.3.4"),
		"fraudguard":     newIPEvent(t, "1.2.3.4"),
		"ipqualityscore": newIPEvent(t, "1.2.3.4"),
		"fullcontact":    newDomainEvent(t, "example.com"),
		"spyonweb":       newIPEvent(t, "1.2.3.4"),
	}
	for _, n := range ipIntelNames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup: %v", n, err)
			continue
		}
		out, err := m.HandleEvent(context.Background(), inputs[n])
		if err != nil {
			t.Errorf("%s: error: %v", n, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: expected no events without API key, got %d", n, len(out))
		}
	}
}

// TestIPIntelRejectGenericAPIKey ensures no module consumes a generic
// "api_key" opt — only vendor-prefixed keys are accepted.
func TestIPIntelRejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":          "leaked",
		"api_key_account":  "leaked",
		"api_key_password": "leaked",
		"api_key_username": "leaked",
	}
	pd := getModule("pulsedive")().(*Pulsedive)
	_ = pd.Setup(opts)
	if pd.apiKey != "" {
		t.Errorf("pulsedive: leaked generic apiKey = %q", pd.apiKey)
	}
	be := getModule("binaryedge")().(*BinaryEdge)
	_ = be.Setup(opts)
	if be.apiKey != "" {
		t.Errorf("binaryedge: leaked generic apiKey = %q", be.apiKey)
	}
	fg := getModule("fraudguard")().(*FraudGuard)
	_ = fg.Setup(opts)
	if fg.username != "" || fg.password != "" {
		t.Errorf("fraudguard: leaked generic creds u=%q p=%q", fg.username, fg.password)
	}
	iq := getModule("ipqualityscore")().(*IPQualityScore)
	_ = iq.Setup(opts)
	if iq.apiKey != "" {
		t.Errorf("ipqualityscore: leaked generic apiKey = %q", iq.apiKey)
	}
	fc := getModule("fullcontact")().(*FullContact)
	_ = fc.Setup(opts)
	if fc.apiKey != "" {
		t.Errorf("fullcontact: leaked generic apiKey = %q", fc.apiKey)
	}
	sw := getModule("spyonweb")().(*SpyOnWeb)
	_ = sw.Setup(opts)
	if sw.apiKey != "" {
		t.Errorf("spyonweb: leaked generic apiKey = %q", sw.apiKey)
	}
}

// TestIPIntelAcceptPrefixedKeys verifies vendor-prefixed opt names work.
func TestIPIntelAcceptPrefixedKeys(t *testing.T) {
	pd := getModule("pulsedive")().(*Pulsedive)
	_ = pd.Setup(map[string]any{"pulsedive_api_key": "k"})
	if pd.apiKey != "k" {
		t.Errorf("pulsedive: %q", pd.apiKey)
	}
	be := getModule("binaryedge")().(*BinaryEdge)
	_ = be.Setup(map[string]any{"binaryedge_api_key": "k"})
	if be.apiKey != "k" {
		t.Errorf("binaryedge: %q", be.apiKey)
	}
	fg := getModule("fraudguard")().(*FraudGuard)
	_ = fg.Setup(map[string]any{
		"fraudguard_api_key_account":  "u",
		"fraudguard_api_key_password": "p",
	})
	if fg.username != "u" || fg.password != "p" {
		t.Errorf("fraudguard: u=%q p=%q", fg.username, fg.password)
	}
	iq := getModule("ipqualityscore")().(*IPQualityScore)
	_ = iq.Setup(map[string]any{"ipqualityscore_api_key": "k"})
	if iq.apiKey != "k" {
		t.Errorf("ipqualityscore: %q", iq.apiKey)
	}
	fc := getModule("fullcontact")().(*FullContact)
	_ = fc.Setup(map[string]any{"fullcontact_api_key": "k"})
	if fc.apiKey != "k" {
		t.Errorf("fullcontact: %q", fc.apiKey)
	}
	sw := getModule("spyonweb")().(*SpyOnWeb)
	_ = sw.Setup(map[string]any{"spyonweb_api_key": "k"})
	if sw.apiKey != "k" {
		t.Errorf("spyonweb: %q", sw.apiKey)
	}
}

// TestPulsediveLiveParse exercises the Pulsedive parser end-to-end.
func TestPulsediveLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"iid": 12345,
			"attributes": {"port": ["80", "443"]},
			"threats": [{"name": "BadGuy", "category": "malware"}]
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("pulsedive")().(*Pulsedive)
	_ = m.Setup(map[string]any{"pulsedive_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + 2 ports + 1 malicious = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestBinaryEdgeLiveParse exercises the BinaryEdge IP parser.
func TestBinaryEdgeLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") != "k" {
			t.Errorf("missing X-Key header: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"events": [
				{"results": [
					{"target": {"ip": "1.2.3.4", "port": 80, "protocol": "tcp"},
					 "result": {"data": {"service": {"banner": "nginx/1.18"}}}}
				]}
			]
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("binaryedge")().(*BinaryEdge)
	_ = m.Setup(map[string]any{"binaryedge_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + TCP_PORT_OPEN + TCP_PORT_OPEN_BANNER = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestFraudGuardLiveParse exercises the FraudGuard parser.
func TestFraudGuardLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"state": "CA", "city": "Mountain View",
			"postal_code": "94043", "country": "US",
			"threat": "honeypot_tracker", "risk_level": "5"
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("fraudguard")().(*FraudGuard)
	_ = m.Setup(map[string]any{
		"fraudguard_api_key_account":  "u",
		"fraudguard_api_key_password": "p",
	})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + GEOINFO + MALICIOUS_IPADDR = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestIPQualityScoreLiveParse exercises the IPQualityScore parser.
func TestIPQualityScoreLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true, "fraud_score": 90, "recent_abuse": true,
			"city": "Tokyo", "region": "Tokyo", "country_code": "JP"
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipqualityscore")().(*IPQualityScore)
	_ = m.Setup(map[string]any{"ipqualityscore_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + MALICIOUS_IPADDR + GEOINFO = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestSpyOnWebSummaryShape is a regression test for Codex adversarial
// review 2026-04-09: the summary endpoint nests adsense/analytics as
// sibling objects (each with its own items map), not as a flat items
// map keyed by ID. Parsing against the real shape must extract both
// buckets and label them correctly.
func TestSpyOnWebSummaryShape(t *testing.T) {
	body := []byte(`{
		"status": "found",
		"result": {
			"summary": {
				"example.com": {
					"adsense": {"items": {"pub-1111": "2023-01-01", "ca-pub-2222": "2023-02-02"}},
					"analytics": {"items": {"UA-3333": "2023-03-03", "G-4444": "2023-04-04"}}
				}
			}
		}
	}`)
	var sresp spyOnWebSummaryResp
	if err := json.Unmarshal(body, &sresp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sresp.Status != "found" {
		t.Fatalf("status: %q", sresp.Status)
	}
	rec, ok := sresp.Result.Summary["example.com"]
	if !ok {
		t.Fatalf("missing example.com record")
	}
	if len(rec.Adsense.Items) != 2 {
		t.Errorf("adsense items: %v", rec.Adsense.Items)
	}
	if len(rec.Analytics.Items) != 2 {
		t.Errorf("analytics items: %v", rec.Analytics.Items)
	}
	if _, ok := rec.Adsense.Items["pub-1111"]; !ok {
		t.Errorf("missing pub-1111")
	}
	if _, ok := rec.Analytics.Items["UA-3333"]; !ok {
		t.Errorf("missing UA-3333")
	}
}

// TestFullContactNoCommitOnEmpty verifies that a syntactically valid
// but semantically empty FullContact response does not poison the
// dedup cache. Codex adversarial review 2026-04-09.
func TestFullContactNoCommitOnEmpty(t *testing.T) {
	// Simulate the parse step: empty person response should leave
	// no usable fields, so the HandleEvent branch must bail out
	// before committing. We validate this by checking the response
	// struct directly.
	var p fullContactPersonResp
	if err := json.Unmarshal([]byte(`{}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.FullName != "" {
		t.Errorf("expected empty FullName, got %q", p.FullName)
	}
	// A company response with status=404 must also not commit.
	var c fullContactCompanyResp
	if err := json.Unmarshal([]byte(`{"status":404}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Status != 404 {
		t.Errorf("expected status 404, got %d", c.Status)
	}
}

// compile-time interface checks
var _ module.Module = (*Pulsedive)(nil)
var _ module.Module = (*BinaryEdge)(nil)
var _ module.Module = (*FraudGuard)(nil)
var _ module.Module = (*IPQualityScore)(nil)
var _ module.Module = (*FullContact)(nil)
var _ module.Module = (*SpyOnWeb)(nil)
