package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

var majorAPI2Names = []string{
	"riskiq", "intelx", "dehashed", "leakix",
	"threatfox", "urlscan", "xforce",
}

// keyedMajorAPI2Names are the modules that require API credentials.
var keyedMajorAPI2Names = []string{"riskiq", "intelx", "dehashed", "leakix", "xforce"}

// TestMajorAPIs2Registered confirms all Batch 13 modules are registered.
func TestMajorAPIs2Registered(t *testing.T) {
	for _, n := range majorAPI2Names {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestMajorAPIs2Meta checks Meta returns correct name. Modules that
// require an API key set RequiresAPIKey=true; free modules leave it false.
func TestMajorAPIs2Meta(t *testing.T) {
	keyed := map[string]bool{}
	for _, n := range keyedMajorAPI2Names {
		keyed[n] = true
	}
	for _, n := range majorAPI2Names {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %q", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
		if got := meta.RequiresAPIKey; got != keyed[n] {
			t.Errorf("%s: RequiresAPIKey = %v, want %v", n, got, keyed[n])
		}
	}
}

// TestMajorAPIs2WatchedProduced smoke-checks non-empty event lists.
func TestMajorAPIs2WatchedProduced(t *testing.T) {
	for _, n := range majorAPI2Names {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

// TestMajorAPIs2HandleNilEvent ensures nil events are no-ops.
func TestMajorAPIs2HandleNilEvent(t *testing.T) {
	for _, n := range majorAPI2Names {
		m := getModule(n)()
		_ = m.Setup(nil)
		out, err := m.HandleEvent(context.Background(), nil)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if out != nil {
			t.Errorf("%s: expected nil results for nil event, got %d", n, len(out))
		}
	}
}

// TestMajorAPIs2Finish verifies Finish is safe to call.
func TestMajorAPIs2Finish(t *testing.T) {
	for _, n := range majorAPI2Names {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

// TestMajorAPIs2KeyedNoKeyNoOp ensures keyed modules no-op without keys.
func TestMajorAPIs2KeyedNoKeyNoOp(t *testing.T) {
	inputs := map[string]*event.Event{
		"riskiq":   newDomainEvent(t, "example.com"),
		"intelx":   newEmailEvent(t, "user@example.com"),
		"dehashed": newEmailEvent(t, "user@example.com"),
		"leakix":   newIPEvent(t, "1.2.3.4"),
		"xforce":   newIPEvent(t, "1.2.3.4"),
	}
	for _, n := range keyedMajorAPI2Names {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
			continue
		}
		out, err := m.HandleEvent(context.Background(), inputs[n])
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: expected no events without API key, got %d", n, len(out))
		}
	}
}

// TestMajorAPIs2RejectGenericAPIKey is the security regression test:
// none of the keyed modules must consume a generic "api_key" opt.
func TestMajorAPIs2RejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":          "leaked",
		"api_key_login":    "leaked",
		"api_key_password": "leaked",
		"api_key_username": "leaked",
	}

	ri := getModule("riskiq")().(*RiskIQ)
	_ = ri.Setup(opts)
	if ri.login != "" || ri.password != "" {
		t.Errorf("riskiq: leaked generic creds login=%q password=%q", ri.login, ri.password)
	}

	ix := getModule("intelx")().(*IntelX)
	_ = ix.Setup(opts)
	if ix.apiKey != "" {
		t.Errorf("intelx: leaked generic api_key = %q", ix.apiKey)
	}

	dh := getModule("dehashed")().(*Dehashed)
	_ = dh.Setup(opts)
	if dh.username != "" || dh.apiKey != "" {
		t.Errorf("dehashed: leaked generic creds username=%q apiKey=%q", dh.username, dh.apiKey)
	}

	lx := getModule("leakix")().(*LeakIX)
	_ = lx.Setup(opts)
	if lx.apiKey != "" {
		t.Errorf("leakix: leaked generic api_key = %q", lx.apiKey)
	}

	xf := getModule("xforce")().(*XForce)
	_ = xf.Setup(opts)
	if xf.apiKey != "" || xf.password != "" {
		t.Errorf("xforce: leaked generic creds apiKey=%q password=%q", xf.apiKey, xf.password)
	}
}

// TestMajorAPIs2AcceptPrefixedKeys verifies prefixed opt names work.
func TestMajorAPIs2AcceptPrefixedKeys(t *testing.T) {
	ri := getModule("riskiq")().(*RiskIQ)
	_ = ri.Setup(map[string]any{
		"riskiq_api_key_login":    "user",
		"riskiq_api_key_password": "pass",
	})
	if ri.login != "user" || ri.password != "pass" {
		t.Errorf("riskiq: creds not set: login=%q password=%q", ri.login, ri.password)
	}

	ix := getModule("intelx")().(*IntelX)
	_ = ix.Setup(map[string]any{"intelx_api_key": "k"})
	if ix.apiKey != "k" {
		t.Errorf("intelx: apiKey = %q", ix.apiKey)
	}

	dh := getModule("dehashed")().(*Dehashed)
	_ = dh.Setup(map[string]any{
		"dehashed_api_key_username": "u",
		"dehashed_api_key":          "k",
	})
	if dh.username != "u" || dh.apiKey != "k" {
		t.Errorf("dehashed: creds not set: username=%q apiKey=%q", dh.username, dh.apiKey)
	}

	lx := getModule("leakix")().(*LeakIX)
	_ = lx.Setup(map[string]any{"leakix_api_key": "k"})
	if lx.apiKey != "k" {
		t.Errorf("leakix: apiKey = %q", lx.apiKey)
	}

	xf := getModule("xforce")().(*XForce)
	_ = xf.Setup(map[string]any{
		"xforce_api_key":          "k",
		"xforce_api_key_password": "p",
	})
	if xf.apiKey != "k" || xf.password != "p" {
		t.Errorf("xforce: creds not set: apiKey=%q password=%q", xf.apiKey, xf.password)
	}
}

// TestURLScanLiveParse verifies URLScan search parsing.
func TestURLScanLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "domain") {
			t.Errorf("missing domain query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [
				{
					"page": {
						"domain": "example.com",
						"asn": "AS15169",
						"city": "Tokyo",
						"country": "JP",
						"server": "nginx/1.18"
					},
					"task": {"url": "https://example.com/"}
				}
			]
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("urlscan")().(*URLScan)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: RAW_RIR_DATA + GEOINFO + BGP_AS_MEMBER + WEBSERVER_BANNER + LINKED_URL_INTERNAL = 5
	if len(out) != 5 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 5 events, got %d", len(out))
	}
	for _, e := range out {
		if e.Type == event.BGP_AS_MEMBER && e.Data != "15169" {
			t.Errorf("ASN not stripped: %q", e.Data)
		}
	}
}

// TestThreatFoxLiveParse verifies ThreatFox POST parsing.
func TestThreatFoxLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("wrong content-type: %q", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[{"ioc":"1.2.3.4"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("threatfox")().(*ThreatFox)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect BLACKLISTED_IPADDR + MALICIOUS_IPADDR = 2
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestBasicAuthHeader verifies Basic auth encoding.
func TestBasicAuthHeader(t *testing.T) {
	got := basicAuthHeader("user", "pass")
	// base64("user:pass") == "dXNlcjpwYXNz"
	want := "Basic dXNlcjpwYXNz"
	if got != want {
		t.Errorf("basicAuthHeader = %q, want %q", got, want)
	}
}

// compile-time interface checks
var _ module.Module = (*RiskIQ)(nil)
var _ module.Module = (*IntelX)(nil)
var _ module.Module = (*Dehashed)(nil)
var _ module.Module = (*LeakIX)(nil)
var _ module.Module = (*ThreatFox)(nil)
var _ module.Module = (*URLScan)(nil)
var _ module.Module = (*XForce)(nil)
