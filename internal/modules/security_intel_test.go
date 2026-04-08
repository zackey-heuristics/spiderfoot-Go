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

var securityIntelNames = []string{
	"googlesafebrowsing", "metadefender", "hybridanalysis", "openbugbounty",
}

var keyedSecurityIntelNames = []string{
	"googlesafebrowsing", "metadefender", "hybridanalysis",
}

// TestSecurityIntelRegistered confirms all Batch 14 modules are registered.
func TestSecurityIntelRegistered(t *testing.T) {
	for _, n := range securityIntelNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestSecurityIntelMeta checks Meta name, summary, and RequiresAPIKey.
func TestSecurityIntelMeta(t *testing.T) {
	keyed := map[string]bool{}
	for _, n := range keyedSecurityIntelNames {
		keyed[n] = true
	}
	for _, n := range securityIntelNames {
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

// TestSecurityIntelWatchedProduced smoke-checks non-empty event lists.
func TestSecurityIntelWatchedProduced(t *testing.T) {
	for _, n := range securityIntelNames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

// TestSecurityIntelHandleNilEvent ensures nil events are no-ops.
func TestSecurityIntelHandleNilEvent(t *testing.T) {
	for _, n := range securityIntelNames {
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

// TestSecurityIntelFinish verifies Finish is safe to call.
func TestSecurityIntelFinish(t *testing.T) {
	for _, n := range securityIntelNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

// TestSecurityIntelKeyedNoKeyNoOp ensures keyed modules no-op without keys.
func TestSecurityIntelKeyedNoKeyNoOp(t *testing.T) {
	inputs := map[string]*event.Event{
		"googlesafebrowsing": newIPEvent(t, "1.2.3.4"),
		"metadefender":       newIPEvent(t, "1.2.3.4"),
		"hybridanalysis":     newIPEvent(t, "1.2.3.4"),
	}
	for _, n := range keyedSecurityIntelNames {
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

// TestSecurityIntelRejectGenericAPIKey is the security regression test:
// none of the keyed modules must consume a generic "api_key" opt.
func TestSecurityIntelRejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{"api_key": "leaked"}

	g := getModule("googlesafebrowsing")().(*GoogleSafeBrowsing)
	_ = g.Setup(opts)
	if g.apiKey != "" {
		t.Errorf("googlesafebrowsing: leaked generic api_key = %q", g.apiKey)
	}

	md := getModule("metadefender")().(*MetaDefender)
	_ = md.Setup(opts)
	if md.apiKey != "" {
		t.Errorf("metadefender: leaked generic api_key = %q", md.apiKey)
	}

	ha := getModule("hybridanalysis")().(*HybridAnalysis)
	_ = ha.Setup(opts)
	if ha.apiKey != "" {
		t.Errorf("hybridanalysis: leaked generic api_key = %q", ha.apiKey)
	}
}

// TestSecurityIntelAcceptPrefixedKeys verifies prefixed opt names work.
func TestSecurityIntelAcceptPrefixedKeys(t *testing.T) {
	g := getModule("googlesafebrowsing")().(*GoogleSafeBrowsing)
	_ = g.Setup(map[string]any{"googlesafebrowsing_api_key": "k"})
	if g.apiKey != "k" {
		t.Errorf("googlesafebrowsing: apiKey = %q", g.apiKey)
	}

	md := getModule("metadefender")().(*MetaDefender)
	_ = md.Setup(map[string]any{"metadefender_api_key": "k"})
	if md.apiKey != "k" {
		t.Errorf("metadefender: apiKey = %q", md.apiKey)
	}

	ha := getModule("hybridanalysis")().(*HybridAnalysis)
	_ = ha.Setup(map[string]any{"hybridanalysis_api_key": "k"})
	if ha.apiKey != "k" {
		t.Errorf("hybridanalysis: apiKey = %q", ha.apiKey)
	}
}

// TestGoogleSafeBrowsingLiveParse verifies SafeBrowsing POST parsing.
func TestGoogleSafeBrowsingLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.RawQuery, "key=testkey") {
			t.Errorf("missing key= query param: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":[{"threatType":"MALWARE"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("googlesafebrowsing")().(*GoogleSafeBrowsing)
	_ = m.Setup(map[string]any{"googlesafebrowsing_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect RAW_RIR_DATA + MALICIOUS_IPADDR = 2
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestGoogleSafeBrowsingNoMatch returns empty matches and expects no events.
func TestGoogleSafeBrowsingNoMatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("googlesafebrowsing")().(*GoogleSafeBrowsing)
	_ = m.Setup(map[string]any{"googlesafebrowsing_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 events, got %d", len(out))
	}
}

// TestMetaDefenderLiveParse verifies MetaDefender IP reputation parsing.
func TestMetaDefenderLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apikey") != "testkey" {
			t.Errorf("missing apikey header: %q", r.Header.Get("apikey"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"geo_info": {"city":{"name":"Tokyo"},"country":{"name":"Japan"}},
			"lookup_results": {"sources":[
				{"assessment":"malicious","provider":"VendorA"},
				{"assessment":"trustworthy","provider":"VendorB"}
			]}
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("metadefender")().(*MetaDefender)
	_ = m.Setup(map[string]any{"metadefender_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: GEOINFO + MALICIOUS_IPADDR + BLACKLISTED_IPADDR = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
	var gotGeo bool
	for _, e := range out {
		if e.Type == event.GEOINFO && e.Data == "Tokyo, Japan" {
			gotGeo = true
		}
	}
	if !gotGeo {
		t.Errorf("GEOINFO not emitted as 'Tokyo, Japan'")
	}
}

// TestHybridAnalysisLiveParse verifies two-phase (terms then hash) flow.
func TestHybridAnalysisLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("api-key") != "testkey" {
			t.Errorf("missing api-key: %q", r.Header.Get("api-key"))
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("wrong content-type: %q", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/search/terms"):
			_, _ = w.Write([]byte(`{"result":[{"sha256":"deadbeef"}]}`))
		case strings.HasSuffix(r.URL.Path, "/search/hash"):
			_, _ = w.Write([]byte(`[{"domains":["bad.example.com"],"submissions":[{"url":"https://bad.example.com/x"}]}]`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("hybridanalysis")().(*HybridAnalysis)
	_ = m.Setup(map[string]any{"hybridanalysis_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: RAW_RIR_DATA (terms) + RAW_RIR_DATA (hash) + INTERNET_NAME + LINKED_URL_INTERNAL = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestOpenBugBountyLiveParse verifies HTML scraping.
func TestOpenBugBountyLiveParse(t *testing.T) {
	html := `<html><body>
<div class="cell1"><a href="/reports/1234/">sub.example.com</a></div>
<div class="cell1"><a href="/reports/5678/">example.com</a></div>
<div class="cell1"><a href="/reports/9999/">other.org</a></div>
</body></html>`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("openbugbounty")().(*OpenBugBounty)
	_ = m.Setup(nil)
	// Use an INTERNET_NAME event. Reuse newDomainEvent builder and
	// change the type via a fresh event construction below.
	root, err := event.New(event.ROOT, "example.com", "test", nil)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	evt, err := event.New(event.INTERNET_NAME, "example.com", "test", root)
	if err != nil {
		t.Fatalf("evt: %v", err)
	}
	out, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: 2 matches (example.com and sub.example.com), other.org filtered
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	for _, e := range out {
		if e.Type != event.VULNERABILITY_DISCLOSURE {
			t.Errorf("unexpected type: %s", e.Type)
		}
	}
}

// compile-time interface checks
var _ module.Module = (*GoogleSafeBrowsing)(nil)
var _ module.Module = (*MetaDefender)(nil)
var _ module.Module = (*HybridAnalysis)(nil)
var _ module.Module = (*OpenBugBounty)(nil)
