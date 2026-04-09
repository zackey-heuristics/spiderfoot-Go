package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

var batch20Names = []string{
	"ahmia", "onionsearchengine", "bitcoinabuse",
	"opencorporates", "onyphe", "zetalytics",
}

// TestBatch20Registered verifies all Batch 20 modules are registered.
func TestBatch20Registered(t *testing.T) {
	for _, n := range batch20Names {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestBatch20Meta sanity-checks module metadata and key flags.
func TestBatch20Meta(t *testing.T) {
	keyed := map[string]bool{
		"ahmia":             false,
		"onionsearchengine": false,
		"bitcoinabuse":      true,
		"opencorporates":    true,
		"onyphe":            true,
		"zetalytics":        true,
	}
	for _, n := range batch20Names {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %q", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
		if meta.RequiresAPIKey != keyed[n] {
			t.Errorf("%s: RequiresAPIKey=%v, want %v", n, meta.RequiresAPIKey, keyed[n])
		}
		if len(m.WatchedEvents()) == 0 || len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: empty watched/produced", n)
		}
	}
}

// TestBatch20SetupNilOpts verifies Setup handles nil opts.
func TestBatch20SetupNilOpts(t *testing.T) {
	for _, n := range batch20Names {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup nil: %v", n, err)
		}
	}
}

// TestBatch20WatchedEvents asserts each module subscribes to its claimed inputs.
func TestBatch20WatchedEvents(t *testing.T) {
	expects := map[string][]event.Type{
		"ahmia":             {event.DOMAIN_NAME, event.HUMAN_NAME, event.EMAILADDR},
		"onionsearchengine": {event.DOMAIN_NAME, event.HUMAN_NAME, event.EMAILADDR},
		"bitcoinabuse":      {event.BITCOIN_ADDRESS},
		"opencorporates":    {event.COMPANY_NAME},
		"onyphe":            {event.IP_ADDRESS, event.IPV6_ADDRESS},
		"zetalytics":        {event.INTERNET_NAME, event.DOMAIN_NAME, event.EMAILADDR},
	}
	for name, want := range expects {
		m := getModule(name)()
		got := m.WatchedEvents()
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
			continue
		}
		set := map[event.Type]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, w := range want {
			if !set[w] {
				t.Errorf("%s: missing watched event %s", name, w)
			}
		}
	}
}

// TestBatch20RejectGenericAPIKey verifies no Batch 20 module reads a
// generic api_key opt.
func TestBatch20RejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":    "leaked",
		"api_token":  "leaked",
		"token":      "leaked",
		"access_key": "leaked",
	}
	ba := getModule("bitcoinabuse")().(*BitcoinAbuse)
	_ = ba.Setup(opts)
	if ba.apiKey != "" {
		t.Errorf("bitcoinabuse leaked: %q", ba.apiKey)
	}
	oc := getModule("opencorporates")().(*OpenCorporates)
	_ = oc.Setup(opts)
	if oc.apiKey != "" {
		t.Errorf("opencorporates leaked: %q", oc.apiKey)
	}
	on := getModule("onyphe")().(*Onyphe)
	_ = on.Setup(opts)
	if on.apiKey != "" {
		t.Errorf("onyphe leaked: %q", on.apiKey)
	}
	zt := getModule("zetalytics")().(*Zetalytics)
	_ = zt.Setup(opts)
	if zt.apiKey != "" {
		t.Errorf("zetalytics leaked: %q", zt.apiKey)
	}
}

// TestBatch20AcceptPrefixedKeys verifies vendor-prefixed keys load.
func TestBatch20AcceptPrefixedKeys(t *testing.T) {
	ba := getModule("bitcoinabuse")().(*BitcoinAbuse)
	_ = ba.Setup(map[string]any{"bitcoinabuse_api_key": "k"})
	if ba.apiKey != "k" {
		t.Errorf("bitcoinabuse: %q", ba.apiKey)
	}
	oc := getModule("opencorporates")().(*OpenCorporates)
	_ = oc.Setup(map[string]any{"opencorporates_api_key": "k"})
	if oc.apiKey != "k" {
		t.Errorf("opencorporates: %q", oc.apiKey)
	}
	on := getModule("onyphe")().(*Onyphe)
	_ = on.Setup(map[string]any{"onyphe_api_key": "k"})
	if on.apiKey != "k" {
		t.Errorf("onyphe: %q", on.apiKey)
	}
	zt := getModule("zetalytics")().(*Zetalytics)
	_ = zt.Setup(map[string]any{"zetalytics_api_key": "k"})
	if zt.apiKey != "k" {
		t.Errorf("zetalytics: %q", zt.apiKey)
	}
}

// TestBatch20KeyedNoKeyNoOp ensures keyed modules no-op without creds.
func TestBatch20KeyedNoKeyNoOp(t *testing.T) {
	cases := map[string]*event.Event{
		"bitcoinabuse":   newBitcoinEvent(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
		"opencorporates": newCompanyEvent(t, "Acme Inc"),
		"onyphe":         newIPEvent(t, "1.2.3.4"),
		"zetalytics":     newDomainEvent(t, "example.com"),
	}
	for n, evt := range cases {
		m := getModule(n)()
		_ = m.Setup(nil)
		out, err := m.HandleEvent(context.Background(), evt)
		if err != nil {
			t.Errorf("%s: %v", n, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: emitted %d events without key", n, len(out))
		}
	}
}

// newBitcoinEvent constructs a BITCOIN_ADDRESS event for tests.
func newBitcoinEvent(t *testing.T, addr string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "target", "test", nil)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	e, err := event.New(event.BITCOIN_ADDRESS, addr, "test", root)
	if err != nil {
		t.Fatalf("btc: %v", err)
	}
	return e
}

// newCompanyEvent constructs a COMPANY_NAME event for tests.
func newCompanyEvent(t *testing.T, name string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "target", "test", nil)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	e, err := event.New(event.COMPANY_NAME, name, "test", root)
	if err != nil {
		t.Fatalf("co: %v", err)
	}
	return e
}

// TestAhmiaParse verifies ahmia HTML scrape extracts onion URLs.
func TestAhmiaParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
<a href="/search/redirect_url=http://exampleabcd1234.onion/path">link1</a>
<a href="/search/redirect_url=http://other5678.onion/foo">link2</a>
<a href="/search/redirect_url=http://clearnet.example.com/x">notonion</a>
</html>`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("ahmia")().(*Ahmia)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestAhmiaEmptyNoCommit verifies ahmia does not commit when no
// onion links are found.
func TestAhmiaEmptyNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>no results</html>`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("ahmia")().(*Ahmia)
	_ = m.Setup(nil)
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// TestOnionSearchEngineParse exercises the page extraction.
func TestOnionSearchEngineParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<a href="url.php?u=http://abc1234.onion/x">A</a>
<a href="url.php?u=http://def5678.onion/y">B</a>`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("onionsearchengine")().(*OnionSearchEngine)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestOnionSearchEnginePercentDecoded is a regression test for
// Codex adversarial review 2026-04-09: the u= parameter is a
// query-parameter payload that may be percent-encoded; it must be
// decoded before emission so downstream consumers see canonical
// onion URLs, not wrapped values.
func TestOnionSearchEnginePercentDecoded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			`<a href="url.php?u=http%3A%2F%2Fabc1234.onion%2Fpath%3Fq%3D1">E</a>` +
				`<a href="url.php?u=http://not-onion.example/x">bad</a>`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("onionsearchengine")().(*OnionSearchEngine)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 1 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 1 event, got %d", len(out))
	}
	if out[0].Data != "http://abc1234.onion/path?q=1" {
		t.Errorf("expected decoded canonical URL, got %q", out[0].Data)
	}
}

// TestBitcoinAbuseLiveParse verifies the success path.
func TestBitcoinAbuseLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "api_token=k") {
			t.Errorf("missing api_token: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","count":3}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("bitcoinabuse")().(*BitcoinAbuse)
	_ = m.Setup(map[string]any{"bitcoinabuse_api_key": "k"})
	out, err := m.HandleEvent(context.Background(),
		newBitcoinEvent(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// MALICIOUS_BITCOIN_ADDRESS + RAW_RIR_DATA
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	if out[0].Type != event.MALICIOUS_BITCOIN_ADDRESS {
		t.Errorf("first event type=%s", out[0].Type)
	}
}

// TestBitcoinAbuseZeroCountNoCommit verifies count==0 does not commit.
func TestBitcoinAbuseZeroCountNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"address":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","count":0}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("bitcoinabuse")().(*BitcoinAbuse)
	_ = m.Setup(map[string]any{"bitcoinabuse_api_key": "k"})
	out, _ := m.HandleEvent(context.Background(),
		newBitcoinEvent(t, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// TestBitcoinAbuseShape is a regression test on the JSON field names.
func TestBitcoinAbuseShape(t *testing.T) {
	var r bitcoinAbuseResp
	if err := json.Unmarshal([]byte(`{"address":"x","count":7}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Address != "x" || r.Count != 7 {
		t.Errorf("parsed: %+v", r)
	}
}

// TestOpenCorporatesLiveParse exercises the search path.
func TestOpenCorporatesLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":{"companies":[{"company":{
"name":"Acme Inc",
"jurisdiction_code":"us_ca",
"company_number":"C123",
"registered_address_in_full":"1 Main St\nSan Francisco",
"registered_address":{"country":"USA"},
"previous_names":[{"company_name":"Old Acme"}],
"officers":[{"name":"Jane Doe"}]
}}]}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("opencorporates")().(*OpenCorporates)
	_ = m.Setup(map[string]any{"opencorporates_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newCompanyEvent(t, "Acme Inc"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// PHYSICAL_ADDRESS + previous COMPANY_NAME + RAW_RIR_DATA officer = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestOpenCorporatesNameMismatchNoCommit verifies a mismatch is dropped.
func TestOpenCorporatesNameMismatchNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":{"companies":[{"company":{"name":"Other Corp"}}]}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("opencorporates")().(*OpenCorporates)
	_ = m.Setup(map[string]any{"opencorporates_api_key": "k"})
	out, _ := m.HandleEvent(context.Background(), newCompanyEvent(t, "Acme Inc"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestOnypheLiveParse exercises the geoloc + threatlist + vulnscan path.
func TestOnypheLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "apikey k" {
			t.Errorf("missing Authorization: %v", r.Header)
		}
		switch {
		case strings.Contains(r.URL.Path, "/geoloc/"):
			_, _ = w.Write([]byte(`{"status":"ok","results":[{"city":"Tokyo","country":"Japan","location":"35.6,139.7"}]}`))
		case strings.Contains(r.URL.Path, "/threatlist/"):
			_, _ = w.Write([]byte(`{"status":"ok","results":[{"threatlist":"badlist1"}]}`))
		case strings.Contains(r.URL.Path, "/vulnscan/"):
			_, _ = w.Write([]byte(`{"status":"ok","results":[{"cve":["CVE-2024-0001","CVE-2024-0002"]}]}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok","results":[]}`))
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("onyphe")().(*Onyphe)
	_ = m.Setup(map[string]any{"onyphe_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: 3 RAW_RIR_DATA + GEOINFO + PHYSICAL_COORDINATES + MALICIOUS_IPADDR
	//   + 2 VULNERABILITY_GENERAL = 8
	if len(out) != 8 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 8 events, got %d", len(out))
	}
	// Regression for Codex adversarial review 2026-04-09:
	// MALICIOUS_IPADDR must carry the queried IP artifact, not
	// the threatlist label.
	var malFound bool
	for _, e := range out {
		if e.Type == event.MALICIOUS_IPADDR {
			malFound = true
			if e.Data != "1.2.3.4" {
				t.Errorf("MALICIOUS_IPADDR should carry IP, got %q", e.Data)
			}
		}
	}
	if !malFound {
		t.Errorf("no MALICIOUS_IPADDR emitted")
	}
}

// TestOnypheNokNoCommit verifies an upstream error status produces no events.
func TestOnypheNokNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"nok","text":"bad key"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("onyphe")().(*Onyphe)
	_ = m.Setup(map[string]any{"onyphe_api_key": "k"})
	out, _ := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestZetalyticsSubdomainsParse verifies the subdomains query path.
func TestZetalyticsSubdomainsParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "token=k") {
			t.Errorf("missing token: %q", r.URL.RawQuery)
		}
		switch {
		case strings.Contains(r.URL.Path, "/subdomains/"):
			_, _ = w.Write([]byte(`{"results":[{"qname":"a.example.com"},{"qname":"b.example.com"},{"qname":"unrelated.org"}]}`))
		case strings.Contains(r.URL.Path, "/email_domain/"):
			_, _ = w.Write([]byte(`{"results":[]}`))
		default:
			_, _ = w.Write([]byte(`{"results":[]}`))
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("zetalytics")().(*Zetalytics)
	_ = m.Setup(map[string]any{"zetalytics_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 2 INTERNET_NAME (matching target) + 1 RAW_RIR_DATA
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestZetalyticsEmailAddressParse verifies the email_address path.
func TestZetalyticsEmailAddressParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"d":"foo.com"},{"d":"bar.net"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("zetalytics")().(*Zetalytics)
	_ = m.Setup(map[string]any{"zetalytics_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newEmailEvent(t, "a@example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 2 AFFILIATE_DOMAIN_NAME + 1 RAW_RIR_DATA
	if len(out) != 3 {
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestZetalyticsEmptyNoCommit verifies a no-results response is dropped.
func TestZetalyticsEmptyNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("zetalytics")().(*Zetalytics)
	_ = m.Setup(map[string]any{"zetalytics_api_key": "k"})
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// compile-time interface checks.
var _ module.Module = (*Ahmia)(nil)
var _ module.Module = (*OnionSearchEngine)(nil)
var _ module.Module = (*BitcoinAbuse)(nil)
var _ module.Module = (*OpenCorporates)(nil)
var _ module.Module = (*Onyphe)(nil)
var _ module.Module = (*Zetalytics)(nil)
