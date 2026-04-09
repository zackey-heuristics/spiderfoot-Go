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

var geoIPNames = []string{"ipapico", "ipapicom", "ipregistry", "ipstack", "neutrinoapi"}

// TestGeoIPRegistered verifies all Batch 18 modules are registered.
func TestGeoIPRegistered(t *testing.T) {
	for _, n := range geoIPNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestGeoIPMeta checks module metadata.
func TestGeoIPMeta(t *testing.T) {
	keyed := map[string]bool{
		"ipapico":     false,
		"ipapicom":    true,
		"ipregistry":  true,
		"ipstack":     true,
		"neutrinoapi": true,
	}
	for _, n := range geoIPNames {
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

// TestGeoIPSetupNilOpts verifies Setup handles nil opts.
func TestGeoIPSetupNilOpts(t *testing.T) {
	for _, n := range geoIPNames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup nil: %v", n, err)
		}
	}
}

// TestGeoIPHandleNilEvent ensures nil events are safe no-ops.
func TestGeoIPHandleNilEvent(t *testing.T) {
	for _, n := range geoIPNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		out, err := m.HandleEvent(context.Background(), nil)
		if err != nil || out != nil {
			t.Errorf("%s: nil event returned %v, %v", n, out, err)
		}
		_ = m.Finish()
	}
}

// TestGeoIPKeyedNoKeyNoOp ensures keyed modules no-op without creds.
func TestGeoIPKeyedNoKeyNoOp(t *testing.T) {
	for _, n := range []string{"ipapicom", "ipregistry", "ipstack", "neutrinoapi"} {
		m := getModule(n)()
		_ = m.Setup(nil)
		out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
		if err != nil {
			t.Errorf("%s: %v", n, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: emitted %d events without key", n, len(out))
		}
	}
}

// TestGeoIPRejectGenericAPIKey verifies no module consumes a generic
// api_key / user_id opt — only vendor-prefixed keys.
func TestGeoIPRejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":        "leaked",
		"user_id":        "leaked",
		"access_key":     "leaked",
		"api_key_user":   "leaked",
		"api_key_secret": "leaked",
	}
	ic := getModule("ipapicom")().(*IPAPICom)
	_ = ic.Setup(opts)
	if ic.apiKey != "" {
		t.Errorf("ipapicom: leaked key = %q", ic.apiKey)
	}
	ir := getModule("ipregistry")().(*IPRegistry)
	_ = ir.Setup(opts)
	if ir.apiKey != "" {
		t.Errorf("ipregistry: leaked key = %q", ir.apiKey)
	}
	is := getModule("ipstack")().(*IPStack)
	_ = is.Setup(opts)
	if is.apiKey != "" {
		t.Errorf("ipstack: leaked key = %q", is.apiKey)
	}
	na := getModule("neutrinoapi")().(*NeutrinoAPI)
	_ = na.Setup(opts)
	if na.userID != "" || na.apiKey != "" {
		t.Errorf("neutrinoapi: leaked creds u=%q k=%q", na.userID, na.apiKey)
	}
}

// TestGeoIPAcceptPrefixedKeys verifies vendor-prefixed opt names work.
func TestGeoIPAcceptPrefixedKeys(t *testing.T) {
	ic := getModule("ipapicom")().(*IPAPICom)
	_ = ic.Setup(map[string]any{"ipapicom_api_key": "k"})
	if ic.apiKey != "k" {
		t.Errorf("ipapicom: %q", ic.apiKey)
	}
	ir := getModule("ipregistry")().(*IPRegistry)
	_ = ir.Setup(map[string]any{"ipregistry_api_key": "k"})
	if ir.apiKey != "k" {
		t.Errorf("ipregistry: %q", ir.apiKey)
	}
	is := getModule("ipstack")().(*IPStack)
	_ = is.Setup(map[string]any{"ipstack_api_key": "k"})
	if is.apiKey != "k" {
		t.Errorf("ipstack: %q", is.apiKey)
	}
	na := getModule("neutrinoapi")().(*NeutrinoAPI)
	_ = na.Setup(map[string]any{
		"neutrinoapi_api_key_user":   "u",
		"neutrinoapi_api_key_secret": "s",
	})
	if na.userID != "u" || na.apiKey != "s" {
		t.Errorf("neutrinoapi: u=%q s=%q", na.userID, na.apiKey)
	}
}

// TestIPAPICoLiveParse exercises the ipapi.co parser end-to-end.
func TestIPAPICoLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"city": "Mountain View",
			"region": "California",
			"region_code": "CA",
			"country": "US",
			"country_name": "United States"
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipapico")().(*IPAPICo)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// GEOINFO + RAW_RIR_DATA = 2
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	if !strings.Contains(out[0].Data, "Mountain View") {
		t.Errorf("geo data missing city: %q", out[0].Data)
	}
}

// TestIPAPICoErrorNoCommit verifies an error response leaves committed=false.
func TestIPAPICoErrorNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error": true, "reason": "rate limited"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipapico")().(*IPAPICo)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events on error response, got %d", len(out))
	}
}

// TestIPAPIComLiveParse exercises the ipapi.com parser.
func TestIPAPIComLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "access_key=k") {
			t.Errorf("missing access_key: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{
			"city": "Tokyo",
			"region_name": "Tokyo",
			"region_code": "13",
			"country_name": "Japan",
			"country_code": "JP",
			"latitude": 35.6895,
			"longitude": 139.6917
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipapicom")().(*IPAPICom)
	_ = m.Setup(map[string]any{"ipapicom_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// GEOINFO + PHYSICAL_COORDINATES + RAW_RIR_DATA = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestIPAPIComSuccessFalseNoCommit ensures a success:false payload does
// not commit to the dedup cache.
func TestIPAPIComSuccessFalseNoCommit(t *testing.T) {
	var resp ipapiComResp
	if err := json.Unmarshal([]byte(`{"success": false, "error": {"code": 101}}`), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Success == nil || *resp.Success {
		t.Errorf("expected Success=false")
	}
	if resp.CountryName != "" {
		t.Errorf("expected empty country")
	}
}

// TestIPRegistryLiveParse exercises the nested ipregistry response shape.
func TestIPRegistryLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"location": {
				"city": "Paris",
				"postal": "75001",
				"country": {"name": "France"},
				"region": {"name": "Ile-de-France"},
				"latitude": 48.8566,
				"longitude": 2.3522
			},
			"security": {"is_abuser": true, "is_attacker": false, "is_threat": false}
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipregistry")().(*IPRegistry)
	_ = m.Setup(map[string]any{"ipregistry_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// GEOINFO + PHYSICAL_COORDINATES + MALICIOUS_IPADDR + RAW_RIR_DATA = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestIPRegistryNestedShape is a regression test ensuring
// location.country.name and location.region.name are parsed as
// objects, not flat strings (matches documented shape).
func TestIPRegistryNestedShape(t *testing.T) {
	var r ipRegistryResp
	body := []byte(`{"location": {"country": {"name": "Germany"}, "region": {"name": "Bavaria"}}}`)
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Location.Country.Name != "Germany" {
		t.Errorf("country: %q", r.Location.Country.Name)
	}
	if r.Location.Region.Name != "Bavaria" {
		t.Errorf("region: %q", r.Location.Region.Name)
	}
}

// TestIPRegistryEmptyNoCommit verifies an empty location/security
// payload does not commit.
func TestIPRegistryEmptyNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"location": {}, "security": {}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipregistry")().(*IPRegistry)
	_ = m.Setup(map[string]any{"ipregistry_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// TestIPStackLiveParse exercises the ipstack parser.
func TestIPStackLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"country_name": "Germany"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipstack")().(*IPStack)
	_ = m.Setup(map[string]any{"ipstack_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 1 || out[0].Data != "Germany" {
		t.Fatalf("unexpected events: %v", out)
	}
}

// TestIPStackSuccessFalseNoCommit verifies the documented success:false
// error shape leaves committed=false.
func TestIPStackSuccessFalseNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success": false, "error": {"code": 104, "type": "usage_limit_reached"}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipstack")().(*IPStack)
	_ = m.Setup(map[string]any{"ipstack_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events on success:false, got %d", len(out))
	}
}

// TestNeutrinoAPIIPInfoParse exercises the IP info/blocklist path.
func TestNeutrinoAPIIPInfoParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ip-info"):
			_, _ = w.Write([]byte(`{"city": "Osaka", "region": "Osaka", "country-code": "JP"}`))
		case strings.HasSuffix(r.URL.Path, "/ip-blocklist"):
			_, _ = w.Write([]byte(`{"is-listed": true, "is-proxy": true}`))
		case strings.HasSuffix(r.URL.Path, "/host-reputation"):
			_, _ = w.Write([]byte(`{"is-listed": false}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("neutrinoapi")().(*NeutrinoAPI)
	_ = m.Setup(map[string]any{
		"neutrinoapi_api_key_user":   "u",
		"neutrinoapi_api_key_secret": "s",
	})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// GEOINFO + MALICIOUS_IPADDR + BLACKLISTED_IPADDR + RAW_RIR_DATA = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestNeutrinoFieldNames is a regression test ensuring the hyphenated
// field names from the documented NeutrinoAPI response are parsed
// correctly into Go struct tags (country-code, is-listed).
func TestNeutrinoFieldNames(t *testing.T) {
	var info neutrinoIPInfoResp
	if err := json.Unmarshal([]byte(`{"city":"X","region":"Y","country-code":"US"}`), &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if info.CountryCode != "US" {
		t.Errorf("country-code: %q", info.CountryCode)
	}
	var bl neutrinoIPBlocklistResp
	if err := json.Unmarshal([]byte(`{"is-listed":true}`), &bl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bl.IsListed {
		t.Errorf("is-listed not parsed")
	}
}

// TestNeutrinoAPIHostRouting is a regression test for Codex
// adversarial review 2026-04-09. Host/domain events must be routed
// to the host-reputation endpoint (not ip-info/ip-blocklist), and
// INTERNET_NAME must be in WatchedEvents.
func TestNeutrinoAPIHostRouting(t *testing.T) {
	na := getModule("neutrinoapi")().(*NeutrinoAPI)
	var seen bool
	for _, w := range na.WatchedEvents() {
		if w == event.INTERNET_NAME {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("neutrinoapi: INTERNET_NAME not in WatchedEvents: %v", na.WatchedEvents())
	}

	var hostReputationCalled, ipInfoCalled, ipBlocklistCalled bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/host-reputation"):
			hostReputationCalled = true
			_, _ = w.Write([]byte(`{"is-listed": true}`))
		case strings.HasSuffix(r.URL.Path, "/ip-info"):
			ipInfoCalled = true
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/ip-blocklist"):
			ipBlocklistCalled = true
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("neutrinoapi")().(*NeutrinoAPI)
	_ = m.Setup(map[string]any{
		"neutrinoapi_api_key_user":   "u",
		"neutrinoapi_api_key_secret": "s",
	})
	root, _ := event.New(event.ROOT, "target", "test", nil)
	host, err := event.New(event.INTERNET_NAME, "evil.example.com", "test", root)
	if err != nil {
		t.Fatalf("create host event: %v", err)
	}
	out, err := m.HandleEvent(context.Background(), host)
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if !hostReputationCalled {
		t.Errorf("host-reputation not called for INTERNET_NAME")
	}
	if ipInfoCalled || ipBlocklistCalled {
		t.Errorf("IP endpoints called for host event: ipInfo=%v ipBlocklist=%v", ipInfoCalled, ipBlocklistCalled)
	}
	// Expect MALICIOUS + BLACKLISTED + RAW_RIR = 3 events.
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// compile-time interface checks.
var _ module.Module = (*IPAPICo)(nil)
var _ module.Module = (*IPAPICom)(nil)
var _ module.Module = (*IPRegistry)(nil)
var _ module.Module = (*IPStack)(nil)
var _ module.Module = (*NeutrinoAPI)(nil)

// ensure event import isn't lint-unused in the future if helpers move.
var _ = event.IP_ADDRESS
