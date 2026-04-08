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

var majorAPINames = []string{
	"shodan", "virustotal", "abuseipdb", "censys",
	"greynoise", "ipinfo", "securitytrails",
}

// TestMajorAPIsRegistered confirms all Batch 12 modules are registered.
func TestMajorAPIsRegistered(t *testing.T) {
	for _, n := range majorAPINames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestMajorAPIsMeta checks Meta returns correct name and RequiresAPIKey=true.
func TestMajorAPIsMeta(t *testing.T) {
	for _, n := range majorAPINames {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %q", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
		if !meta.RequiresAPIKey {
			t.Errorf("%s: RequiresAPIKey = false, want true", n)
		}
	}
}

// TestMajorAPIsWatchedProduced smoke-checks non-empty event lists.
func TestMajorAPIsWatchedProduced(t *testing.T) {
	for _, n := range majorAPINames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

// TestMajorAPIsHandleNilEvent ensures nil events are no-ops.
func TestMajorAPIsHandleNilEvent(t *testing.T) {
	for _, n := range majorAPINames {
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

// TestMajorAPIsFinish verifies Finish is safe to call.
func TestMajorAPIsFinish(t *testing.T) {
	for _, n := range majorAPINames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

// TestMajorAPIsNoKeyNoOp ensures all modules return zero events without keys.
func TestMajorAPIsNoKeyNoOp(t *testing.T) {
	inputs := map[string]*event.Event{
		"shodan":         newIPEvent(t, "1.2.3.4"),
		"virustotal":     newIPEvent(t, "1.2.3.4"),
		"abuseipdb":      newIPEvent(t, "1.2.3.4"),
		"censys":         newIPEvent(t, "1.2.3.4"),
		"greynoise":      newIPEvent(t, "1.2.3.4"),
		"ipinfo":         newIPEvent(t, "1.2.3.4"),
		"securitytrails": newDomainEvent(t, "example.com"),
	}
	for _, n := range majorAPINames {
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

// TestMajorAPIsRejectGenericAPIKey is the security regression test
// (cf. Batch 11): a generic "api_key" merged from `default:` must
// NEVER be picked up. Censys is checked separately because it uses
// uid+secret rather than a single api_key.
func TestMajorAPIsRejectGenericAPIKey(t *testing.T) {
	getters := map[string]func(module.Module) string{
		"shodan":         func(m module.Module) string { return m.(*Shodan).apiKey },
		"virustotal":     func(m module.Module) string { return m.(*VirusTotal).apiKey },
		"abuseipdb":      func(m module.Module) string { return m.(*AbuseIPDB).apiKey },
		"greynoise":      func(m module.Module) string { return m.(*GreyNoise).apiKey },
		"ipinfo":         func(m module.Module) string { return m.(*IPInfo).apiKey },
		"securitytrails": func(m module.Module) string { return m.(*SecurityTrails).apiKey },
	}
	for name, getter := range getters {
		m := getModule(name)()
		if err := m.Setup(map[string]any{"api_key": "leaked-default-key"}); err != nil {
			t.Errorf("%s: setup error: %v", name, err)
			continue
		}
		if got := getter(m); got != "" {
			t.Errorf("%s: leaked generic api_key into apiKey = %q (must be empty)", name, got)
		}
	}
	// Censys uses two separate keys; ensure neither leaks from generic names.
	c := getModule("censys")().(*Censys)
	_ = c.Setup(map[string]any{"api_key": "x", "uid": "y", "secret": "z"})
	if c.uid != "" || c.secret != "" {
		t.Errorf("censys: leaked generic uid/secret = (%q, %q)", c.uid, c.secret)
	}
}

// TestMajorAPIsAcceptPrefixedKey verifies the vendor-prefixed key works.
func TestMajorAPIsAcceptPrefixedKey(t *testing.T) {
	cases := []struct {
		name string
		opt  string
		get  func(module.Module) string
	}{
		{"shodan", "shodan_api_key", func(m module.Module) string { return m.(*Shodan).apiKey }},
		{"virustotal", "virustotal_api_key", func(m module.Module) string { return m.(*VirusTotal).apiKey }},
		{"abuseipdb", "abuseipdb_api_key", func(m module.Module) string { return m.(*AbuseIPDB).apiKey }},
		{"greynoise", "greynoise_api_key", func(m module.Module) string { return m.(*GreyNoise).apiKey }},
		{"ipinfo", "ipinfo_api_key", func(m module.Module) string { return m.(*IPInfo).apiKey }},
		{"securitytrails", "securitytrails_api_key", func(m module.Module) string { return m.(*SecurityTrails).apiKey }},
	}
	for _, c := range cases {
		m := getModule(c.name)()
		if err := m.Setup(map[string]any{c.opt: "prefixkey"}); err != nil {
			t.Errorf("%s: setup error: %v", c.name, err)
			continue
		}
		if got := c.get(m); got != "prefixkey" {
			t.Errorf("%s: apiKey = %q, want %q", c.name, got, "prefixkey")
		}
	}
	// Censys requires both UID and secret.
	c := getModule("censys")().(*Censys)
	_ = c.Setup(map[string]any{
		"censys_api_key_uid":    "u",
		"censys_api_key_secret": "s",
	})
	if c.uid != "u" || c.secret != "s" {
		t.Errorf("censys: uid=%q, secret=%q", c.uid, c.secret)
	}
}

// newIPEvent constructs an IP_ADDRESS event for tests.
func newIPEvent(t *testing.T, ip string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "target", "test", nil)
	if err != nil {
		t.Fatalf("create root event: %v", err)
	}
	e, err := event.New(event.IP_ADDRESS, ip, "test", root)
	if err != nil {
		t.Fatalf("create ip event: %v", err)
	}
	return e
}

// withFakeMajorAPIServer redirects majorAPIHTTPClient to ts and restores on cleanup.
func withFakeMajorAPIServer(t *testing.T, ts *httptest.Server) {
	t.Helper()
	orig := majorAPIHTTPClient
	majorAPIHTTPClient = ts.Client()
	majorAPIHTTPClient.Transport = rewriteTransport{
		target: ts.URL,
		inner:  ts.Client().Transport,
	}
	t.Cleanup(func() { majorAPIHTTPClient = orig })
}

// TestShodanLiveParse verifies Shodan host parsing.
func TestShodanLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "key=testkey") {
			t.Errorf("missing key= query param: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"os": "Linux 3.x",
			"devtype": "router",
			"city": "Tokyo",
			"country_name": "Japan",
			"asn": "AS15169",
			"data": [
				{"port": 80, "data": "HTTP banner", "vulns": ["CVE-2021-1234", "CVE-2022-5678"]},
				{"port": 443, "data": "TLS banner"}
			]
		}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("shodan")().(*Shodan)
	_ = m.Setup(map[string]any{"shodan_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: RAW_RIR_DATA + OS + DEVICE_TYPE + GEOINFO + BGP_AS_MEMBER
	//  + 2x TCP_PORT_OPEN + 2x TCP_PORT_OPEN_BANNER + 2x VULNERABILITY_GENERAL = 11
	if len(out) != 11 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 11 events, got %d", len(out))
	}
	// Verify ASN was stripped of "AS" prefix.
	for _, e := range out {
		if e.Type == event.BGP_AS_MEMBER && e.Data != "15169" {
			t.Errorf("ASN not stripped: %q", e.Data)
		}
	}
}

// TestIPInfoLiveParse verifies IPInfo geoinfo parsing.
func TestIPInfoLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer testkey" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"city":"Tokyo","region":"Tokyo","country":"JP"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("ipinfo")().(*IPInfo)
	_ = m.Setup(map[string]any{"ipinfo_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 events (RAW_RIR_DATA + GEOINFO), got %d", len(out))
	}
	for _, e := range out {
		if e.Type == event.GEOINFO && e.Data != "Tokyo, Tokyo, JP" {
			t.Errorf("wrong GEOINFO: %q", e.Data)
		}
	}
}

// TestAbuseIPDBLiveParse verifies the blacklist membership check.
func TestAbuseIPDBLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "testkey" {
			t.Errorf("missing Key header")
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("# header comment\n1.2.3.4\n5.6.7.8\n"))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("abuseipdb")().(*AbuseIPDB)
	_ = m.Setup(map[string]any{"abuseipdb_api_key": "testkey"})
	defer m.Finish()

	// Hit
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 2 { // BLACKLISTED_IPADDR + MALICIOUS_IPADDR
		t.Errorf("expected 2 events for hit, got %d", len(out))
	}
	// Miss
	out, err = m.HandleEvent(context.Background(), newIPEvent(t, "9.9.9.9"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 events for miss, got %d", len(out))
	}
}

// compile-time interface checks
var _ module.Module = (*Shodan)(nil)
var _ module.Module = (*VirusTotal)(nil)
var _ module.Module = (*AbuseIPDB)(nil)
var _ module.Module = (*Censys)(nil)
var _ module.Module = (*GreyNoise)(nil)
var _ module.Module = (*IPInfo)(nil)
var _ module.Module = (*SecurityTrails)(nil)
