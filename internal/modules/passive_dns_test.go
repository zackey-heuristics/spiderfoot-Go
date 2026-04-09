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

var passiveDNSNames = []string{"dnsdb", "whoxy", "mnemonic", "circllu", "fullhunt"}

// TestPassiveDNSRegistered verifies all Batch 19 modules are registered.
func TestPassiveDNSRegistered(t *testing.T) {
	for _, n := range passiveDNSNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestPassiveDNSMeta sanity-checks module metadata and key flags.
func TestPassiveDNSMeta(t *testing.T) {
	keyed := map[string]bool{
		"dnsdb":    true,
		"whoxy":    true,
		"mnemonic": false,
		"circllu":  true,
		"fullhunt": true,
	}
	for _, n := range passiveDNSNames {
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

// TestPassiveDNSSetupNilOpts verifies Setup handles nil opts.
func TestPassiveDNSSetupNilOpts(t *testing.T) {
	for _, n := range passiveDNSNames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup nil: %v", n, err)
		}
	}
}

// TestPassiveDNSKeyedNoKeyNoOp ensures keyed modules no-op without creds.
func TestPassiveDNSKeyedNoKeyNoOp(t *testing.T) {
	cases := map[string]*event.Event{
		"dnsdb":    newDomainEvent(t, "example.com"),
		"whoxy":    newEmailEvent(t, "a@example.com"),
		"circllu":  newIPEvent(t, "1.2.3.4"),
		"fullhunt": newDomainEvent(t, "example.com"),
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

// TestPassiveDNSRejectGenericAPIKey verifies no module consumes a
// generic api_key / user_id / access_key opt.
func TestPassiveDNSRejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":          "leaked",
		"api_key_login":    "leaked",
		"api_key_password": "leaked",
		"user_id":          "leaked",
		"access_key":       "leaked",
	}
	d := getModule("dnsdb")().(*DNSDB)
	_ = d.Setup(opts)
	if d.apiKey != "" {
		t.Errorf("dnsdb: leaked key = %q", d.apiKey)
	}
	w := getModule("whoxy")().(*Whoxy)
	_ = w.Setup(opts)
	if w.apiKey != "" {
		t.Errorf("whoxy: leaked key = %q", w.apiKey)
	}
	c := getModule("circllu")().(*CIRCLLU)
	_ = c.Setup(opts)
	if c.login != "" || c.password != "" {
		t.Errorf("circllu: leaked creds l=%q p=%q", c.login, c.password)
	}
	f := getModule("fullhunt")().(*FullHunt)
	_ = f.Setup(opts)
	if f.apiKey != "" {
		t.Errorf("fullhunt: leaked key = %q", f.apiKey)
	}
}

// TestPassiveDNSAcceptPrefixedKeys verifies vendor-prefixed keys work.
func TestPassiveDNSAcceptPrefixedKeys(t *testing.T) {
	d := getModule("dnsdb")().(*DNSDB)
	_ = d.Setup(map[string]any{"dnsdb_api_key": "k"})
	if d.apiKey != "k" {
		t.Errorf("dnsdb: %q", d.apiKey)
	}
	w := getModule("whoxy")().(*Whoxy)
	_ = w.Setup(map[string]any{"whoxy_api_key": "k"})
	if w.apiKey != "k" {
		t.Errorf("whoxy: %q", w.apiKey)
	}
	c := getModule("circllu")().(*CIRCLLU)
	_ = c.Setup(map[string]any{
		"circllu_api_key_login":    "u",
		"circllu_api_key_password": "p",
	})
	if c.login != "u" || c.password != "p" {
		t.Errorf("circllu: l=%q p=%q", c.login, c.password)
	}
	f := getModule("fullhunt")().(*FullHunt)
	_ = f.Setup(map[string]any{"fullhunt_api_key": "k"})
	if f.apiKey != "k" {
		t.Errorf("fullhunt: %q", f.apiKey)
	}
}

// TestPassiveDNSWatchedEvents asserts each module watches the claimed
// input event types and nothing outside its advertised capability.
func TestPassiveDNSWatchedEvents(t *testing.T) {
	expects := map[string][]event.Type{
		"dnsdb":    {event.IP_ADDRESS, event.IPV6_ADDRESS, event.DOMAIN_NAME},
		"whoxy":    {event.EMAILADDR},
		"mnemonic": {event.IP_ADDRESS, event.IPV6_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME},
		"circllu":  {event.IP_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME},
		"fullhunt": {event.DOMAIN_NAME},
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

// TestDNSDBNDJSONParse verifies the begin/record/end ndjson frame.
func TestDNSDBNDJSONParse(t *testing.T) {
	body := []byte(`{"cond":"begin"}
{"obj":{"rrtype":"A","rrname":"example.com.","rdata":["1.2.3.4","5.6.7.8"]}}
{"obj":{"rrtype":"MX","rrname":"example.com.","rdata":["10 mx.example.com."]}}
{"cond":"succeeded"}`)
	recs := parseDNSDBNDJSON(body)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].Obj.RRType != "A" || len(recs[0].Obj.RData) != 2 {
		t.Errorf("rec0: %+v", recs[0])
	}
	if recs[1].Obj.RRType != "MX" || recs[1].Obj.RData[0] != "10 mx.example.com." {
		t.Errorf("rec1: %+v", recs[1])
	}
}

// TestDNSDBDomainLiveParse exercises the full dnsdb domain path.
func TestDNSDBDomainLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			t.Errorf("missing X-API-Key header: %v", r.Header)
		}
		switch {
		case strings.Contains(r.URL.Path, "/rrset/name/"):
			_, _ = w.Write([]byte(`{"cond":"begin"}
{"obj":{"rrtype":"A","rrname":"example.com.","rdata":["1.2.3.4"]}}
{"obj":{"rrtype":"NS","rrname":"example.com.","rdata":["ns1.example.com."]}}
{"cond":"succeeded"}`))
		case strings.Contains(r.URL.Path, "/rdata/name/"):
			_, _ = w.Write([]byte(`{"cond":"begin"}
{"obj":{"rrtype":"CNAME","rrname":"alias.other.com.","rdata":["example.com."]}}
{"cond":"succeeded"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)

	m := getModule("dnsdb")().(*DNSDB)
	_ = m.Setup(map[string]any{"dnsdb_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// IP + NS + CNAME co-host = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestDNSDBIPLiveParse exercises the IP → rdata/ip path.
func TestDNSDBIPLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cond":"begin"}
{"obj":{"rrtype":"A","rrname":"host.example.com.","rdata":["1.2.3.4"]}}
{"cond":"succeeded"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("dnsdb")().(*DNSDB)
	_ = m.Setup(map[string]any{"dnsdb_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 1 || out[0].Type != event.INTERNET_NAME || out[0].Data != "host.example.com" {
		t.Fatalf("unexpected: %+v", out)
	}
}

// TestWhoxyLiveParse exercises the whoxy reverse-whois path.
func TestWhoxyLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "key=k") {
			t.Errorf("missing key= query: %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"status":1,"total_pages":1,"current_page":1,"search_result":[{"domain_name":"foo.com"},{"domain_name":"bar.net"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("whoxy")().(*Whoxy)
	_ = m.Setup(map[string]any{"whoxy_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newEmailEvent(t, "a@example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 2 domains × (AFFILIATE_INTERNET_NAME + AFFILIATE_DOMAIN_NAME) = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestWhoxyStatusZeroNoCommit verifies a status:0 payload commits nothing.
func TestWhoxyStatusZeroNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":0,"status_reason":"invalid key"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("whoxy")().(*Whoxy)
	_ = m.Setup(map[string]any{"whoxy_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newEmailEvent(t, "a@example.com"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// TestMnemonicLiveParse exercises the mnemonic domain path.
func TestMnemonicLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"responseCode":200,"size":2,"count":2,"data":[{"query":"example.com","answer":"1.2.3.4","rrtype":"a"},{"query":"example.com","answer":"1.2.3.5","rrtype":"a"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("mnemonic")().(*Mnemonic)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 2 IP_ADDRESS + 1 RAW_RIR_DATA
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestMnemonicErrorNoCommit verifies a non-200 responseCode produces no events.
func TestMnemonicErrorNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"responseCode":402,"size":0,"count":0,"data":[]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("mnemonic")().(*Mnemonic)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// TestMnemonicResponseShape is a regression test on the JSON field names.
func TestMnemonicResponseShape(t *testing.T) {
	var r mnemonicResp
	if err := json.Unmarshal([]byte(`{"responseCode":200,"size":1,"count":1,"data":[{"query":"x","answer":"y","rrtype":"cname"}]}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.ResponseCode != 200 || len(r.Data) != 1 || r.Data[0].RRType != "cname" {
		t.Errorf("parsed: %+v", r)
	}
}

// TestCIRCLLULiveParse exercises circllu with Basic auth assertion.
func TestCIRCLLULiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("missing Basic auth: %v", r.Header)
		}
		_, _ = w.Write([]byte(`{"rrtype":"A","rrname":"cohost.example.net","rdata":"1.2.3.4","time_last":1600000000}
{"rrtype":"A","rrname":"other.example.net","rdata":"9.9.9.9","time_last":1600000000}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("circllu")().(*CIRCLLU)
	_ = m.Setup(map[string]any{
		"circllu_api_key_login":    "u",
		"circllu_api_key_password": "p",
	})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 1 CO_HOSTED_SITE (match on rdata=1.2.3.4) + 1 RAW_RIR_DATA
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestFullHuntLiveParse exercises the fullhunt parser.
func TestFullHuntLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "k" {
			t.Errorf("missing X-API-KEY header: %v", r.Header)
		}
		_, _ = w.Write([]byte(`{"hosts":[{"host":"www.example.com","dns":{"mx":["mx.example.com."],"ns":["ns1.example.com."],"cname":["cdn.example.net."]},"network_ports":[80,443]}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("fullhunt")().(*FullHunt)
	_ = m.Setup(map[string]any{"fullhunt_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect: 2 TCP_PORT_OPEN + PROVIDER_MAIL + PROVIDER_DNS + 3 host events
	// (www, mx, ns1 → INTERNET_NAME; cdn.example.net → AFFILIATE) + RAW_RIR
	// = 2 + 1 + 1 + 4 + 1 = 9
	if len(out) != 9 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 9 events, got %d", len(out))
	}
}

// TestFullHuntEmptyHostsNoCommit verifies empty hosts array does not commit.
func TestFullHuntEmptyHostsNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hosts":[]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("fullhunt")().(*FullHunt)
	_ = m.Setup(map[string]any{"fullhunt_api_key": "k"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no events, got %d", len(out))
	}
}

// compile-time interface checks.
var _ module.Module = (*DNSDB)(nil)
var _ module.Module = (*Whoxy)(nil)
var _ module.Module = (*Mnemonic)(nil)
var _ module.Module = (*CIRCLLU)(nil)
var _ module.Module = (*FullHunt)(nil)
