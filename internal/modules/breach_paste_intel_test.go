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

var batch21Names = []string{"psbdmp", "skymem", "grepapp", "snov", "abstractapi"}

// TestBatch21Registered verifies all Batch 21 modules are registered.
func TestBatch21Registered(t *testing.T) {
	for _, n := range batch21Names {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestBatch21Meta sanity-checks metadata and the RequiresAPIKey flag.
func TestBatch21Meta(t *testing.T) {
	keyed := map[string]bool{
		"psbdmp":      false,
		"skymem":      false,
		"grepapp":     false,
		"snov":        true,
		"abstractapi": true,
	}
	for _, n := range batch21Names {
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

// TestBatch21SetupNilOpts verifies Setup handles nil opts.
func TestBatch21SetupNilOpts(t *testing.T) {
	for _, n := range batch21Names {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup nil: %v", n, err)
		}
	}
}

// TestBatch21WatchedEvents asserts subscribed types match the documented set.
func TestBatch21WatchedEvents(t *testing.T) {
	expects := map[string][]event.Type{
		"psbdmp":      {event.EMAILADDR, event.DOMAIN_NAME, event.INTERNET_NAME},
		"skymem":      {event.INTERNET_NAME, event.DOMAIN_NAME},
		"grepapp":     {event.DOMAIN_NAME},
		"snov":        {event.DOMAIN_NAME, event.INTERNET_NAME},
		"abstractapi": {event.DOMAIN_NAME, event.PHONE_NUMBER, event.IP_ADDRESS, event.IPV6_ADDRESS},
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

// TestBatch21RejectGenericAPIKey verifies no Batch 21 module reads a
// generic api_key opt.
func TestBatch21RejectGenericAPIKey(t *testing.T) {
	opts := map[string]any{
		"api_key":       "leaked",
		"api_token":     "leaked",
		"token":         "leaked",
		"client_id":     "leaked",
		"client_secret": "leaked",
	}
	sn := getModule("snov")().(*Snov)
	_ = sn.Setup(opts)
	if sn.clientID != "" || sn.clientSecret != "" {
		t.Errorf("snov leaked: id=%q secret=%q", sn.clientID, sn.clientSecret)
	}
	ab := getModule("abstractapi")().(*AbstractAPI)
	_ = ab.Setup(opts)
	if ab.companyKey != "" || ab.phoneKey != "" || ab.ipGeoKey != "" {
		t.Errorf("abstractapi leaked: %+v", ab)
	}
}

// TestBatch21AcceptPrefixedKeys verifies the vendor-prefixed keys load.
func TestBatch21AcceptPrefixedKeys(t *testing.T) {
	sn := getModule("snov")().(*Snov)
	_ = sn.Setup(map[string]any{
		"snov_api_key_client_id":     "id",
		"snov_api_key_client_secret": "sec",
	})
	if sn.clientID != "id" || sn.clientSecret != "sec" {
		t.Errorf("snov: %+v", sn)
	}
	ab := getModule("abstractapi")().(*AbstractAPI)
	_ = ab.Setup(map[string]any{
		"abstractapi_api_key_companyenrichment": "c",
		"abstractapi_api_key_phonevalidation":   "p",
		"abstractapi_api_key_ipgeolocation":     "i",
	})
	if ab.companyKey != "c" || ab.phoneKey != "p" || ab.ipGeoKey != "i" {
		t.Errorf("abstractapi: %+v", ab)
	}
}

// TestBatch21KeyedNoKeyNoOp ensures keyed modules no-op without creds.
func TestBatch21KeyedNoKeyNoOp(t *testing.T) {
	cases := map[string]*event.Event{
		"snov":        newDomainEvent(t, "example.com"),
		"abstractapi": newDomainEvent(t, "example.com"),
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

// TestPsbdmpLiveParse exercises the success path.
func TestPsbdmpLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/search/domain/example.com") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"count":2,"data":[{"id":"abc123"},{"id":"def456"}]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("psbdmp")().(*Psbdmp)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// 2 LEAKSITE_URL + 1 RAW_RIR_DATA
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestPsbdmpZeroCountNoCommit verifies count==0 does not commit.
func TestPsbdmpZeroCountNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":0,"data":[]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("psbdmp")().(*Psbdmp)
	_ = m.Setup(nil)
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestPsbdmpEmailPath verifies the email-query path is picked.
func TestPsbdmpEmailPath(t *testing.T) {
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"count":0,"data":[]}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("psbdmp")().(*Psbdmp)
	_ = m.Setup(nil)
	_, _ = m.HandleEvent(context.Background(), newEmailEvent(t, "foo@example.com"))
	if !strings.Contains(gotPath, "/api/search/email/") {
		t.Errorf("expected email path, got %q", gotPath)
	}
}

// TestPsbdmpShape is a regression test on the response shape.
func TestPsbdmpShape(t *testing.T) {
	var r psbdmpResp
	if err := json.Unmarshal([]byte(`{"count":1,"data":[{"id":"xyz"}]}`), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Count != 1 || len(r.Data) != 1 || r.Data[0].ID != "xyz" {
		t.Errorf("parsed: %+v", r)
	}
}

// TestSkymemParse verifies email extraction + domain filter.
func TestSkymemParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return landing page with one matching and one unrelated email;
		// no domain-id link so no pagination.
		_, _ = w.Write([]byte(`<html>
foo@example.com bar@other.com sales@sub.example.com
</html>`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("skymem")().(*Skymem)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// foo@example.com + sales@sub.example.com (bar@other.com filtered)
	if len(out) != 2 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 2 events, got %d", len(out))
	}
}

// TestSkymemEmptyNoCommit verifies no-matches does not commit.
func TestSkymemEmptyNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`no emails here`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("skymem")().(*Skymem)
	_ = m.Setup(nil)
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestGrepappLiveParse exercises the success path.
func TestGrepappLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
"facets":{"count":1},
"hits":{"hits":[
  {"content":{"snippet":"visit https://www.example.com/path and mail foo@example.com or unrelated@bad.org"}}
]}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("grepapp")().(*Grepapp)
	_ = m.Setup(nil)
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + LINKED_URL_INTERNAL + INTERNET_NAME + EMAILADDR = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestGrepappShape is a regression test on the response shape.
func TestGrepappShape(t *testing.T) {
	var r grepappResp
	if err := json.Unmarshal([]byte(
		`{"facets":{"count":3},"hits":{"hits":[{"content":{"snippet":"s"}}]}}`,
	), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Facets.Count != 3 || len(r.Hits.Hits) != 1 || r.Hits.Hits[0].Content.Snippet != "s" {
		t.Errorf("parsed: %+v", r)
	}
}

// TestGrepappEmptyNoCommit verifies count==0 does not commit.
func TestGrepappEmptyNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"facets":{"count":0},"hits":{"hits":[]}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("grepapp")().(*Grepapp)
	_ = m.Setup(nil)
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestSnovLiveParse exercises the two-step OAuth + domain-emails path.
func TestSnovLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/v1/oauth/access_token"):
			_, _ = w.Write([]byte(`{"access_token":"tok"}`))
		case strings.Contains(r.URL.Path, "/v2/domain-emails-with-info"):
			_, _ = w.Write([]byte(`{"emails":[{"email":"foo@example.com"},{"email":"bar@example.com"}],"lastId":42}`))
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("snov")().(*Snov)
	_ = m.Setup(map[string]any{
		"snov_api_key_client_id":     "id",
		"snov_api_key_client_secret": "sec",
	})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + 2 EMAILADDR
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestSnovNoTokenNoCommit verifies a missing access token aborts.
func TestSnovNoTokenNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":"bad creds"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("snov")().(*Snov)
	_ = m.Setup(map[string]any{
		"snov_api_key_client_id":     "id",
		"snov_api_key_client_secret": "sec",
	})
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestSnovShape is a regression test on the two response shapes.
func TestSnovShape(t *testing.T) {
	var tok snovTokenResp
	if err := json.Unmarshal([]byte(`{"access_token":"xyz"}`), &tok); err != nil {
		t.Fatalf("tok: %v", err)
	}
	if tok.AccessToken != "xyz" {
		t.Errorf("tok: %+v", tok)
	}
	var d snovDomainResp
	if err := json.Unmarshal([]byte(`{"emails":[{"email":"a@b.com"}],"lastId":9}`), &d); err != nil {
		t.Fatalf("domain: %v", err)
	}
	if len(d.Emails) != 1 || d.Emails[0].Email != "a@b.com" || d.LastID != 9 {
		t.Errorf("domain: %+v", d)
	}
}

// TestAbstractAPICompany exercises the company-enrichment path.
func TestAbstractAPICompany(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Host, "companyenrichment") && !strings.Contains(r.Host, "companyenrichment") {
			// rewriteTransport retargets host, can't rely on original host
		}
		_, _ = w.Write([]byte(`{"name":"Acme","linkedin_url":"linkedin.com/company/acme","locality":"SF","country":"USA"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("abstractapi")().(*AbstractAPI)
	_ = m.Setup(map[string]any{"abstractapi_api_key_companyenrichment": "k"})
	out, err := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW_RIR_DATA + COMPANY_NAME + SOCIAL_MEDIA + GEOINFO = 4
	if len(out) != 4 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 4 events, got %d", len(out))
	}
}

// TestAbstractAPICompanyTBCNoCommit verifies "To Be Confirmed" is dropped.
func TestAbstractAPICompanyTBCNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"To Be Confirmed"}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("abstractapi")().(*AbstractAPI)
	_ = m.Setup(map[string]any{"abstractapi_api_key_companyenrichment": "k"})
	out, _ := m.HandleEvent(context.Background(), newDomainEvent(t, "example.com"))
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestAbstractAPIPhone exercises the phone-validation path.
func TestAbstractAPIPhone(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"valid":true,"carrier":"ACME Telecom","location":"SF","country":{"name":"USA"}}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("abstractapi")().(*AbstractAPI)
	_ = m.Setup(map[string]any{"abstractapi_api_key_phonevalidation": "k"})
	root, _ := event.New(event.ROOT, "target", "test", nil)
	ph, _ := event.New(event.PHONE_NUMBER, "+15551234", "test", root)
	out, err := m.HandleEvent(context.Background(), ph)
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW + PROVIDER_TELCO + GEOINFO = 3
	if len(out) != 3 {
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestAbstractAPIPhoneInvalidNoCommit verifies valid=false drops results.
func TestAbstractAPIPhoneInvalidNoCommit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"valid":false}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("abstractapi")().(*AbstractAPI)
	_ = m.Setup(map[string]any{"abstractapi_api_key_phonevalidation": "k"})
	root, _ := event.New(event.ROOT, "target", "test", nil)
	ph, _ := event.New(event.PHONE_NUMBER, "+15551234", "test", root)
	out, _ := m.HandleEvent(context.Background(), ph)
	if len(out) != 0 {
		t.Errorf("expected 0 events, got %d", len(out))
	}
}

// TestAbstractAPIIPGeo exercises the IP geolocation path.
func TestAbstractAPIIPGeo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"city":"Tokyo","region":"Tokyo","postal_code":"100","country":"Japan","continent":"Asia","latitude":35.6,"longitude":139.7}`))
	}))
	defer ts.Close()
	withFakeMajorAPIServer(t, ts)
	m := getModule("abstractapi")().(*AbstractAPI)
	_ = m.Setup(map[string]any{"abstractapi_api_key_ipgeolocation": "k"})
	out, err := m.HandleEvent(context.Background(), newIPEvent(t, "1.2.3.4"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// RAW + GEOINFO + PHYSICAL_COORDINATES = 3
	if len(out) != 3 {
		for i, e := range out {
			t.Logf("[%d] %s = %q", i, e.Type, e.Data)
		}
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestAbstractAPIShapes is a regression test on all three response shapes.
func TestAbstractAPIShapes(t *testing.T) {
	var c abstractCompanyResp
	if err := json.Unmarshal(
		[]byte(`{"name":"Acme","linkedin_url":"l","locality":"x","country":"y"}`), &c); err != nil {
		t.Fatalf("company: %v", err)
	}
	if c.Name != "Acme" || c.LinkedinURL != "l" {
		t.Errorf("company: %+v", c)
	}
	var p abstractPhoneResp
	if err := json.Unmarshal(
		[]byte(`{"valid":true,"carrier":"c","location":"l","country":{"name":"USA"}}`), &p); err != nil {
		t.Fatalf("phone: %v", err)
	}
	if !p.Valid || p.Country.Name != "USA" {
		t.Errorf("phone: %+v", p)
	}
	var g abstractIPGeoResp
	if err := json.Unmarshal(
		[]byte(`{"city":"T","country":"J","latitude":1.5,"longitude":2.5}`), &g); err != nil {
		t.Fatalf("ipgeo: %v", err)
	}
	if g.Latitude != 1.5 || g.Longitude != 2.5 {
		t.Errorf("ipgeo: %+v", g)
	}
}

// compile-time interface checks.
var _ module.Module = (*Psbdmp)(nil)
var _ module.Module = (*Skymem)(nil)
var _ module.Module = (*Grepapp)(nil)
var _ module.Module = (*Snov)(nil)
var _ module.Module = (*AbstractAPI)(nil)
