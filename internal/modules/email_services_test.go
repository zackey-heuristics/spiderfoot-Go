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

var emailServiceNames = []string{"haveibeenpwned", "hunter", "clearbit", "emailrep"}

// TestEmailServicesRegistered confirms all Batch 11 modules are registered.
func TestEmailServicesRegistered(t *testing.T) {
	for _, n := range emailServiceNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

// TestEmailServicesMeta checks Meta returns correct name and RequiresAPIKey=true.
func TestEmailServicesMeta(t *testing.T) {
	for _, n := range emailServiceNames {
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

// TestEmailServicesWatchedProduced smoke-checks non-empty event lists.
func TestEmailServicesWatchedProduced(t *testing.T) {
	for _, n := range emailServiceNames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

// TestEmailServicesHandleNilEvent ensures nil events are no-ops.
func TestEmailServicesHandleNilEvent(t *testing.T) {
	for _, n := range emailServiceNames {
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

// TestEmailServicesFinish verifies Finish is safe to call.
func TestEmailServicesFinish(t *testing.T) {
	for _, n := range emailServiceNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

// TestEmailServicesNoKeyNoOp ensures all 4 modules return zero events
// without an API key. Mirrors TestGoogleBingNoKeyNoOp in search_apis_test.go.
func TestEmailServicesNoKeyNoOp(t *testing.T) {
	inputs := map[string]*event.Event{
		"haveibeenpwned": newEmailEvent(t, "user@example.com"),
		"hunter":         newDomainEvent(t, "example.com"),
		"clearbit":       newEmailEvent(t, "user@example.com"),
		"emailrep":       newEmailEvent(t, "user@example.com"),
	}
	for _, n := range emailServiceNames {
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

// newEmailEvent constructs an EMAILADDR event for tests.
func newEmailEvent(t *testing.T, addr string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "target", "test", nil)
	if err != nil {
		t.Fatalf("create root event: %v", err)
	}
	e, err := event.New(event.EMAILADDR, addr, "test", root)
	if err != nil {
		t.Fatalf("create email event: %v", err)
	}
	return e
}

// newDomainEvent constructs a DOMAIN_NAME event for tests.
func newDomainEvent(t *testing.T, domain string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "target", "test", nil)
	if err != nil {
		t.Fatalf("create root event: %v", err)
	}
	e, err := event.New(event.DOMAIN_NAME, domain, "test", root)
	if err != nil {
		t.Fatalf("create domain event: %v", err)
	}
	return e
}

// withFakeEmailSvcServer replaces emailSvcHTTPClient with one that
// routes all requests to ts regardless of URL, and restores on cleanup.
func withFakeEmailSvcServer(t *testing.T, ts *httptest.Server) {
	t.Helper()
	orig := emailSvcHTTPClient
	emailSvcHTTPClient = ts.Client()
	emailSvcHTTPClient.Transport = rewriteTransport{
		target: ts.URL,
		inner:  ts.Client().Transport,
	}
	t.Cleanup(func() {
		emailSvcHTTPClient = orig
	})
}

// rewriteTransport redirects every request to target preserving path+query.
type rewriteTransport struct {
	target string
	inner  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tsReq, err := http.NewRequestWithContext(req.Context(), req.Method, r.target+req.URL.RequestURI(), req.Body)
	if err != nil {
		return nil, err
	}
	tsReq.Header = req.Header.Clone()
	inner := r.inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(tsReq)
}

// TestHibpLiveParse verifies HIBP parses a mock breach response.
func TestHibpLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") != "testkey" {
			t.Errorf("missing hibp-api-key header")
		}
		if r.URL.Path == "/api/v3/pasteaccount/user@example.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{{"Name": "Adobe"}, {"Name": "LinkedIn"}})
	}))
	defer ts.Close()
	withFakeEmailSvcServer(t, ts)

	m := getModule("haveibeenpwned")().(*HaveIBeenPwned)
	_ = m.Setup(map[string]any{"hibp_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newEmailEvent(t, "user@example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 breach events, got %d", len(out))
	}
	for _, e := range out {
		if e.Type != event.EMAILADDR_COMPROMISED {
			t.Errorf("wrong type: %s", e.Type)
		}
	}
}

// TestEmailRepLiveParse verifies emailrep parses a mock response.
func TestEmailRepLiveParse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "testkey" {
			t.Errorf("missing Key header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"details":{"credentials_leaked":true,"malicious_activity":true}}`))
	}))
	defer ts.Close()
	withFakeEmailSvcServer(t, ts)

	m := getModule("emailrep")().(*EmailRep)
	_ = m.Setup(map[string]any{"emailrep_api_key": "testkey"})
	out, err := m.HandleEvent(context.Background(), newEmailEvent(t, "user@example.com"))
	if err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}
	// Expect RAW_RIR_DATA + EMAILADDR_COMPROMISED + MALICIOUS_EMAILADDR = 3
	if len(out) != 3 {
		t.Fatalf("expected 3 events, got %d", len(out))
	}
}

// TestEmailServicesRejectGenericAPIKey is a security regression test:
// a generic "api_key" merged from the shared `default:` YAML section
// must NEVER be picked up by these modules. If it were, a default key
// intended for one vendor would silently be sent to all four upstream
// services. (Codex adversarial review, 2026-04-08.)
func TestEmailServicesRejectGenericAPIKey(t *testing.T) {
	apiKeyGetters := map[string]func(module.Module) string{
		"haveibeenpwned": func(m module.Module) string { return m.(*HaveIBeenPwned).apiKey },
		"hunter":         func(m module.Module) string { return m.(*Hunter).apiKey },
		"clearbit":       func(m module.Module) string { return m.(*Clearbit).apiKey },
		"emailrep":       func(m module.Module) string { return m.(*EmailRep).apiKey },
	}
	for _, n := range emailServiceNames {
		m := getModule(n)()
		if err := m.Setup(map[string]any{"api_key": "leaked-default-key"}); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
			continue
		}
		if got := apiKeyGetters[n](m); got != "" {
			t.Errorf("%s: leaked generic api_key into apiKey = %q (must be empty)", n, got)
		}
	}
}

// TestEmailServicesPrefixedAPIKey verifies prefixed opt names still work.
func TestEmailServicesPrefixedAPIKey(t *testing.T) {
	cases := []struct {
		name   string
		optKey string
		get    func(module.Module) string
	}{
		{"haveibeenpwned", "hibp_api_key", func(m module.Module) string { return m.(*HaveIBeenPwned).apiKey }},
		{"hunter", "hunter_api_key", func(m module.Module) string { return m.(*Hunter).apiKey }},
		{"clearbit", "clearbit_api_key", func(m module.Module) string { return m.(*Clearbit).apiKey }},
		{"emailrep", "emailrep_api_key", func(m module.Module) string { return m.(*EmailRep).apiKey }},
	}
	for _, c := range cases {
		m := getModule(c.name)()
		if err := m.Setup(map[string]any{c.optKey: "prefixkey"}); err != nil {
			t.Errorf("%s: setup error: %v", c.name, err)
			continue
		}
		if got := c.get(m); got != "prefixkey" {
			t.Errorf("%s: apiKey = %q, want %q", c.name, got, "prefixkey")
		}
	}
}

// ensure module.Module interface satisfied (compile-time check).
var _ module.Module = (*HaveIBeenPwned)(nil)
var _ module.Module = (*Hunter)(nil)
var _ module.Module = (*Clearbit)(nil)
var _ module.Module = (*EmailRep)(nil)
