// Package modules — Batch 11: Email/Phone service integrations.
//
// This file implements pragmatic ports of:
//   - haveibeenpwned (HIBP breach + paste lookup)
//   - hunter         (Hunter.io domain-search)
//   - clearbit       (Clearbit Person+Company combined find; API deprecated 2023)
//   - emailrep       (emailrep.io reputation lookup)
//
// All four modules require a per-module API key and will no-op when
// their key is not configured. Keys are read from opts under the
// Python-compatible prefixed names (hibp_api_key, hunter_api_key,
// clearbit_api_key, emailrep_api_key) to avoid collisions with the
// shared `default:` opts section that ModuleOpts merges.
//
// Each module declares Meta.RequiresAPIKey = true so future tooling
// (web UI indicators, CLI diagnostics) can surface missing keys.

package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// emailSvcHTTPClient is a dedicated http.Client for Batch 11 modules.
// We use net/http directly (not sflib.HTTPClient) because every one of
// these APIs requires a custom request header (hibp-api-key,
// Authorization Basic, Key) that sflib.HTTPClient does not expose —
// same reason BingSearch uses its own client.
var emailSvcHTTPClient = &http.Client{Timeout: 20 * time.Second}

// emailSvcMaxBody caps upstream response bodies to protect against
// misbehaving servers. 10 MiB is generous for these JSON APIs.
const emailSvcMaxBody = 10 << 20

// doJSONRequest performs an HTTP GET and returns the raw body on
// 200, or (nil, false) on any error/non-200. The caller supplies
// headers via a callback to avoid leaking http.Request across module
// boundaries. A false ok result signals the caller to release its
// seenSet reservation so a later event may retry.
func doJSONRequest(ctx context.Context, rawURL string, setHeaders func(h http.Header)) (body []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	if setHeaders != nil {
		setHeaders(req.Header)
	}
	resp, err := emailSvcHTTPClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	// 404 on HIBP means "no breaches for this account" — a definitive
	// answer, not a transient error. Callers handle this by checking
	// the returned ok flag and the status via a separate path; for
	// simplicity here we treat 404 as "no data" (nil body, ok=true).
	if resp.StatusCode == http.StatusNotFound {
		return nil, true
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, emailSvcMaxBody))
	if err != nil {
		return nil, false
	}
	return b, true
}

// ============================================================================
// HaveIBeenPwned
// ============================================================================

// HaveIBeenPwned queries the HIBP v3 API for breached accounts and
// pastes. Requires opts["hibp_api_key"].
type HaveIBeenPwned struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *HaveIBeenPwned) Meta() module.Meta {
	return module.Meta{
		Name:           "haveibeenpwned",
		Summary:        "Check HaveIBeenPwned.com for hacked e-mail addresses and phone numbers.",
		Categories:     []string{"Leaks, Dumps and Breaches"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts. Only the vendor-prefixed key
// name (hibp_api_key) is honored — a plain "api_key" from the
// shared `default:` section is intentionally NOT consumed, to
// prevent a generic default key from leaking to unrelated upstream
// vendors.
func (m *HaveIBeenPwned) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "hibp_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *HaveIBeenPwned) WatchedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.PHONE_NUMBER}
}

// ProducedEvents returns emitted event types.
func (m *HaveIBeenPwned) ProducedEvents() []event.Type {
	return []event.Type{
		event.EMAILADDR_COMPROMISED,
		event.PHONE_NUMBER_COMPROMISED,
		event.LEAKSITE_URL,
	}
}

// hibpBreach is the relevant subset of a HIBP breach entry.
type hibpBreach struct {
	Name string `json:"Name"`
}

// hibpPaste is the relevant subset of a HIBP paste entry.
type hibpPaste struct {
	Source string `json:"Source"`
	ID     string `json:"Id"`
}

// HandleEvent queries HIBP for breaches and pastes for the given account.
func (m *HaveIBeenPwned) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if m.apiKey == "" {
		return nil, nil
	}

	setHdr := func(h http.Header) {
		h.Set("hibp-api-key", m.apiKey)
		h.Set("Accept", "application/vnd.haveibeenpwned.v3+json")
		h.Set("User-Agent", "spiderfoot-go")
	}

	breachURL := "https://haveibeenpwned.com/api/v3/breachedaccount/" + url.PathEscape(evt.Data) + "?truncateResponse=true"
	breachBody, ok := doJSONRequest(ctx, breachURL, setHdr)
	if !ok {
		return nil, nil
	}
	// Parse before committing — a 200 with garbage JSON is a transient
	// upstream failure and should not suppress future retries. An empty
	// body (the 404 "no breach" case) is itself a definitive answer.
	var breaches []hibpBreach
	if len(breachBody) > 0 {
		if err := json.Unmarshal(breachBody, &breaches); err != nil {
			return nil, nil
		}
	}
	// Definitive response from HIBP (valid JSON or empty 404 body).
	// Commit regardless of pastes success below so later duplicates skip.
	committed = true

	var results []*event.Event
	compType := event.EMAILADDR_COMPROMISED
	if evt.Type == event.PHONE_NUMBER {
		compType = event.PHONE_NUMBER_COMPROMISED
	}
	for _, b := range breaches {
		if b.Name == "" {
			continue
		}
		data := fmt.Sprintf("%s [%s]", evt.Data, b.Name)
		if e, err := event.New(compType, data, "haveibeenpwned", evt); err == nil {
			results = append(results, e)
		}
	}

	// Pastes — only meaningful for email addresses.
	if evt.Type == event.EMAILADDR {
		pasteURL := "https://haveibeenpwned.com/api/v3/pasteaccount/" + url.PathEscape(evt.Data)
		pasteBody, ok := doJSONRequest(ctx, pasteURL, setHdr)
		if ok && len(pasteBody) > 0 {
			var pastes []hibpPaste
			if err := json.Unmarshal(pasteBody, &pastes); err == nil {
				for _, p := range pastes {
					if p.Source == "" || p.ID == "" {
						continue
					}
					var leakURL string
					switch strings.ToLower(p.Source) {
					case "pastebin":
						leakURL = "https://pastebin.com/" + p.ID
					case "pastie":
						leakURL = "https://pastie.org/" + p.ID
					default:
						continue
					}
					if e, err := event.New(event.LEAKSITE_URL, leakURL, "haveibeenpwned", evt); err == nil {
						results = append(results, e)
					}
				}
			}
		}
	}

	return results, nil
}

// Finish clears state.
func (m *HaveIBeenPwned) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Hunter
// ============================================================================

// Hunter queries api.hunter.io/v2/domain-search for emails associated
// with a domain. Requires opts["hunter_api_key"].
type Hunter struct {
	seen   seenSet
	apiKey string
}

// genericEmailLocals lists local-parts treated as role/generic accounts
// and emitted as EMAILADDR_GENERIC instead of EMAILADDR. Mirrors the
// _genericusers list in the Python SpiderFoot modules (abbreviated).
// Shared by Hunter and Clearbit.
var genericEmailLocals = map[string]bool{
	"abuse": true, "admin": true, "administrator": true, "contact": true,
	"help": true, "hello": true, "hostmaster": true, "info": true,
	"marketing": true, "noreply": true, "no-reply": true, "postmaster": true,
	"root": true, "sales": true, "security": true, "support": true,
	"webmaster": true,
}

// Meta returns module metadata.
func (m *Hunter) Meta() module.Meta {
	return module.Meta{
		Name:           "hunter",
		Summary:        "Check Hunter.io for e-mail addresses and names associated with a domain.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts. Only hunter_api_key is honored;
// see HaveIBeenPwned.Setup for rationale.
func (m *Hunter) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "hunter_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Hunter) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Hunter) ProducedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.EMAILADDR_GENERIC, event.RAW_RIR_DATA}
}

// hunterResponse is the relevant subset of the Hunter domain-search response.
type hunterResponse struct {
	Data struct {
		Emails []struct {
			Value     string `json:"value"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"emails"`
	} `json:"data"`
}

// HandleEvent queries Hunter.io for the given domain.
func (m *Hunter) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if m.apiKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf(
		"https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s&limit=10&offset=0",
		url.QueryEscape(evt.Data), url.QueryEscape(m.apiKey),
	)
	body, ok := doJSONRequest(ctx, u, func(h http.Header) {
		h.Set("User-Agent", "spiderfoot-go")
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var payload hunterResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "hunter", evt); err == nil {
		results = append(results, e)
	}
	for _, em := range payload.Data.Emails {
		if em.Value == "" {
			continue
		}
		local := em.Value
		if at := strings.IndexByte(local, '@'); at > 0 {
			local = local[:at]
		}
		evType := event.EMAILADDR
		if genericEmailLocals[strings.ToLower(local)] {
			evType = event.EMAILADDR_GENERIC
		}
		if e, err := event.New(evType, em.Value, "hunter", evt); err == nil {
			results = append(results, e)
		}
		if em.FirstName != "" && em.LastName != "" {
			name := "Possible full name: " + em.FirstName + " " + em.LastName
			if e, err := event.New(event.RAW_RIR_DATA, name, "hunter", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Hunter) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Clearbit
// ============================================================================

// Clearbit queries person.clearbit.com combined find API. Requires
// opts["clearbit_api_key"]. Note: Clearbit's Discover API was
// deprecated in 2023; this module is a faithful port of the Python
// code path but is unlikely to return data in practice.
type Clearbit struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Clearbit) Meta() module.Meta {
	return module.Meta{
		Name:           "clearbit",
		Summary:        "Check Clearbit.com for person and company information by e-mail address.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts. Only clearbit_api_key is honored;
// see HaveIBeenPwned.Setup for rationale.
func (m *Clearbit) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "clearbit_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Clearbit) WatchedEvents() []event.Type { return []event.Type{event.EMAILADDR} }

// ProducedEvents returns emitted event types.
func (m *Clearbit) ProducedEvents() []event.Type {
	return []event.Type{
		event.RAW_RIR_DATA,
		event.PHONE_NUMBER,
		event.PHYSICAL_ADDRESS,
		event.AFFILIATE_INTERNET_NAME,
		event.INTERNET_NAME,
		event.EMAILADDR,
		event.EMAILADDR_GENERIC,
	}
}

// clearbitResponse captures the fields read from the combined-find response.
type clearbitResponse struct {
	Person *struct {
		Name struct {
			FullName string `json:"fullName"`
		} `json:"name"`
	} `json:"person"`
	Company *struct {
		Domain        string   `json:"domain"`
		DomainAliases []string `json:"domainAliases"`
		Site          struct {
			PhoneNumbers   []string `json:"phoneNumbers"`
			EmailAddresses []string `json:"emailAddresses"`
		} `json:"site"`
		Geo struct {
			StreetNumber string `json:"streetNumber"`
			StreetName   string `json:"streetName"`
			City         string `json:"city"`
			PostalCode   string `json:"postalCode"`
			State        string `json:"state"`
			Country      string `json:"country"`
		} `json:"geo"`
	} `json:"company"`
	Geo *struct {
		StreetNumber string `json:"streetNumber"`
		StreetName   string `json:"streetName"`
		City         string `json:"city"`
		PostalCode   string `json:"postalCode"`
		State        string `json:"state"`
		Country      string `json:"country"`
	} `json:"geo"`
}

// joinAddress builds a comma-separated physical address from parts.
func joinAddress(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ", ")
}

// HandleEvent queries Clearbit for the given email address.
func (m *Clearbit) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if m.apiKey == "" {
		return nil, nil
	}

	u := "https://person.clearbit.com/v2/combined/find?email=" + url.QueryEscape(evt.Data)
	token := base64.StdEncoding.EncodeToString([]byte(m.apiKey + ":"))
	body, ok := doJSONRequest(ctx, u, func(h http.Header) {
		h.Set("Authorization", "Basic "+token)
		h.Set("User-Agent", "spiderfoot-go")
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var payload clearbitResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "clearbit", evt); err == nil {
		results = append(results, e)
	}
	if payload.Person != nil && payload.Person.Name.FullName != "" {
		name := "Possible full name: " + payload.Person.Name.FullName
		if e, err := event.New(event.RAW_RIR_DATA, name, "clearbit", evt); err == nil {
			results = append(results, e)
		}
	}
	if payload.Geo != nil {
		addr := joinAddress(
			strings.TrimSpace(payload.Geo.StreetNumber+" "+payload.Geo.StreetName),
			payload.Geo.City, payload.Geo.PostalCode, payload.Geo.State, payload.Geo.Country,
		)
		if addr != "" {
			if e, err := event.New(event.PHYSICAL_ADDRESS, addr, "clearbit", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	// Infer target email domain once so we can classify aliases.
	emailDomain := ""
	if at := strings.IndexByte(evt.Data, '@'); at >= 0 {
		emailDomain = strings.ToLower(evt.Data[at+1:])
	}
	if payload.Company != nil {
		comp := payload.Company
		for _, alias := range comp.DomainAliases {
			alias = strings.TrimSpace(alias)
			if alias == "" {
				continue
			}
			evType := event.AFFILIATE_INTERNET_NAME
			if strings.EqualFold(alias, emailDomain) {
				evType = event.INTERNET_NAME
			}
			if e, err := event.New(evType, alias, "clearbit", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, ph := range comp.Site.PhoneNumbers {
			ph = strings.TrimSpace(ph)
			if ph == "" {
				continue
			}
			if e, err := event.New(event.PHONE_NUMBER, ph, "clearbit", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, em := range comp.Site.EmailAddresses {
			em = strings.TrimSpace(em)
			if em == "" {
				continue
			}
			local := em
			if at := strings.IndexByte(local, '@'); at > 0 {
				local = local[:at]
			}
			evType := event.EMAILADDR
			if genericEmailLocals[strings.ToLower(local)] {
				evType = event.EMAILADDR_GENERIC
			}
			if e, err := event.New(evType, em, "clearbit", evt); err == nil {
				results = append(results, e)
			}
		}
		addr := joinAddress(
			strings.TrimSpace(comp.Geo.StreetNumber+" "+comp.Geo.StreetName),
			comp.Geo.City, comp.Geo.PostalCode, comp.Geo.State, comp.Geo.Country,
		)
		if addr != "" {
			if e, err := event.New(event.PHYSICAL_ADDRESS, addr, "clearbit", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Clearbit) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// EmailRep
// ============================================================================

// EmailRep queries emailrep.io for email reputation. The API key is
// optional (the service allows ~50 anonymous requests/day), but this
// module still declares RequiresAPIKey=true and no-ops without a key
// to match the Batch 11 convention — encouraging users to supply a key
// to avoid rate limiting.
type EmailRep struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *EmailRep) Meta() module.Meta {
	return module.Meta{
		Name:           "emailrep",
		Summary:        "Search EmailRep for reputation information about an e-mail address.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts. Only emailrep_api_key is honored;
// see HaveIBeenPwned.Setup for rationale.
func (m *EmailRep) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "emailrep_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *EmailRep) WatchedEvents() []event.Type { return []event.Type{event.EMAILADDR} }

// ProducedEvents returns emitted event types.
func (m *EmailRep) ProducedEvents() []event.Type {
	return []event.Type{
		event.RAW_RIR_DATA,
		event.EMAILADDR_COMPROMISED,
		event.MALICIOUS_EMAILADDR,
	}
}

// emailRepResponse captures the fields read from the emailrep.io response.
type emailRepResponse struct {
	Details struct {
		CredentialsLeaked bool `json:"credentials_leaked"`
		MaliciousActivity bool `json:"malicious_activity"`
	} `json:"details"`
}

// HandleEvent queries emailrep.io for the given email address.
func (m *EmailRep) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if m.apiKey == "" {
		return nil, nil
	}

	u := "https://emailrep.io/" + url.PathEscape(evt.Data)
	body, ok := doJSONRequest(ctx, u, func(h http.Header) {
		h.Set("Key", m.apiKey)
		h.Set("User-Agent", "spiderfoot-go")
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var payload emailRepResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}
	committed = true
	if !payload.Details.CredentialsLeaked && !payload.Details.MaliciousActivity {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "emailrep", evt); err == nil {
		results = append(results, e)
	}
	if payload.Details.CredentialsLeaked {
		data := evt.Data + " [Unknown]"
		if e, err := event.New(event.EMAILADDR_COMPROMISED, data, "emailrep", evt); err == nil {
			results = append(results, e)
		}
	}
	if payload.Details.MaliciousActivity {
		data := "EmailRep [" + evt.Data + "]"
		if e, err := event.New(event.MALICIOUS_EMAILADDR, data, "emailrep", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *EmailRep) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("haveibeenpwned", func() module.Module { return &HaveIBeenPwned{} })
	module.Register("hunter", func() module.Module { return &Hunter{} })
	module.Register("clearbit", func() module.Module { return &Clearbit{} })
	module.Register("emailrep", func() module.Module { return &EmailRep{} })
}
