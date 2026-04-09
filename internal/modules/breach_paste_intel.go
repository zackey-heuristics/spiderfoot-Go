// Package modules — Batch 21: Breach/paste/search intel APIs.
//
// This file implements pragmatic ports of:
//   - psbdmp      (psbdmp.cc Pastebin dump search; free, no key)
//   - skymem      (skymem.info email search; free, no key — HTTPS)
//   - grepapp     (grep.app code-search API; free, no key)
//   - snov        (api.snov.io domain->emails; requires client id+secret)
//   - abstractapi (AbstractAPI company/phone/ip endpoints; requires keys)
//
// Keyed modules follow the Batch 11+ vendor-prefixed opts convention
// and no-op without credentials. Generic "api_key" is never consulted.
// All requests use HTTPS. seenSet commits only after a documented-shape
// parse succeeds with substantive data.

package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// ============================================================================
// Psbdmp (Pastebin dump search, free)
// ============================================================================

// Psbdmp checks psbdmp.cc for email/domain leaks in Pastebin dumps.
type Psbdmp struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *Psbdmp) Meta() module.Meta {
	return module.Meta{
		Name:       "psbdmp",
		Summary:    "Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains.",
		Categories: []string{"Leaks, Dumps and Breaches"},
	}
}

// Setup is a no-op.
func (m *Psbdmp) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Psbdmp) WatchedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Psbdmp) ProducedEvents() []event.Type {
	return []event.Type{event.LEAKSITE_URL, event.RAW_RIR_DATA}
}

// psbdmpResp mirrors the documented psbdmp.cc /api/search response.
type psbdmpResp struct {
	Count int `json:"count"`
	Data  []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// HandleEvent queries psbdmp.cc for the given target.
func (m *Psbdmp) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var u string
	if strings.Contains(evt.Data, "@") {
		u = "https://psbdmp.cc/api/search/email/" + url.PathEscape(evt.Data)
	} else {
		u = "https://psbdmp.cc/api/search/domain/" + url.PathEscape(evt.Data)
	}
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp psbdmpResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if resp.Count <= 0 || len(resp.Data) == 0 {
		return nil, nil
	}
	var results []*event.Event
	for _, d := range resp.Data {
		if d.ID == "" {
			continue
		}
		link := "https://pastebin.com/" + d.ID
		if e, err := event.New(event.LEAKSITE_URL, link, "psbdmp", evt); err == nil {
			results = append(results, e)
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "psbdmp", evt); err == nil {
		results = append(results, e)
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Psbdmp) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Skymem (skymem.info email scrape, free)
// ============================================================================

// Skymem scrapes skymem.info for email addresses associated with a domain.
// The Python module fetches HTTP; we force HTTPS (hard-learned lesson #1).
type Skymem struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *Skymem) Meta() module.Meta {
	return module.Meta{
		Name:       "skymem",
		Summary:    "Look up e-mail addresses on Skymem.",
		Categories: []string{"Search Engines"},
	}
}

// Setup is a no-op.
func (m *Skymem) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Skymem) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Skymem) ProducedEvents() []event.Type {
	return []event.Type{event.EMAILADDR}
}

// skymemDomainIDRE extracts the internal skymem domain id from the
// landing-page HTML. Mirrors the Python regex.
var skymemDomainIDRE = regexp.MustCompile(`<a href="/domain/([a-z0-9]+)\?p=`)

// skymemPageMax caps pagination (mirrors Python 20).
const skymemPageMax = 20

// HandleEvent queries skymem.info for the given domain.
func (m *Skymem) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	target := strings.ToLower(evt.Data)
	emitted := map[string]bool{}
	var results []*event.Event

	collect := func(body []byte) {
		for _, e := range sflib.ExtractEmails(string(body)) {
			low := strings.ToLower(e)
			if emitted[low] {
				continue
			}
			parts := strings.SplitN(low, "@", 2)
			if len(parts) != 2 {
				continue
			}
			dom := parts[1]
			if dom != target && !strings.HasSuffix(dom, "."+target) {
				continue
			}
			emitted[low] = true
			if ev, err := event.New(event.EMAILADDR, e, "skymem", evt); err == nil {
				results = append(results, ev)
			}
		}
	}

	firstBody, ok := majorAPIFetch(ctx,
		"https://www.skymem.info/srch?q="+url.QueryEscape(evt.Data), nil)
	if !ok || len(firstBody) == 0 {
		return nil, nil
	}
	collect(firstBody)

	match := skymemDomainIDRE.FindSubmatch(firstBody)
	if len(match) == 2 {
		domainID := string(match[1])
		for page := 1; page <= skymemPageMax; page++ {
			body, ok := majorAPIFetch(ctx,
				"https://www.skymem.info/domain/"+url.PathEscape(domainID)+
					"?p="+itoa(page), nil)
			if !ok || len(body) == 0 {
				break
			}
			collect(body)
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Skymem) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Grepapp (grep.app code search, free)
// ============================================================================

// Grepapp searches grep.app for code mentions of a domain.
type Grepapp struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *Grepapp) Meta() module.Meta {
	return module.Meta{
		Name:       "grepapp",
		Summary:    "Search grep.app API for links and emails related to the specified domain.",
		Categories: []string{"Search Engines"},
	}
}

// Setup is a no-op.
func (m *Grepapp) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Grepapp) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Grepapp) ProducedEvents() []event.Type {
	return []event.Type{
		event.EMAILADDR,
		event.INTERNET_NAME,
		event.LINKED_URL_INTERNAL,
		event.RAW_RIR_DATA,
	}
}

// grepappResp mirrors the documented grep.app /api/search response.
type grepappResp struct {
	Facets struct {
		Count int `json:"count"`
	} `json:"facets"`
	Hits struct {
		Hits []struct {
			Content struct {
				Snippet string `json:"snippet"`
			} `json:"content"`
		} `json:"hits"`
	} `json:"hits"`
}

// grepappMaxPages caps pagination.
const grepappMaxPages = 20

// grepappPerPage is the upstream default page size.
const grepappPerPage = 10

// grepappMarkTagRE strips <mark>/</mark> tags from snippets.
var grepappMarkTagRE = regexp.MustCompile(`</?mark>`)

// HandleEvent queries grep.app for the given domain.
func (m *Grepapp) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	target := strings.ToLower(evt.Data)
	var results []*event.Event
	emitted := map[string]bool{}
	truncated := false
	maxPages := grepappMaxPages

	for page := 1; page <= maxPages; page++ {
		u := "https://grep.app/api/search?q=" + url.QueryEscape(evt.Data) +
			"&page=" + itoa(page)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			break
		}
		var resp grepappResp
		if err := json.Unmarshal(body, &resp); err != nil {
			break
		}
		if resp.Facets.Count == 0 {
			break
		}
		// API-reported total drives pagination ceiling.
		lastPage := (resp.Facets.Count + grepappPerPage - 1) / grepappPerPage
		if lastPage < maxPages {
			maxPages = lastPage
		}
		for _, h := range resp.Hits.Hits {
			snippet := grepappMarkTagRE.ReplaceAllString(h.Content.Snippet, "")
			if snippet == "" {
				continue
			}
			if e, err := event.New(event.RAW_RIR_DATA, snippet, "grepapp", evt); err == nil {
				results = append(results, e)
			}
			for _, link := range sflib.ExtractURLs(snippet) {
				if emitted["u:"+link] {
					continue
				}
				parsed, err := url.Parse(link)
				if err != nil || parsed.Host == "" {
					continue
				}
				host := strings.ToLower(parsed.Host)
				if host != target && !strings.HasSuffix(host, "."+target) {
					continue
				}
				emitted["u:"+link] = true
				if e, err := event.New(event.LINKED_URL_INTERNAL, link, "grepapp", evt); err == nil {
					results = append(results, e)
				}
				if !emitted["h:"+host] {
					emitted["h:"+host] = true
					if e, err := event.New(event.INTERNET_NAME, host, "grepapp", evt); err == nil {
						results = append(results, e)
					}
				}
			}
			for _, em := range sflib.ExtractEmails(snippet) {
				low := strings.ToLower(em)
				if emitted["e:"+low] {
					continue
				}
				parts := strings.SplitN(low, "@", 2)
				if len(parts) != 2 {
					continue
				}
				if parts[1] != target && !strings.HasSuffix(parts[1], "."+target) {
					continue
				}
				emitted["e:"+low] = true
				if e, err := event.New(event.EMAILADDR, em, "grepapp", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		if page == maxPages && page < (resp.Facets.Count+grepappPerPage-1)/grepappPerPage {
			truncated = true
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	if truncated {
		if e, err := event.New(event.RAW_RIR_DATA,
			"grepapp: pagination capped at "+itoa(grepappMaxPages)+" pages; results may be incomplete",
			"grepapp", evt); err == nil {
			results = append(results, e)
		}
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Grepapp) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Snov (Snov.io domain -> email, requires client id+secret OAuth)
// ============================================================================

// Snov queries Snov.io for emails under a target domain. Requires
// opts["snov_api_key_client_id"] and opts["snov_api_key_client_secret"].
type Snov struct {
	seen         seenSet
	clientID     string
	clientSecret string
}

// Meta returns module metadata.
func (m *Snov) Meta() module.Meta {
	return module.Meta{
		Name:           "snov",
		Summary:        "Gather available email IDs from identified domains via Snov.io.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the client id + secret pair from opts.
func (m *Snov) Setup(opts map[string]any) error {
	m.clientID = optString(opts, "snov_api_key_client_id", "")
	m.clientSecret = optString(opts, "snov_api_key_client_secret", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Snov) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Snov) ProducedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.RAW_RIR_DATA}
}

// snovTokenResp mirrors the /v1/oauth/access_token response.
type snovTokenResp struct {
	AccessToken string `json:"access_token"`
}

// snovDomainResp mirrors the /v2/domain-emails-with-info response.
type snovDomainResp struct {
	Emails []struct {
		Email string `json:"email"`
	} `json:"emails"`
	LastID int `json:"lastId"`
}

// snovLimit is the per-page cap (upstream maximum).
const snovLimit = 100

// snovMaxPages caps pagination to avoid runaway loops.
const snovMaxPages = 20

// HandleEvent queries Snov.io for emails at the given domain.
func (m *Snov) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.clientID == "" || m.clientSecret == "" {
		return nil, nil
	}

	// 1. Fetch access token. Secrets MUST travel in a POST body,
	//    not the URL, so they do not end up in reverse-proxy logs,
	//    tracing spans, or error telemetry. See Codex adversarial
	//    review 2026-04-09.
	tokenForm := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {m.clientID},
		"client_secret": {m.clientSecret},
	}
	body, ok := majorAPIFetchPOST(ctx, "https://api.snov.io/v1/oauth/access_token",
		func(h http.Header) {
			h.Set("Content-Type", "application/x-www-form-urlencoded")
		},
		[]byte(tokenForm.Encode()))
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var tok snovTokenResp
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return nil, nil
	}

	// Normalize the target domain for scoping. Emails whose host
	// does not match the queried domain (or a subdomain of it)
	// are dropped — upstream occasionally returns cross-tenant
	// aliases that would poison the scan graph. See Codex
	// adversarial review 2026-04-09.
	targetDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(evt.Data)), ".")
	inScope := func(email string) bool {
		at := strings.LastIndex(email, "@")
		if at < 0 || at == len(email)-1 {
			return false
		}
		host := email[at+1:]
		return host == targetDomain || strings.HasSuffix(host, "."+targetDomain)
	}

	// 2. Page through domain emails. Access token goes in the
	//    Authorization header rather than the URL.
	bearer := func(h http.Header) {
		h.Set("Authorization", "Bearer "+tok.AccessToken)
	}

	var results []*event.Event
	seen := map[string]bool{}
	truncated := false
	lastID := 0
	for page := 0; page < snovMaxPages; page++ {
		u := "https://api.snov.io/v2/domain-emails-with-info?" +
			"domain=" + url.QueryEscape(evt.Data) +
			"&type=all&limit=" + itoa(snovLimit) +
			"&lastId=" + itoa(lastID)
		body, ok := majorAPIFetch(ctx, u, bearer)
		if !ok || len(body) == 0 {
			break
		}
		var resp snovDomainResp
		if err := json.Unmarshal(body, &resp); err != nil {
			break
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "snov", evt); err == nil {
			results = append(results, e)
		}
		for _, r := range resp.Emails {
			low := strings.ToLower(r.Email)
			if low == "" || seen[low] {
				continue
			}
			if !strings.Contains(low, "@") {
				continue
			}
			if !inScope(low) {
				continue
			}
			seen[low] = true
			if e, err := event.New(event.EMAILADDR, r.Email, "snov", evt); err == nil {
				results = append(results, e)
			}
		}
		if len(resp.Emails) < snovLimit {
			break
		}
		lastID = resp.LastID
		if page == snovMaxPages-1 {
			truncated = true
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	// Require at least one EMAILADDR for substantive data commit.
	substantive := false
	for _, e := range results {
		if e.Type == event.EMAILADDR {
			substantive = true
			break
		}
	}
	if !substantive {
		return nil, nil
	}
	if truncated {
		if e, err := event.New(event.RAW_RIR_DATA,
			"snov: pagination capped at "+itoa(snovMaxPages)+" pages; results may be incomplete",
			"snov", evt); err == nil {
			results = append(results, e)
		}
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Snov) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// AbstractAPI (company / phone validation / ip geolocation, keyed)
// ============================================================================

// AbstractAPI queries the three AbstractAPI v1 endpoints for company,
// phone, and IP enrichment. Each endpoint has an independent
// vendor-prefixed opt key and is skipped when its key is empty.
type AbstractAPI struct {
	seen       seenSet
	companyKey string
	phoneKey   string
	ipGeoKey   string
}

// Meta returns module metadata.
func (m *AbstractAPI) Meta() module.Meta {
	return module.Meta{
		Name:           "abstractapi",
		Summary:        "Look up domain, phone and IP address information from AbstractAPI.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the per-endpoint API keys from opts.
func (m *AbstractAPI) Setup(opts map[string]any) error {
	m.companyKey = optString(opts, "abstractapi_api_key_companyenrichment", "")
	m.phoneKey = optString(opts, "abstractapi_api_key_phonevalidation", "")
	m.ipGeoKey = optString(opts, "abstractapi_api_key_ipgeolocation", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *AbstractAPI) WatchedEvents() []event.Type {
	return []event.Type{
		event.DOMAIN_NAME,
		event.PHONE_NUMBER,
		event.IP_ADDRESS,
		event.IPV6_ADDRESS,
	}
}

// ProducedEvents returns emitted event types.
func (m *AbstractAPI) ProducedEvents() []event.Type {
	return []event.Type{
		event.COMPANY_NAME,
		event.SOCIAL_MEDIA,
		event.GEOINFO,
		event.PHYSICAL_COORDINATES,
		event.PROVIDER_TELCO,
		event.RAW_RIR_DATA,
	}
}

// abstractCompanyResp mirrors the documented company-enrichment shape.
type abstractCompanyResp struct {
	Name        string `json:"name"`
	LinkedinURL string `json:"linkedin_url"`
	Locality    string `json:"locality"`
	Country     string `json:"country"`
}

// abstractPhoneResp mirrors the documented phone-validation shape.
type abstractPhoneResp struct {
	Valid    bool   `json:"valid"`
	Carrier  string `json:"carrier"`
	Location string `json:"location"`
	Country  struct {
		Name string `json:"name"`
	} `json:"country"`
}

// abstractIPGeoResp mirrors the documented ip-geolocation shape.
type abstractIPGeoResp struct {
	City       string  `json:"city"`
	Region     string  `json:"region"`
	PostalCode string  `json:"postal_code"`
	Country    string  `json:"country"`
	Continent  string  `json:"continent"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
}

// HandleEvent dispatches to the relevant AbstractAPI endpoint.
func (m *AbstractAPI) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var results []*event.Event
	switch evt.Type {
	case event.DOMAIN_NAME:
		if m.companyKey == "" {
			return nil, nil
		}
		u := "https://companyenrichment.abstractapi.com/v1/?api_key=" +
			url.QueryEscape(m.companyKey) + "&domain=" + url.QueryEscape(evt.Data)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp abstractCompanyResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		if resp.Name == "" || resp.Name == "To Be Confirmed" {
			return nil, nil
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "abstractapi", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(event.COMPANY_NAME, resp.Name, "abstractapi", evt); err == nil {
			results = append(results, e)
		}
		if resp.LinkedinURL != "" {
			link := resp.LinkedinURL
			if strings.HasPrefix(link, "linkedin.com") {
				link = "https://" + link
			}
			if e, err := event.New(event.SOCIAL_MEDIA,
				"LinkedIn (Company): "+sfURL("LinkedIn", link),
				"abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
		geo := joinNonEmpty(", ", resp.Locality, resp.Country)
		if geo != "" {
			if e, err := event.New(event.GEOINFO, geo, "abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
	case event.PHONE_NUMBER:
		if m.phoneKey == "" {
			return nil, nil
		}
		u := "https://phonevalidation.abstractapi.com/v1/?api_key=" +
			url.QueryEscape(m.phoneKey) + "&phone=" + url.QueryEscape(evt.Data)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp abstractPhoneResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		if !resp.Valid {
			return nil, nil
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "abstractapi", evt); err == nil {
			results = append(results, e)
		}
		if resp.Carrier != "" {
			if e, err := event.New(event.PROVIDER_TELCO, resp.Carrier, "abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
		geo := joinNonEmpty(", ", resp.Location, resp.Country.Name)
		if geo != "" {
			if e, err := event.New(event.GEOINFO, geo, "abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
	case event.IP_ADDRESS, event.IPV6_ADDRESS:
		if m.ipGeoKey == "" {
			return nil, nil
		}
		u := "https://ipgeolocation.abstractapi.com/v1/?api_key=" +
			url.QueryEscape(m.ipGeoKey) + "&ip_address=" + url.QueryEscape(evt.Data)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp abstractIPGeoResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		// Commit only when substantive geo data is present.
		if resp.Country == "" && resp.City == "" && resp.Latitude == 0 && resp.Longitude == 0 {
			return nil, nil
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "abstractapi", evt); err == nil {
			results = append(results, e)
		}
		geo := joinNonEmpty(", ",
			resp.City, resp.Region, resp.PostalCode, resp.Country, resp.Continent)
		if geo != "" {
			if e, err := event.New(event.GEOINFO, geo, "abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
		if resp.Latitude != 0 && resp.Longitude != 0 {
			coords := ftoa(resp.Latitude) + ", " + ftoa(resp.Longitude)
			if e, err := event.New(event.PHYSICAL_COORDINATES, coords, "abstractapi", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *AbstractAPI) Finish() error { m.seen.clear(); return nil }

// joinNonEmpty joins the given strings with sep, skipping any that are
// empty. Mirrors Python's `sep.join(filter(None, [...]))`.
func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// ftoa formats a float64 using the shortest-exact representation.
func ftoa(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("psbdmp", func() module.Module { return &Psbdmp{} })
	module.Register("skymem", func() module.Module { return &Skymem{} })
	module.Register("grepapp", func() module.Module { return &Grepapp{} })
	module.Register("snov", func() module.Module { return &Snov{} })
	module.Register("abstractapi", func() module.Module { return &AbstractAPI{} })
}
