// Package modules — Batch 8: Free APIs Part 2 — search engines and code/Q&A.
//
// This file implements pragmatic ports of:
//   - googlesearch (Google Custom Search JSON API)
//   - bingsearch   (Bing Web Search API)
//   - duckduckgo   (Instant Answer API)
//   - sublist3r    (api.sublist3r.com)
//   - stackoverflow (api.stackexchange.com)
//   - searchcode   (searchcode.com)
//
// Each module ports the most useful single query path of its Python
// counterpart. googlesearch and bingsearch require API credentials
// supplied via the opts map; without them they no-op gracefully.
package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// searchAPIClient is the shared HTTP client used by Batch 8 modules.
var searchAPIClient = sflib.NewHTTPClient(sflib.HTTPClientOpts{
	Timeout:   20 * time.Second,
	RateLimit: 1,
})

// bingHTTPClient is a dedicated http.Client for BingSearch. A bespoke
// client is needed because sflib.HTTPClient does not yet support custom
// request headers and Bing requires an Ocp-Apim-Subscription-Key header.
// An explicit timeout prevents slow/half-open upstream responses from
// stalling a scan indefinitely.
var bingHTTPClient = &http.Client{Timeout: 20 * time.Second}

// optString returns the string value of opts[key] or fallback.
func optString(opts map[string]any, key, fallback string) string {
	if v, ok := opts[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

// hostMatchesTarget reports whether host is the target domain itself or a
// subdomain of it. Both inputs are compared case-insensitively.
func hostMatchesTarget(host, target string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	target = strings.ToLower(strings.TrimSpace(target))
	if host == "" || target == "" {
		return false
	}
	if host == target {
		return true
	}
	return strings.HasSuffix(host, "."+target)
}

// urlInTargetScope reports whether rawURL's hostname is equal to target or a
// subdomain of it. It returns false if rawURL cannot be parsed into a URL
// with a non-empty hostname.
func urlInTargetScope(rawURL, target string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return hostMatchesTarget(u.Hostname(), target)
}

// ============================================================================
// GoogleSearch
// ============================================================================

// GoogleSearch queries the Google Custom Search JSON API for site:<domain>.
// Requires opts["google_api_key"] and opts["google_cse_id"].
type GoogleSearch struct {
	seen   seenSet
	apiKey string
	cseID  string
}

// Meta returns module metadata.
func (m *GoogleSearch) Meta() module.Meta {
	return module.Meta{Name: "googlesearch", Summary: "Identify URLs linked to from a target via Google Custom Search.", Categories: []string{"Search Engines"}}
}

// Setup reads API credentials from opts.
func (m *GoogleSearch) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "google_api_key", "")
	m.cseID = optString(opts, "google_cse_id", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *GoogleSearch) WatchedEvents() []event.Type { return []event.Type{event.INTERNET_NAME} }

// ProducedEvents returns emitted event types.
func (m *GoogleSearch) ProducedEvents() []event.Type {
	return []event.Type{event.LINKED_URL_INTERNAL, event.RAW_RIR_DATA}
}

// gcsResponse is the relevant subset of the Custom Search response.
type gcsResponse struct {
	Items []struct {
		Link string `json:"link"`
	} `json:"items"`
}

// HandleEvent runs a site:<domain> query against Google CSE.
func (m *GoogleSearch) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if m.apiKey == "" || m.cseID == "" {
		return nil, nil
	}
	target := strings.ToLower(evt.Data)
	q := url.QueryEscape("site:" + evt.Data)
	u := fmt.Sprintf("https://www.googleapis.com/customsearch/v1?key=%s&cx=%s&q=%s", url.QueryEscape(m.apiKey), url.QueryEscape(m.cseID), q)
	resp, err := searchAPIClient.FetchURL(ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Transient failures above fall through to the defer which releases
	// the reservation so a later event for the same indicator can retry.
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "googlesearch", evt); err == nil {
		results = append(results, e)
	}
	var payload gcsResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return results, nil
	}
	emitted := make(map[string]bool)
	for _, it := range payload.Items {
		if it.Link == "" || emitted[it.Link] || !urlInTargetScope(it.Link, target) {
			continue
		}
		emitted[it.Link] = true
		if e, err := event.New(event.LINKED_URL_INTERNAL, it.Link, "googlesearch", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *GoogleSearch) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// BingSearch
// ============================================================================

// BingSearch queries the Bing Web Search API for site:<domain>.
// Requires opts["bing_api_key"].
type BingSearch struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *BingSearch) Meta() module.Meta {
	return module.Meta{Name: "bingsearch", Summary: "Identify URLs linked to from a target via Bing Web Search.", Categories: []string{"Search Engines"}}
}

// Setup reads the API key from opts.
func (m *BingSearch) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "bing_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *BingSearch) WatchedEvents() []event.Type { return []event.Type{event.INTERNET_NAME} }

// ProducedEvents returns emitted event types.
func (m *BingSearch) ProducedEvents() []event.Type {
	return []event.Type{event.LINKED_URL_INTERNAL, event.RAW_RIR_DATA}
}

// bingResponse is the relevant subset of the Bing Web Search response.
type bingResponse struct {
	WebPages struct {
		Value []struct {
			URL string `json:"url"`
		} `json:"value"`
	} `json:"webPages"`
}

// HandleEvent runs a site:<domain> query against Bing.
func (m *BingSearch) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
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
	target := strings.ToLower(evt.Data)
	q := url.QueryEscape("site:" + evt.Data)
	u := "https://api.bing.microsoft.com/v7.0/search?count=50&q=" + q
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", m.apiKey)
	httpResp, err := bingHTTPClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 10<<20))
	if err != nil {
		return nil, nil
	}
	// Upstream returned 200 — commit the reservation made at entry.
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "bingsearch", evt); err == nil {
		results = append(results, e)
	}
	var payload bingResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return results, nil
	}
	emitted := make(map[string]bool)
	for _, v := range payload.WebPages.Value {
		if v.URL == "" || emitted[v.URL] || !urlInTargetScope(v.URL, target) {
			continue
		}
		emitted[v.URL] = true
		if e, err := event.New(event.LINKED_URL_INTERNAL, v.URL, "bingsearch", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *BingSearch) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// DuckDuckGo
// ============================================================================

// DuckDuckGo queries the DuckDuckGo Instant Answer API for an abstract and
// related-topic categories about a domain.
type DuckDuckGo struct{ seen seenSet }

// Meta returns module metadata.
func (m *DuckDuckGo) Meta() module.Meta {
	return module.Meta{Name: "duckduckgo", Summary: "Query the DuckDuckGo Instant Answer API for abstract and category information.", Categories: []string{"Search Engines"}}
}

// Setup initializes internal state.
func (m *DuckDuckGo) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *DuckDuckGo) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *DuckDuckGo) ProducedEvents() []event.Type {
	return []event.Type{event.DESCRIPTION_ABSTRACT, event.DESCRIPTION_CATEGORY}
}

// ddgResponse is the relevant subset of the Instant Answer payload.
type ddgResponse struct {
	Heading       string `json:"Heading"`
	AbstractText  string `json:"AbstractText"`
	RelatedTopics []struct {
		Text string `json:"Text"`
	} `json:"RelatedTopics"`
}

// HandleEvent fetches an Instant Answer for the event domain.
func (m *DuckDuckGo) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	u := "https://api.duckduckgo.com/?q=" + url.QueryEscape(evt.Data) + "&format=json&pretty=1"
	resp, err := searchAPIClient.FetchURL(ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Transient failures above fall through to the defer which releases
	// the reservation so a later event for the same indicator can retry.
	committed = true
	var payload ddgResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil || payload.Heading == "" {
		return nil, nil
	}
	var results []*event.Event
	if payload.AbstractText != "" {
		if e, err := event.New(event.DESCRIPTION_ABSTRACT, payload.AbstractText, "duckduckgo", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, t := range payload.RelatedTopics {
		if t.Text == "" {
			continue
		}
		if e, err := event.New(event.DESCRIPTION_CATEGORY, t.Text, "duckduckgo", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *DuckDuckGo) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Sublist3r
// ============================================================================

// Sublist3r queries api.sublist3r.com for known subdomains of a target.
type Sublist3r struct{ seen seenSet }

// Meta returns module metadata.
func (m *Sublist3r) Meta() module.Meta {
	return module.Meta{Name: "sublist3r", Summary: "Passive subdomain enumeration via api.sublist3r.com.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *Sublist3r) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Sublist3r) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Sublist3r) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.RAW_RIR_DATA}
}

// HandleEvent fetches the subdomain list and emits matches.
func (m *Sublist3r) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	target := strings.ToLower(evt.Data)
	u := "https://api.sublist3r.com/search.php?domain=" + url.QueryEscape(evt.Data)
	resp, err := searchAPIClient.FetchURL(ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Transient failures above fall through to the defer which releases
	// the reservation so a later event for the same indicator can retry.
	committed = true
	var hosts []string
	if err := json.Unmarshal([]byte(resp.Body), &hosts); err != nil {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "sublist3r", evt); err == nil {
		results = append(results, e)
	}
	emitted := make(map[string]bool)
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || emitted[h] || !hostMatchesTarget(h, target) {
			continue
		}
		emitted[h] = true
		if e, err := event.New(event.INTERNET_NAME, h, "sublist3r", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Sublist3r) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// StackOverflow
// ============================================================================

// StackOverflow queries api.stackexchange.com for posts mentioning the target
// domain and extracts any embedded email addresses.
type StackOverflow struct{ seen seenSet }

// Meta returns module metadata.
func (m *StackOverflow) Meta() module.Meta {
	return module.Meta{Name: "stackoverflow", Summary: "Search Stack Overflow for mentions of a target domain and extract emails.", Categories: []string{"Search Engines"}}
}

// Setup initializes internal state.
func (m *StackOverflow) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *StackOverflow) WatchedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

// ProducedEvents returns emitted event types.
func (m *StackOverflow) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.EMAILADDR, event.AFFILIATE_EMAILADDR}
}

// stackResponse is the relevant subset of the search/excerpts payload.
type stackResponse struct {
	Items []struct {
		Body    string `json:"body"`
		Excerpt string `json:"excerpt"`
	} `json:"items"`
}

// HandleEvent runs a /search/excerpts query and harvests emails.
func (m *StackOverflow) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	u := "https://api.stackexchange.com/2.3/search/excerpts?order=desc&q=" + url.QueryEscape(evt.Data) + "&site=stackoverflow"
	resp, err := searchAPIClient.FetchURL(ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Transient failures above fall through to the defer which releases
	// the reservation so a later event for the same indicator can retry.
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "stackoverflow", evt); err == nil {
		results = append(results, e)
	}
	var payload stackResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return results, nil
	}
	target := strings.ToLower(evt.Data)
	emitted := make(map[string]bool)
	for _, it := range payload.Items {
		text := it.Body + "\n" + it.Excerpt
		for _, addr := range sflib.ExtractEmails(text) {
			addr = strings.ToLower(addr)
			if emitted[addr] {
				continue
			}
			emitted[addr] = true
			typ := event.AFFILIATE_EMAILADDR
			if at := strings.LastIndex(addr, "@"); at != -1 && hostMatchesTarget(addr[at+1:], target) {
				typ = event.EMAILADDR
			}
			if e, err := event.New(typ, addr, "stackoverflow", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *StackOverflow) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// SearchCode
// ============================================================================

// SearchCode queries searchcode.com for code snippets mentioning the target
// domain. URLs and emails are extracted from each result.
type SearchCode struct{ seen seenSet }

// Meta returns module metadata.
func (m *SearchCode) Meta() module.Meta {
	return module.Meta{Name: "searchcode", Summary: "Search searchcode.com for code referencing a target domain.", Categories: []string{"Search Engines"}}
}

// Setup initializes internal state.
func (m *SearchCode) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *SearchCode) WatchedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

// ProducedEvents returns emitted event types.
func (m *SearchCode) ProducedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.LINKED_URL_INTERNAL, event.RAW_RIR_DATA, event.INTERNET_NAME}
}

// searchcodeResponse is the relevant subset of the codesearch_I payload.
type searchcodeResponse struct {
	Results []struct {
		Repo  string         `json:"repo"`
		URL   string         `json:"url"`
		Lines map[string]any `json:"lines"`
	} `json:"results"`
}

// HandleEvent fetches first page of search results and harvests data.
func (m *SearchCode) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	target := strings.ToLower(evt.Data)
	u := "https://searchcode.com/api/codesearch_I/?q=" + url.QueryEscape(evt.Data) + "&p=0&per_page=20"
	resp, err := searchAPIClient.FetchURL(ctx, u)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Transient failures above fall through to the defer which releases
	// the reservation so a later event for the same indicator can retry.
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "searchcode", evt); err == nil {
		results = append(results, e)
	}
	var payload searchcodeResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return results, nil
	}
	emittedURL := make(map[string]bool)
	emittedEmail := make(map[string]bool)
	for _, r := range payload.Results {
		var snippet strings.Builder
		for _, v := range r.Lines {
			if s, ok := v.(string); ok {
				snippet.WriteString(s)
				snippet.WriteString("\n")
			}
		}
		body := snippet.String()
		for _, addr := range sflib.ExtractEmails(body) {
			addr = strings.ToLower(addr)
			at := strings.LastIndex(addr, "@")
			if at == -1 || !hostMatchesTarget(addr[at+1:], target) {
				continue
			}
			if emittedEmail[addr] {
				continue
			}
			emittedEmail[addr] = true
			if e, err := event.New(event.EMAILADDR, addr, "searchcode", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, link := range sflib.ExtractURLs(body) {
			if !urlInTargetScope(link, target) || emittedURL[link] {
				continue
			}
			emittedURL[link] = true
			if e, err := event.New(event.LINKED_URL_INTERNAL, link, "searchcode", evt); err == nil {
				results = append(results, e)
			}
		}
		if r.URL != "" && urlInTargetScope(r.URL, target) && !emittedURL[r.URL] {
			emittedURL[r.URL] = true
			if e, err := event.New(event.LINKED_URL_INTERNAL, r.URL, "searchcode", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *SearchCode) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registrations
// ============================================================================

func init() {
	module.Register("googlesearch", func() module.Module { return &GoogleSearch{} })
	module.Register("bingsearch", func() module.Module { return &BingSearch{} })
	module.Register("duckduckgo", func() module.Module { return &DuckDuckGo{} })
	module.Register("sublist3r", func() module.Module { return &Sublist3r{} })
	module.Register("stackoverflow", func() module.Module { return &StackOverflow{} })
	module.Register("searchcode", func() module.Module { return &SearchCode{} })
}
