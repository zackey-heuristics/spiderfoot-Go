// Package modules — Batch 14: Security / Threat Intelligence modules.
//
// This file implements pragmatic ports of:
//   - googlesafebrowsing (safebrowsing.googleapis.com /v4/threatMatches:find, key query param, POST)
//   - metadefender       (api.metadefender.com /v4/ip|/v4/domain, apikey header, GET)
//   - hybrid_analysis    (www.hybrid-analysis.com /api/v2/search/terms|/search/hash, api-key header, form POST)
//   - openbugbounty      (www.openbugbounty.org /search/, no auth, HTML scrape)
//
// All modules follow the Batches 11-13 conventions: vendor-prefixed opt
// keys with no generic api_key fallback, seenSet.begin keyed on
// evt.Type+":"+evt.Data, committed set only after JSON/body parse
// succeeds, and url.PathEscape/url.QueryEscape for user-controlled
// URL segments. Shared helpers majorAPIFetch, majorAPIFetchPOST,
// sfURL, optString, seenSet come from major_apis.go and free_apis.go.

package modules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// ============================================================================
// Google Safe Browsing
// ============================================================================

// GoogleSafeBrowsing checks targets against Google Safe Browsing v4
// threatMatches:find. Requires opts["googlesafebrowsing_api_key"].
type GoogleSafeBrowsing struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *GoogleSafeBrowsing) Meta() module.Meta {
	return module.Meta{
		Name:           "googlesafebrowsing",
		Summary:        "Check if a host or IP is listed on any Google Safe Browsing list.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *GoogleSafeBrowsing) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "googlesafebrowsing_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *GoogleSafeBrowsing) WatchedEvents() []event.Type {
	return []event.Type{
		event.INTERNET_NAME,
		event.IP_ADDRESS,
		event.AFFILIATE_INTERNET_NAME,
		event.AFFILIATE_IPADDR,
		event.CO_HOSTED_SITE,
	}
}

// ProducedEvents returns emitted event types.
func (m *GoogleSafeBrowsing) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_INTERNET_NAME,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.MALICIOUS_AFFILIATE_INTERNET_NAME,
		event.MALICIOUS_COHOST,
		event.RAW_RIR_DATA,
	}
}

// gsbMatch is a minimal subset of one entry in the matches array.
type gsbMatch struct {
	ThreatType string `json:"threatType"`
}

// gsbResp is the relevant subset of threatMatches:find response.
type gsbResp struct {
	Matches []gsbMatch `json:"matches"`
}

// HandleEvent queries Google Safe Browsing.
func (m *GoogleSafeBrowsing) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	reqBody, err := json.Marshal(map[string]any{
		"client": map[string]string{"clientId": "SpiderFoot", "clientVersion": "3.2"},
		"threatInfo": map[string]any{
			"threatTypes": []string{
				"THREAT_TYPE_UNSPECIFIED",
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFUL_APPLICATION",
			},
			"platformTypes":    []string{"PLATFORM_TYPE_UNSPECIFIED", "ANY_PLATFORM"},
			"threatEntryTypes": []string{"THREAT_ENTRY_TYPE_UNSPECIFIED", "URL", "EXECUTABLE"},
			"threatEntries":    []map[string]string{{"url": evt.Data}},
		},
	})
	if err != nil {
		return nil, nil
	}
	u := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetchPOST(ctx, u, nil, reqBody)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp gsbResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if len(resp.Matches) == 0 {
		return nil, nil
	}

	var evType event.Type
	switch evt.Type {
	case event.IP_ADDRESS:
		evType = event.MALICIOUS_IPADDR
	case event.AFFILIATE_IPADDR:
		evType = event.MALICIOUS_AFFILIATE_IPADDR
	case event.INTERNET_NAME:
		evType = event.MALICIOUS_INTERNET_NAME
	case event.AFFILIATE_INTERNET_NAME:
		evType = event.MALICIOUS_AFFILIATE_INTERNET_NAME
	case event.CO_HOSTED_SITE:
		evType = event.MALICIOUS_COHOST
	default:
		return nil, nil
	}

	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "googlesafebrowsing", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(evType, "Google SafeBrowsing ["+evt.Data+"]", "googlesafebrowsing", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *GoogleSafeBrowsing) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// MetaDefender
// ============================================================================

// MetaDefender queries api.metadefender.com for IP / domain reputation.
// Requires opts["metadefender_api_key"].
type MetaDefender struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *MetaDefender) Meta() module.Meta {
	return module.Meta{
		Name:           "metadefender",
		Summary:        "Query MetaDefender Cloud for IP and domain reputation.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *MetaDefender) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "metadefender_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *MetaDefender) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *MetaDefender) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_INTERNET_NAME,
		event.BLACKLISTED_IPADDR,
		event.BLACKLISTED_INTERNET_NAME,
		event.GEOINFO,
	}
}

// metaDefenderSource is one reputation provider entry.
type metaDefenderSource struct {
	Assessment string `json:"assessment"`
	Provider   string `json:"provider"`
}

// metaDefenderResp is the relevant subset of the v4 reputation response.
type metaDefenderResp struct {
	GeoInfo *struct {
		City struct {
			Name string `json:"name"`
		} `json:"city"`
		Country struct {
			Name string `json:"name"`
		} `json:"country"`
	} `json:"geo_info"`
	LookupResults *struct {
		Sources []metaDefenderSource `json:"sources"`
	} `json:"lookup_results"`
}

// HandleEvent queries MetaDefender for the given selector.
func (m *MetaDefender) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var u string
	if evt.Type == event.IP_ADDRESS {
		u = "https://api.metadefender.com/v4/ip/" + url.PathEscape(evt.Data)
	} else {
		u = "https://api.metadefender.com/v4/domain/" + url.PathEscape(evt.Data)
	}
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("apikey", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp metaDefenderResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if evt.Type == event.IP_ADDRESS && resp.GeoInfo != nil {
		city := resp.GeoInfo.City.Name
		country := resp.GeoInfo.Country.Name
		var loc string
		switch {
		case city != "" && country != "":
			loc = city + ", " + country
		case country != "":
			loc = country
		case city != "":
			loc = city
		}
		if loc != "" {
			if e, err := event.New(event.GEOINFO, loc, "metadefender", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	if resp.LookupResults == nil {
		return results, nil
	}
	malType := event.MALICIOUS_IPADDR
	blType := event.BLACKLISTED_IPADDR
	if evt.Type != event.IP_ADDRESS {
		malType = event.MALICIOUS_INTERNET_NAME
		blType = event.BLACKLISTED_INTERNET_NAME
	}
	for _, s := range resp.LookupResults.Sources {
		if s.Assessment == "" || s.Assessment == "trustworthy" {
			continue
		}
		if s.Provider == "" {
			continue
		}
		data := s.Provider + " [" + evt.Data + "]"
		if e, err := event.New(malType, data, "metadefender", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(blType, data, "metadefender", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *MetaDefender) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Hybrid Analysis
// ============================================================================

// HybridAnalysis searches www.hybrid-analysis.com for domains and
// URLs related to the target. Requires opts["hybrid_analysis_api_key"].
type HybridAnalysis struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *HybridAnalysis) Meta() module.Meta {
	return module.Meta{
		Name:           "hybridanalysis",
		Summary:        "Search Hybrid Analysis for domains and URLs related to the target.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *HybridAnalysis) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "hybridanalysis_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *HybridAnalysis) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *HybridAnalysis) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.INTERNET_NAME, event.LINKED_URL_INTERNAL}
}

// hybridAnalysisTermsResp is the /search/terms response subset.
type hybridAnalysisTermsResp struct {
	Result []struct {
		SHA256 string `json:"sha256"`
	} `json:"result"`
}

// hybridAnalysisHashEntry is one entry of the /search/hash array.
type hybridAnalysisHashEntry struct {
	Domains     []string `json:"domains"`
	Submissions []struct {
		URL string `json:"url"`
	} `json:"submissions"`
}

// postHybridForm performs a form-encoded POST to rawURL with the
// supplied form values and the api-key header. Returns the body on 200.
func postHybridForm(ctx context.Context, rawURL, apiKey string, form url.Values) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Falcon Sandbox")
	req.Header.Set("api-key", apiKey)
	resp, err := majorAPIHTTPClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, majorAPIMaxBody))
	if err != nil {
		return nil, false
	}
	return b, true
}

// HandleEvent queries Hybrid Analysis for hashes related to the
// selector, then resolves each hash to domains and URLs.
func (m *HybridAnalysis) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	form := url.Values{}
	if evt.Type == event.IP_ADDRESS {
		form.Set("host", evt.Data)
	} else {
		form.Set("domain", evt.Data)
	}
	body, ok := postHybridForm(ctx, "https://www.hybrid-analysis.com/api/v2/search/terms", m.apiKey, form)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var termsResp hybridAnalysisTermsResp
	if err := json.Unmarshal(body, &termsResp); err != nil {
		return nil, nil
	}
	committed = true
	if len(termsResp.Result) == 0 {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "hybridanalysis", evt); err == nil {
		results = append(results, e)
	}

	emittedDomains := make(map[string]bool)
	emittedURLs := make(map[string]bool)
	seenHash := make(map[string]bool)
	for _, r := range termsResp.Result {
		h := r.SHA256
		if h == "" || seenHash[h] {
			continue
		}
		seenHash[h] = true
		hashForm := url.Values{}
		hashForm.Set("hash", h)
		hashBody, ok := postHybridForm(ctx, "https://www.hybrid-analysis.com/api/v2/search/hash", m.apiKey, hashForm)
		if !ok || len(hashBody) == 0 {
			continue
		}
		var entries []hybridAnalysisHashEntry
		if err := json.Unmarshal(hashBody, &entries); err != nil {
			continue
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(hashBody), "hybridanalysis", evt); err == nil {
			results = append(results, e)
		}
		for _, en := range entries {
			for _, d := range en.Domains {
				d = strings.TrimSpace(d)
				if d == "" || emittedDomains[d] {
					continue
				}
				emittedDomains[d] = true
				if e, err := event.New(event.INTERNET_NAME, d, "hybridanalysis", evt); err == nil {
					results = append(results, e)
				}
			}
			for _, s := range en.Submissions {
				u := strings.TrimSpace(s.URL)
				if u == "" || emittedURLs[u] {
					continue
				}
				emittedURLs[u] = true
				if e, err := event.New(event.LINKED_URL_INTERNAL, u, "hybridanalysis", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *HybridAnalysis) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Open Bug Bounty
// ============================================================================

// OpenBugBounty queries openbugbounty.org for vulnerability
// disclosures listed against the target domain. No API key required.
type OpenBugBounty struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *OpenBugBounty) Meta() module.Meta {
	return module.Meta{
		Name:       "openbugbounty",
		Summary:    "Check openbugbounty.org for publicly disclosed vulnerabilities against the target.",
		Categories: []string{"Leaks, Dumps and Breaches"},
	}
}

// Setup is a no-op — OpenBugBounty is unauthenticated.
func (m *OpenBugBounty) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *OpenBugBounty) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *OpenBugBounty) ProducedEvents() []event.Type {
	return []event.Type{event.VULNERABILITY_DISCLOSURE}
}

// openBugBountyRowRE matches an HTML result row on the search page:
//
//	<div class="cell1"><a href="/reports/xxx/">target.example.com</a></div>
//
// It is intentionally tolerant of attribute quoting variations because
// the Python version accepted any char in the attribute.
var openBugBountyRowRE = regexp.MustCompile(`(?is)<div class=.cell1.><a href=.([^"'>]+).>([^<]+)</a></div>`)

// HandleEvent scrapes openbugbounty.org search results for the host.
func (m *OpenBugBounty) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://www.openbugbounty.org/search/?search=" + url.QueryEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Accept", "text/html")
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	committed = true

	matches := openBugBountyRowRE.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	qry := strings.ToLower(evt.Data)
	var results []*event.Event
	seenLink := make(map[string]bool)
	for _, mm := range matches {
		href := string(mm[1])
		host := strings.ToLower(strings.TrimSpace(string(mm[2])))
		if host != qry && !strings.HasSuffix(host, "."+qry) {
			continue
		}
		link := "https://www.openbugbounty.org" + href
		if seenLink[link] {
			continue
		}
		seenLink[link] = true
		data := "From openbugbounty.org: " + sfURL("openbugbounty.org ["+evt.Data+"]", link)
		if e, err := event.New(event.VULNERABILITY_DISCLOSURE, data, "openbugbounty", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *OpenBugBounty) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("googlesafebrowsing", func() module.Module { return &GoogleSafeBrowsing{} })
	module.Register("metadefender", func() module.Module { return &MetaDefender{} })
	module.Register("hybridanalysis", func() module.Module { return &HybridAnalysis{} })
	module.Register("openbugbounty", func() module.Module { return &OpenBugBounty{} })
}
