// Package modules — Batch 13: Major commercial and free APIs Part 2.
//
// This file implements pragmatic ports of:
//   - riskiq      (api.passivetotal.org PDNS keyword search, Basic auth, POST)
//   - intelx      (2.intelx.io /intelligent/search, x-key header, POST)
//   - dehashed    (api.dehashed.com /search, Basic auth, GET)
//   - leakix      (leakix.net /host|/domain, api-key header, GET)
//   - threatfox   (threatfox-api.abuse.ch /api/v1/, no auth, POST)
//   - urlscan     (urlscan.io /api/v1/search/, no auth, GET)
//   - xforce      (api.xforce.ibmcloud.com /ipr/malware/, Basic auth, GET)
//
// All modules reuse the Batch 11-12 API key convention (vendor
// prefixed opt keys, no generic api_key fallback) and use shared
// helpers from major_apis.go: majorAPIFetch, majorAPIFetchPOST,
// basicAuthHeader, sfURL, seenSet, optString. threatfox and urlscan
// are free and require no API key — their Meta.RequiresAPIKey is
// the zero-value false.

package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// ============================================================================
// RiskIQ (PassiveTotal)
// ============================================================================

// RiskIQ queries api.passivetotal.org for passive DNS keyword search.
// Requires opts["riskiq_api_key_login"] and opts["riskiq_api_key_password"].
type RiskIQ struct {
	seen     seenSet
	login    string
	password string
}

// Meta returns module metadata.
func (m *RiskIQ) Meta() module.Meta {
	return module.Meta{
		Name:           "riskiq",
		Summary:        "Query RiskIQ PassiveTotal for passive DNS keyword searches.",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads both credentials from opts.
func (m *RiskIQ) Setup(opts map[string]any) error {
	m.login = optString(opts, "riskiq_api_key_login", "")
	m.password = optString(opts, "riskiq_api_key_password", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *RiskIQ) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *RiskIQ) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.CO_HOSTED_SITE, event.RAW_RIR_DATA}
}

// riskIQResp is the relevant subset of the PDNS keyword search response.
type riskIQResp struct {
	Results []struct {
		FocusPoint string `json:"focusPoint"`
	} `json:"results"`
}

// HandleEvent queries RiskIQ for keyword matches.
func (m *RiskIQ) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.login == "" || m.password == "" {
		return nil, nil
	}

	reqBody, err := json.Marshal(map[string]any{"query": evt.Data})
	if err != nil {
		return nil, nil
	}
	body, ok := majorAPIFetchPOST(ctx, "https://api.passivetotal.org/v2/dns/search/keyword", func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.login, m.password))
	}, reqBody)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp riskIQResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "riskiq", evt); err == nil {
		results = append(results, e)
	}
	for _, r := range resp.Results {
		host := strings.TrimSpace(r.FocusPoint)
		if host == "" {
			continue
		}
		if e, err := event.New(event.INTERNET_NAME, host, "riskiq", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *RiskIQ) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// IntelX
// ============================================================================

// IntelX queries 2.intelx.io intelligent search for leaked data
// mentions. Requires opts["intelx_api_key"].
type IntelX struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IntelX) Meta() module.Meta {
	return module.Meta{
		Name:           "intelx",
		Summary:        "Search Intelligence X for leaks and darknet mentions of a selector.",
		Categories:     []string{"Leaks, Dumps and Breaches"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IntelX) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "intelx_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IntelX) WatchedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.INTERNET_NAME, event.DOMAIN_NAME, event.PHONE_NUMBER, event.BITCOIN_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *IntelX) ProducedEvents() []event.Type {
	return []event.Type{event.LEAKSITE_URL, event.DARKNET_MENTION_URL, event.RAW_RIR_DATA}
}

// intelxRecord is the relevant subset of one record in the intelx
// intelligent search results array.
type intelxRecord struct {
	Bucket    string `json:"bucket"`
	Name      string `json:"name"`
	KeyValues []struct {
		Value string `json:"value"`
	} `json:"keyvalues"`
}

// intelxResp is the top-level /intelligent/search response.
type intelxResp struct {
	Records []intelxRecord `json:"records"`
}

// HandleEvent queries IntelX for the given selector.
func (m *IntelX) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
		"term":        evt.Data,
		"buckets":     []string{},
		"lookuplevel": 0,
		"maxresults":  100,
		"timeout":     20,
		"datefrom":    "",
		"dateto":      "",
		"sort":        4,
		"media":       0,
		"terminate":   []any{},
	})
	if err != nil {
		return nil, nil
	}
	body, ok := majorAPIFetchPOST(ctx, "https://2.intelx.io/intelligent/search", func(h http.Header) {
		h.Set("x-key", m.apiKey)
	}, reqBody)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp intelxResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "intelx", evt); err == nil {
		results = append(results, e)
	}
	for _, rec := range resp.Records {
		var target string
		if len(rec.KeyValues) > 0 {
			target = rec.KeyValues[0].Value
		}
		if target == "" {
			target = rec.Name
		}
		if target == "" {
			continue
		}
		evType := event.LEAKSITE_URL
		if strings.HasPrefix(strings.ToLower(rec.Bucket), "darknet") {
			evType = event.DARKNET_MENTION_URL
		}
		if e, err := event.New(evType, target, "intelx", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *IntelX) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Dehashed
// ============================================================================

// Dehashed queries api.dehashed.com for compromised credentials.
// Requires opts["dehashed_api_key_username"] and opts["dehashed_api_key"].
type Dehashed struct {
	seen     seenSet
	username string
	apiKey   string
}

// Meta returns module metadata.
func (m *Dehashed) Meta() module.Meta {
	return module.Meta{
		Name:           "dehashed",
		Summary:        "Search Dehashed.com for leaked credentials associated with an email or domain.",
		Categories:     []string{"Leaks, Dumps and Breaches"},
		RequiresAPIKey: true,
	}
}

// Setup reads credentials from opts.
func (m *Dehashed) Setup(opts map[string]any) error {
	m.username = optString(opts, "dehashed_api_key_username", "")
	m.apiKey = optString(opts, "dehashed_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Dehashed) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.EMAILADDR}
}

// ProducedEvents returns emitted event types.
func (m *Dehashed) ProducedEvents() []event.Type {
	return []event.Type{
		event.EMAILADDR_COMPROMISED,
		event.PASSWORD_COMPROMISED,
		event.HASH_COMPROMISED,
		event.RAW_RIR_DATA,
	}
}

// dehashedResp is the relevant subset of the Dehashed search response.
type dehashedResp struct {
	Entries []struct {
		Email          string `json:"email"`
		Password       string `json:"password"`
		HashedPassword string `json:"hashed_password"`
		DatabaseName   string `json:"database_name"`
	} `json:"entries"`
}

// HandleEvent queries Dehashed for the given selector.
func (m *Dehashed) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.username == "" || m.apiKey == "" {
		return nil, nil
	}

	var q string
	if evt.Type == event.EMAILADDR {
		q = `email:"` + evt.Data + `"`
	} else {
		q = `email:"@` + evt.Data + `"`
	}
	u := "https://api.dehashed.com/search?query=" + url.QueryEscape(q) + "&size=10000"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.username, m.apiKey))
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp dehashedResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "dehashed", evt); err == nil {
		results = append(results, e)
	}
	for _, row := range resp.Entries {
		src := row.DatabaseName
		if src == "" {
			src = "Unknown"
		}
		if row.Email != "" {
			data := row.Email + " [" + src + "]"
			if e, err := event.New(event.EMAILADDR_COMPROMISED, data, "dehashed", evt); err == nil {
				results = append(results, e)
			}
		}
		if row.Password != "" {
			data := row.Email + ":" + row.Password + " [" + src + "]"
			if e, err := event.New(event.PASSWORD_COMPROMISED, data, "dehashed", evt); err == nil {
				results = append(results, e)
			}
		}
		if row.HashedPassword != "" {
			data := row.Email + ":" + row.HashedPassword + " [" + src + "]"
			if e, err := event.New(event.HASH_COMPROMISED, data, "dehashed", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Dehashed) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// LeakIX
// ============================================================================

// LeakIX queries leakix.net for host/domain exposure information.
// Requires opts["leakix_api_key"].
type LeakIX struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *LeakIX) Meta() module.Meta {
	return module.Meta{
		Name:           "leakix",
		Summary:        "Query LeakIX for host and domain exposure information.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *LeakIX) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "leakix_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *LeakIX) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *LeakIX) ProducedEvents() []event.Type {
	return []event.Type{
		event.TCP_PORT_OPEN,
		event.WEBSERVER_BANNER,
		event.SOFTWARE_USED,
		event.OPERATING_SYSTEM,
		event.GEOINFO,
		event.INTERNET_NAME,
		event.RAW_RIR_DATA,
	}
}

// leakixService is one entry of Services.
type leakixService struct {
	Host    string              `json:"host"`
	IP      string              `json:"ip"`
	Port    int                 `json:"port"`
	Headers map[string][]string `json:"headers"`
	GeoIP   struct {
		City    string `json:"city_name"`
		Country string `json:"country_name"`
	} `json:"geoip"`
	Software struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		OS      string `json:"os"`
	} `json:"software"`
}

// leakixResp is the relevant subset of /host/{ip} or /domain/{d}.
type leakixResp struct {
	Services []leakixService `json:"Services"`
}

// HandleEvent queries LeakIX for the given host or domain.
func (m *LeakIX) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
		u = "https://leakix.net/host/" + url.PathEscape(evt.Data)
	} else {
		u = "https://leakix.net/domain/" + url.PathEscape(evt.Data)
	}
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("api-key", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp leakixResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "leakix", evt); err == nil {
		results = append(results, e)
	}
	emittedPort := make(map[int]bool)
	emittedHost := make(map[string]bool)
	for _, s := range resp.Services {
		if s.Port > 0 && !emittedPort[s.Port] {
			emittedPort[s.Port] = true
			portStr := fmt.Sprintf("%s:%d", evt.Data, s.Port)
			if e, err := event.New(event.TCP_PORT_OPEN, portStr, "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
		if servers, ok := s.Headers["Server"]; ok && len(servers) > 0 {
			if e, err := event.New(event.WEBSERVER_BANNER, servers[0], "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
		swStr := strings.TrimSpace(s.Software.Name + " " + s.Software.Version)
		if swStr != "" {
			if e, err := event.New(event.SOFTWARE_USED, swStr, "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
		if s.Software.OS != "" {
			if e, err := event.New(event.OPERATING_SYSTEM, s.Software.OS, "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
		if s.GeoIP.Country != "" {
			geo := s.GeoIP.Country
			if s.GeoIP.City != "" {
				geo = s.GeoIP.City + ", " + s.GeoIP.Country
			}
			if e, err := event.New(event.GEOINFO, geo, "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
		if s.Host != "" && !emittedHost[s.Host] {
			emittedHost[s.Host] = true
			if e, err := event.New(event.INTERNET_NAME, s.Host, "leakix", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *LeakIX) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// ThreatFox
// ============================================================================

// ThreatFox queries abuse.ch's ThreatFox for IOC matches. No API key required.
type ThreatFox struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *ThreatFox) Meta() module.Meta {
	return module.Meta{
		Name:       "threatfox",
		Summary:    "Check if an IP address is a known IOC in abuse.ch ThreatFox.",
		Categories: []string{"Reputation Systems"},
	}
}

// Setup is a no-op — ThreatFox is unauthenticated.
func (m *ThreatFox) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *ThreatFox) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *ThreatFox) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.BLACKLISTED_IPADDR,
		event.BLACKLISTED_AFFILIATE_IPADDR,
	}
}

// threatFoxResp is the relevant subset of /api/v1/ search_ioc response.
type threatFoxResp struct {
	QueryStatus string `json:"query_status"`
	Data        []any  `json:"data"`
}

// HandleEvent queries ThreatFox for the given IP.
func (m *ThreatFox) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	reqBody, err := json.Marshal(map[string]any{
		"query":       "search_ioc",
		"search_term": evt.Data,
	})
	if err != nil {
		return nil, nil
	}
	body, ok := majorAPIFetchPOST(ctx, "https://threatfox-api.abuse.ch/api/v1/", nil, reqBody)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp threatFoxResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if resp.QueryStatus != "ok" || len(resp.Data) == 0 {
		return nil, nil
	}
	data := sfURL("ThreatFox ["+evt.Data+"]",
		"https://threatfox.abuse.ch/browse.php?search=ioc:"+url.QueryEscape(evt.Data))
	malType := event.MALICIOUS_IPADDR
	blType := event.BLACKLISTED_IPADDR
	if evt.Type == event.AFFILIATE_IPADDR {
		malType = event.MALICIOUS_AFFILIATE_IPADDR
		blType = event.BLACKLISTED_AFFILIATE_IPADDR
	}
	var results []*event.Event
	if e, err := event.New(blType, data, "threatfox", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(malType, data, "threatfox", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *ThreatFox) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// URLScan
// ============================================================================

// URLScan queries urlscan.io search for domain information. No API key required.
type URLScan struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *URLScan) Meta() module.Meta {
	return module.Meta{
		Name:       "urlscan",
		Summary:    "Query urlscan.io for historical scan data about a domain.",
		Categories: []string{"Search Engines"},
	}
}

// Setup is a no-op — URLScan search is unauthenticated.
func (m *URLScan) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *URLScan) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *URLScan) ProducedEvents() []event.Type {
	return []event.Type{
		event.GEOINFO,
		event.BGP_AS_MEMBER,
		event.WEBSERVER_BANNER,
		event.LINKED_URL_INTERNAL,
		event.RAW_RIR_DATA,
	}
}

// urlscanResp is the relevant subset of /api/v1/search/.
type urlscanResp struct {
	Results []struct {
		Page struct {
			Domain  string `json:"domain"`
			ASN     string `json:"asn"`
			City    string `json:"city"`
			Country string `json:"country"`
			Server  string `json:"server"`
		} `json:"page"`
		Task struct {
			URL string `json:"url"`
		} `json:"task"`
	} `json:"results"`
}

// HandleEvent queries URLScan for the given domain.
func (m *URLScan) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://urlscan.io/api/v1/search/?q=" + url.QueryEscape("domain:"+evt.Data)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp urlscanResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "urlscan", evt); err == nil {
		results = append(results, e)
	}
	emittedGeo := make(map[string]bool)
	emittedASN := make(map[string]bool)
	emittedSrv := make(map[string]bool)
	emittedURL := make(map[string]bool)
	for _, r := range resp.Results {
		if r.Page.Country != "" {
			geo := r.Page.Country
			if r.Page.City != "" {
				geo = r.Page.City + ", " + r.Page.Country
			}
			if !emittedGeo[geo] {
				emittedGeo[geo] = true
				if e, err := event.New(event.GEOINFO, geo, "urlscan", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		if r.Page.ASN != "" {
			asn := strings.TrimPrefix(r.Page.ASN, "AS")
			if !emittedASN[asn] {
				emittedASN[asn] = true
				if e, err := event.New(event.BGP_AS_MEMBER, asn, "urlscan", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		if r.Page.Server != "" && !emittedSrv[r.Page.Server] {
			emittedSrv[r.Page.Server] = true
			if e, err := event.New(event.WEBSERVER_BANNER, r.Page.Server, "urlscan", evt); err == nil {
				results = append(results, e)
			}
		}
		if r.Task.URL != "" && !emittedURL[r.Task.URL] {
			emittedURL[r.Task.URL] = true
			if e, err := event.New(event.LINKED_URL_INTERNAL, r.Task.URL, "urlscan", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *URLScan) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// XForce
// ============================================================================

// XForce queries api.xforce.ibmcloud.com for IP reputation. Requires
// opts["xforce_api_key"] and opts["xforce_api_key_password"].
type XForce struct {
	seen     seenSet
	apiKey   string
	password string
}

// Meta returns module metadata.
func (m *XForce) Meta() module.Meta {
	return module.Meta{
		Name:           "xforce",
		Summary:        "Obtain reputation information from IBM X-Force Exchange.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads both credentials from opts.
func (m *XForce) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "xforce_api_key", "")
	m.password = optString(opts, "xforce_api_key_password", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *XForce) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *XForce) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.RAW_RIR_DATA,
	}
}

// xforceResp is the relevant subset of /ipr/malware/{ip}.
type xforceResp struct {
	Malware []any `json:"malware"`
}

// HandleEvent queries X-Force for malware history of the given IP.
func (m *XForce) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.apiKey == "" || m.password == "" {
		return nil, nil
	}

	u := "https://api.xforce.ibmcloud.com/ipr/malware/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.apiKey, m.password))
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp xforceResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if len(resp.Malware) == 0 {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "xforce", evt); err == nil {
		results = append(results, e)
	}
	data := sfURL("X-Force ["+evt.Data+"]",
		"https://exchange.xforce.ibmcloud.com/ip/"+url.PathEscape(evt.Data))
	malType := event.MALICIOUS_IPADDR
	if evt.Type == event.AFFILIATE_IPADDR {
		malType = event.MALICIOUS_AFFILIATE_IPADDR
	}
	if e, err := event.New(malType, data, "xforce", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *XForce) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("riskiq", func() module.Module { return &RiskIQ{} })
	module.Register("intelx", func() module.Module { return &IntelX{} })
	module.Register("dehashed", func() module.Module { return &Dehashed{} })
	module.Register("leakix", func() module.Module { return &LeakIX{} })
	module.Register("threatfox", func() module.Module { return &ThreatFox{} })
	module.Register("urlscan", func() module.Module { return &URLScan{} })
	module.Register("xforce", func() module.Module { return &XForce{} })
}
