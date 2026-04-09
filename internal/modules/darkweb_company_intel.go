// Package modules — Batch 20: Dark web search, company/crypto
// reputation, and network intel APIs.
//
// This file implements pragmatic ports of:
//   - ahmia             (https://ahmia.fi Tor search; free, no key)
//   - onionsearchengine (https://onionsearchengine.com; free, no key)
//   - bitcoinabuse      (bitcoinabuse.com address reputation; requires api_key)
//   - opencorporates    (api.opencorporates.com company search; requires api_key)
//   - onyphe            (api.onyphe.io IP reputation; requires api_key)
//   - zetalytics        (zonecruncher.com passive DNS; requires api_key)
//
// All keyed modules follow the vendor-prefixed opts convention
// (Batch 11+) and no-op without credentials. All requests use HTTPS.
// The seenSet reservation is committed only after a substantive parse
// succeeds on the documented response shape.

package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// ============================================================================
// Ahmia (Tor search engine, free)
// ============================================================================

// Ahmia searches ahmia.fi for darknet mentions of the target.
type Ahmia struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *Ahmia) Meta() module.Meta {
	return module.Meta{
		Name:       "ahmia",
		Summary:    "Search Tor 'Ahmia' search engine for mentions of the target.",
		Categories: []string{"Search Engines"},
	}
}

// Setup is a no-op.
func (m *Ahmia) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Ahmia) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.HUMAN_NAME, event.EMAILADDR}
}

// ProducedEvents returns emitted event types.
func (m *Ahmia) ProducedEvents() []event.Type {
	return []event.Type{event.DARKNET_MENTION_URL}
}

// ahmiaRedirectRE extracts the redirect_url target from the Ahmia HTML
// result page. Mirrors the Python regex verbatim.
var ahmiaRedirectRE = regexp.MustCompile(`redirect_url=([^"]+)"`)

// HandleEvent queries Ahmia for the given event.
func (m *Ahmia) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://ahmia.fi/search/?q=" + url.QueryEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	matches := ahmiaRedirectRE.FindAllStringSubmatch(string(body), -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var results []*event.Event
	emitted := map[string]bool{}
	for _, mm := range matches {
		link := mm[1]
		if emitted[link] {
			continue
		}
		emitted[link] = true
		if !strings.Contains(link, ".onion") {
			continue
		}
		if e, err := event.New(event.DARKNET_MENTION_URL, link, "ahmia", evt); err == nil {
			results = append(results, e)
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Ahmia) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Onionsearchengine (Tor search engine, free)
// ============================================================================

// OnionSearchEngine searches onionsearchengine.com for darknet mentions.
type OnionSearchEngine struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *OnionSearchEngine) Meta() module.Meta {
	return module.Meta{
		Name:       "onionsearchengine",
		Summary:    "Search Tor onionsearchengine.com for mentions of the target.",
		Categories: []string{"Search Engines"},
	}
}

// Setup is a no-op.
func (m *OnionSearchEngine) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *OnionSearchEngine) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.HUMAN_NAME, event.EMAILADDR}
}

// ProducedEvents returns emitted event types.
func (m *OnionSearchEngine) ProducedEvents() []event.Type {
	return []event.Type{event.DARKNET_MENTION_URL}
}

// onionSEURLRE extracts the unwrapped target from `url.php?u=...` links.
var onionSEURLRE = regexp.MustCompile(`url\.php\?u=([^"']+)["']`)

// onionSEMaxPages caps pagination to avoid a runaway upstream loop.
const onionSEMaxPages = 20

// HandleEvent queries onionsearchengine.com for the given target.
func (m *OnionSearchEngine) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	emitted := map[string]bool{}
	truncated := false
	for page := 1; page <= onionSEMaxPages; page++ {
		u := "https://onionsearchengine.com/search.php?search=" +
			url.QueryEscape(`"`+evt.Data+`"`) +
			"&submit=Search&page=" + itoa(page)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			break
		}
		content := string(body)
		if !strings.Contains(content, "url.php?u=") {
			break
		}
		matches := onionSEURLRE.FindAllStringSubmatch(content, -1)
		for _, mm := range matches {
			// The captured value is a query-parameter payload,
			// so it may be percent-encoded. Decode once and
			// reject anything that does not parse as an onion
			// URL with a host. See Codex adversarial review
			// 2026-04-09 — the pre-fix code emitted wrapped
			// values directly and produced non-canonical
			// DARKNET_MENTION_URL events.
			raw := mm[1]
			decoded, err := url.QueryUnescape(raw)
			if err != nil {
				continue
			}
			parsed, err := url.Parse(decoded)
			if err != nil || parsed.Host == "" {
				continue
			}
			if !strings.HasSuffix(parsed.Host, ".onion") {
				continue
			}
			canon := parsed.String()
			if emitted[canon] {
				continue
			}
			emitted[canon] = true
			if e, err := event.New(event.DARKNET_MENTION_URL, canon, "onionsearchengine", evt); err == nil {
				results = append(results, e)
			}
		}
		if !strings.Contains(content, "forward >") {
			break
		}
		if page == onionSEMaxPages {
			truncated = true
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	if truncated {
		if e, err := event.New(event.RAW_RIR_DATA,
			"onionsearchengine: pagination capped at "+itoa(onionSEMaxPages)+" pages; results may be incomplete",
			"onionsearchengine", evt); err == nil {
			results = append(results, e)
		}
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *OnionSearchEngine) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// BitcoinAbuse
// ============================================================================

// BitcoinAbuse checks Bitcoin addresses against bitcoinabuse.com.
// Requires opts["bitcoinabuse_api_key"].
type BitcoinAbuse struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *BitcoinAbuse) Meta() module.Meta {
	return module.Meta{
		Name:           "bitcoinabuse",
		Summary:        "Check Bitcoin addresses against the bitcoinabuse.com database of suspect/malicious addresses.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *BitcoinAbuse) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "bitcoinabuse_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *BitcoinAbuse) WatchedEvents() []event.Type { return []event.Type{event.BITCOIN_ADDRESS} }

// ProducedEvents returns emitted event types.
func (m *BitcoinAbuse) ProducedEvents() []event.Type {
	return []event.Type{event.MALICIOUS_BITCOIN_ADDRESS, event.RAW_RIR_DATA}
}

// bitcoinAbuseResp mirrors the documented BitcoinAbuse
// /api/reports/check response shape.
type bitcoinAbuseResp struct {
	Address string `json:"address"`
	Count   int    `json:"count"`
}

// HandleEvent queries bitcoinabuse.com for the given address.
func (m *BitcoinAbuse) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://www.bitcoinabuse.com/api/reports/check?address=" +
		url.QueryEscape(evt.Data) + "&api_token=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp bitcoinAbuseResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	// Commit only after verifying both documented success fields:
	// non-empty address AND non-zero report count.
	if resp.Address == "" || resp.Count <= 0 {
		return nil, nil
	}
	var results []*event.Event
	reportURL := "https://www.bitcoinabuse.com/reports/" + resp.Address
	if e, err := event.New(event.MALICIOUS_BITCOIN_ADDRESS,
		sfURL("BitcoinAbuse ["+resp.Address+"]", reportURL),
		"bitcoinabuse", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "bitcoinabuse", evt); err == nil {
		results = append(results, e)
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *BitcoinAbuse) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// OpenCorporates
// ============================================================================

// OpenCorporates looks up company information via api.opencorporates.com.
// Requires opts["opencorporates_api_key"] for unlimited access; without
// a key the module no-ops (the Python version allows 50 anon lookups
// per day, but we do not ship credentials to OpenCorporates silently).
type OpenCorporates struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *OpenCorporates) Meta() module.Meta {
	return module.Meta{
		Name:           "opencorporates",
		Summary:        "Look up company information from OpenCorporates.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *OpenCorporates) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "opencorporates_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *OpenCorporates) WatchedEvents() []event.Type { return []event.Type{event.COMPANY_NAME} }

// ProducedEvents returns emitted event types.
func (m *OpenCorporates) ProducedEvents() []event.Type {
	return []event.Type{event.COMPANY_NAME, event.PHYSICAL_ADDRESS, event.RAW_RIR_DATA}
}

// openCorpSearchResp mirrors the documented search response shape.
type openCorpSearchResp struct {
	Results struct {
		Companies []struct {
			Company openCorpCompany `json:"company"`
		} `json:"companies"`
	} `json:"results"`
}

// openCorpCompany mirrors a single company record.
type openCorpCompany struct {
	Name                    string `json:"name"`
	JurisdictionCode        string `json:"jurisdiction_code"`
	CompanyNumber           string `json:"company_number"`
	RegisteredAddressInFull string `json:"registered_address_in_full"`
	RegisteredAddress       struct {
		Country string `json:"country"`
	} `json:"registered_address"`
	PreviousNames []struct {
		CompanyName string `json:"company_name"`
	} `json:"previous_names"`
	Officers []struct {
		Name string `json:"name"`
	} `json:"officers"`
}

// HandleEvent queries OpenCorporates for the given company name.
func (m *OpenCorporates) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.opencorporates.com/v0.4/companies/search?q=" +
		url.QueryEscape(evt.Data+"*") +
		"&format=json&order=score&confidence=100&api_token=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp openCorpSearchResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if len(resp.Results.Companies) == 0 {
		return nil, nil
	}

	var results []*event.Event
	target := strings.ToLower(evt.Data)
	for _, c := range resp.Results.Companies {
		if strings.ToLower(c.Company.Name) != target {
			continue
		}
		results = append(results, extractOpenCorpDetails(c.Company, evt)...)
	}
	if len(results) == 0 {
		return nil, nil
	}
	committed = true
	return results, nil
}

// extractOpenCorpDetails mirrors the Python extractCompanyDetails helper.
func extractOpenCorpDetails(c openCorpCompany, src *event.Event) []*event.Event {
	var out []*event.Event
	loc := c.RegisteredAddressInFull
	if len(loc) >= 3 && len(loc) <= 100 {
		if country := c.RegisteredAddress.Country; country != "" && !strings.HasSuffix(loc, country) {
			loc += ", " + country
		}
		loc = strings.ReplaceAll(loc, "\n", ",")
		if e, err := event.New(event.PHYSICAL_ADDRESS, loc, "opencorporates", src); err == nil {
			out = append(out, e)
		}
	}
	for _, p := range c.PreviousNames {
		if p.CompanyName == "" {
			continue
		}
		if e, err := event.New(event.COMPANY_NAME, p.CompanyName, "opencorporates", src); err == nil {
			out = append(out, e)
		}
	}
	for _, o := range c.Officers {
		if o.Name == "" {
			continue
		}
		if e, err := event.New(event.RAW_RIR_DATA, "Possible full name: "+o.Name, "opencorporates", src); err == nil {
			out = append(out, e)
		}
	}
	return out
}

// Finish clears state.
func (m *OpenCorporates) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Onyphe
// ============================================================================

// Onyphe checks api.onyphe.io for geo/threatlist/vulnerabilities on an IP.
// Requires opts["onyphe_api_key"].
type Onyphe struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Onyphe) Meta() module.Meta {
	return module.Meta{
		Name:           "onyphe",
		Summary:        "Check Onyphe data (threat list, geo-location, vulnerabilities) about a given IP.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *Onyphe) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "onyphe_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Onyphe) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *Onyphe) ProducedEvents() []event.Type {
	return []event.Type{
		event.GEOINFO,
		event.PHYSICAL_COORDINATES,
		event.MALICIOUS_IPADDR,
		event.LEAKSITE_CONTENT,
		event.VULNERABILITY_GENERAL,
		event.RAW_RIR_DATA,
	}
}

// onypheResp mirrors the documented api.onyphe.io v2 simple endpoint shape.
type onypheResp struct {
	Status  string                   `json:"status"`
	Results []map[string]interface{} `json:"results"`
}

// onypheQuery GETs an Onyphe simple endpoint and parses the documented
// v2 response shape. Returns (nil,nil,false) on any failure, non-200,
// nok status, or empty results.
func (m *Onyphe) onypheQuery(ctx context.Context, endpoint, ip string) (*onypheResp, []byte, bool) {
	u := "https://www.onyphe.io/api/v2/simple/" + endpoint + "/" + url.PathEscape(ip) + "?page=1"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", "apikey "+m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil, false
	}
	var resp onypheResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, false
	}
	if resp.Status == "nok" {
		return nil, nil, false
	}
	if len(resp.Results) == 0 {
		return nil, nil, false
	}
	return &resp, body, true
}

// HandleEvent queries several Onyphe endpoints for the given IP.
func (m *Onyphe) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var results []*event.Event
	any := false
	sent := map[string]bool{}

	// geoloc
	if geo, raw, ok := m.onypheQuery(ctx, "geoloc", evt.Data); ok {
		any = true
		if e, err := event.New(event.RAW_RIR_DATA, string(raw), "onyphe", evt); err == nil {
			results = append(results, e)
		}
		for _, r := range geo.Results {
			city := asString(r["city"])
			country := asString(r["country"])
			parts := make([]string, 0, 2)
			if city != "" {
				parts = append(parts, city)
			}
			if country != "" {
				parts = append(parts, country)
			}
			loc := strings.Join(parts, ", ")
			if loc != "" && !sent["geo:"+loc] {
				sent["geo:"+loc] = true
				if e, err := event.New(event.GEOINFO, loc, "onyphe", evt); err == nil {
					results = append(results, e)
				}
			}
			coords := asString(r["location"])
			if coords != "" && !sent["coord:"+coords] {
				sent["coord:"+coords] = true
				if e, err := event.New(event.PHYSICAL_COORDINATES, coords, "onyphe", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	}

	// pastries
	if past, raw, ok := m.onypheQuery(ctx, "pastries", evt.Data); ok {
		any = true
		if e, err := event.New(event.RAW_RIR_DATA, string(raw), "onyphe", evt); err == nil {
			results = append(results, e)
		}
		for _, r := range past.Results {
			c := asString(r["content"])
			if c == "" || sent["paste:"+c] {
				continue
			}
			sent["paste:"+c] = true
			if e, err := event.New(event.LEAKSITE_CONTENT, c, "onyphe", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	// threatlist — MALICIOUS_IPADDR must carry the queried IP as
	// its canonical artifact value (see phishing_reputation.go
	// convention and Codex adversarial review 2026-04-09). The
	// threatlist label is preserved in the adjacent RAW_RIR_DATA
	// event's body. Dedup on the list label guards against
	// multiple list hits re-emitting the same IP.
	if tl, raw, ok := m.onypheQuery(ctx, "threatlist", evt.Data); ok {
		any = true
		if e, err := event.New(event.RAW_RIR_DATA, string(raw), "onyphe", evt); err == nil {
			results = append(results, e)
		}
		ipEmitted := false
		for _, r := range tl.Results {
			t := asString(r["threatlist"])
			if t == "" || sent["tl:"+t] {
				continue
			}
			sent["tl:"+t] = true
			if ipEmitted {
				continue
			}
			ipEmitted = true
			if e, err := event.New(event.MALICIOUS_IPADDR, evt.Data, "onyphe", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	// vulnscan
	if vs, raw, ok := m.onypheQuery(ctx, "vulnscan", evt.Data); ok {
		any = true
		if e, err := event.New(event.RAW_RIR_DATA, string(raw), "onyphe", evt); err == nil {
			results = append(results, e)
		}
		for _, r := range vs.Results {
			cves, ok := r["cve"].([]interface{})
			if !ok {
				continue
			}
			for _, c := range cves {
				s := asString(c)
				if s == "" || sent["cve:"+s] {
					continue
				}
				sent["cve:"+s] = true
				if e, err := event.New(event.VULNERABILITY_GENERAL, s, "onyphe", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	}

	if !any || len(results) == 0 {
		return nil, nil
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Onyphe) Finish() error { m.seen.clear(); return nil }

// asString safely converts an arbitrary interface{} to string.
func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ============================================================================
// Zetalytics
// ============================================================================

// Zetalytics queries zonecruncher.com (Zetalytics) for subdomain and
// email-to-domain data. Requires opts["zetalytics_api_key"].
type Zetalytics struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Zetalytics) Meta() module.Meta {
	return module.Meta{
		Name:           "zetalytics",
		Summary:        "Query the Zetalytics database for hosts on your target domain(s).",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *Zetalytics) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "zetalytics_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Zetalytics) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.DOMAIN_NAME, event.EMAILADDR}
}

// ProducedEvents returns emitted event types.
func (m *Zetalytics) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.AFFILIATE_DOMAIN_NAME, event.RAW_RIR_DATA}
}

// zetalyticsResp mirrors the documented response shape for all
// Zetalytics endpoints used here (/subdomains, /hostname, /email_domain,
// /email_address): a results list where each entry is a dict with
// either a "qname" (hostname queries) or "d" (email-domain queries).
type zetalyticsResp struct {
	Results []struct {
		QName string `json:"qname"`
		D     string `json:"d"`
	} `json:"results"`
}

// zetaQuery GETs a Zetalytics endpoint with the shared token param.
func (m *Zetalytics) zetaQuery(ctx context.Context, path, q string) (*zetalyticsResp, []byte, bool) {
	u := "https://zonecruncher.com/api/v1" + path + "/?q=" + url.QueryEscape(q) +
		"&token=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil, false
	}
	var resp zetalyticsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, false
	}
	return &resp, body, true
}

// HandleEvent dispatches to the relevant Zetalytics endpoint.
func (m *Zetalytics) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var results []*event.Event
	target := strings.ToLower(evt.Data)

	emitHost := func(name string) {
		name = strings.ToLower(strings.TrimRight(name, "."))
		if name == "" {
			return
		}
		if name == target || strings.HasSuffix(name, "."+target) {
			if e, err := event.New(event.INTERNET_NAME, name, "zetalytics", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	switch evt.Type {
	case event.INTERNET_NAME:
		resp, raw, ok := m.zetaQuery(ctx, "/hostname", evt.Data)
		if !ok || len(resp.Results) == 0 {
			return nil, nil
		}
		for _, r := range resp.Results {
			emitHost(r.QName)
		}
		if len(results) > 0 {
			if e, err := event.New(event.RAW_RIR_DATA, string(raw), "zetalytics", evt); err == nil {
				results = append(results, e)
			}
		}
	case event.DOMAIN_NAME:
		resp, raw, ok := m.zetaQuery(ctx, "/subdomains", evt.Data)
		if ok && len(resp.Results) > 0 {
			before := len(results)
			for _, r := range resp.Results {
				emitHost(r.QName)
			}
			if len(results) > before {
				if e, err := event.New(event.RAW_RIR_DATA, string(raw), "zetalytics", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		if resp2, raw2, ok2 := m.zetaQuery(ctx, "/email_domain", evt.Data); ok2 && len(resp2.Results) > 0 {
			before := len(results)
			for _, r := range resp2.Results {
				d := strings.ToLower(r.D)
				if d == "" {
					continue
				}
				if e, err := event.New(event.AFFILIATE_DOMAIN_NAME, d, "zetalytics", evt); err == nil {
					results = append(results, e)
				}
			}
			if len(results) > before {
				if e, err := event.New(event.RAW_RIR_DATA, string(raw2), "zetalytics", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	case event.EMAILADDR:
		resp, raw, ok := m.zetaQuery(ctx, "/email_address", evt.Data)
		if !ok || len(resp.Results) == 0 {
			return nil, nil
		}
		for _, r := range resp.Results {
			d := strings.ToLower(r.D)
			if d == "" {
				continue
			}
			if e, err := event.New(event.AFFILIATE_DOMAIN_NAME, d, "zetalytics", evt); err == nil {
				results = append(results, e)
			}
		}
		if len(results) > 0 {
			if e, err := event.New(event.RAW_RIR_DATA, string(raw), "zetalytics", evt); err == nil {
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
func (m *Zetalytics) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("ahmia", func() module.Module { return &Ahmia{} })
	module.Register("onionsearchengine", func() module.Module { return &OnionSearchEngine{} })
	module.Register("bitcoinabuse", func() module.Module { return &BitcoinAbuse{} })
	module.Register("opencorporates", func() module.Module { return &OpenCorporates{} })
	module.Register("onyphe", func() module.Module { return &Onyphe{} })
	module.Register("zetalytics", func() module.Module { return &Zetalytics{} })
}
