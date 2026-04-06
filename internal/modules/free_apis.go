// Package modules — Batch 7: Free (no-auth) HTTP API integrations.
//
// This file implements modules that query free public APIs without
// requiring an API key: hackertarget, certspotter, crt.sh, dnsdumpster,
// commoncrawl, archive.org (Wayback Machine), bgpview, ripe (stat),
// and robtex.
//
// Implementations are intentionally compact: each module ports the
// single most useful query path of the corresponding Python module.
// Netblock expansion options and multi-page pagination are omitted.

package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// freeAPIClient is the shared HTTP client used by all Batch 7 modules.
var freeAPIClient = sflib.NewHTTPClient(sflib.HTTPClientOpts{
	Timeout:   20 * time.Second,
	RateLimit: 2,
})

// seenSet is a simple reusable concurrent dedup set.
type seenSet struct {
	mu sync.Mutex
	m  map[string]bool
}

// add returns true if the key was already present.
func (s *seenSet) add(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]bool)
	}
	if s.m[key] {
		return true
	}
	s.m[key] = true
	return false
}

// clear empties the set.
func (s *seenSet) clear() {
	s.mu.Lock()
	s.m = nil
	s.mu.Unlock()
}

// ============================================================================
// HackerTarget
// ============================================================================

// HackerTarget queries api.hackertarget.com for reverse IP lookups, zone
// transfers, and HTTP headers.
type HackerTarget struct{ seen seenSet }

// Meta returns module metadata.
func (m *HackerTarget) Meta() module.Meta {
	return module.Meta{Name: "hackertarget", Summary: "Search HackerTarget.com for hosts sharing the same IP and other passive data.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *HackerTarget) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *HackerTarget) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *HackerTarget) ProducedEvents() []event.Type {
	return []event.Type{event.CO_HOSTED_SITE, event.INTERNET_NAME, event.RAW_DNS_RECORDS}
}

// HandleEvent dispatches on event type.
func (m *HackerTarget) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	var results []*event.Event
	switch evt.Type {
	case event.IP_ADDRESS:
		url := "https://api.hackertarget.com/reverseiplookup/?q=" + evt.Data
		resp, err := freeAPIClient.FetchURL(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			return nil, nil
		}
		for _, line := range strings.Split(resp.Body, "\n") {
			host := strings.TrimSpace(line)
			if host == "" || strings.HasPrefix(host, "API count exceeded") || strings.HasPrefix(host, "error") {
				continue
			}
			if e, err := event.New(event.CO_HOSTED_SITE, host, "hackertarget", evt); err == nil {
				results = append(results, e)
			}
		}
	case event.DOMAIN_NAME:
		url := "https://api.hackertarget.com/zonetransfer/?q=" + evt.Data
		resp, err := freeAPIClient.FetchURL(ctx, url)
		if err != nil || resp.StatusCode != 200 {
			return nil, nil
		}
		if strings.Contains(strings.ToLower(resp.Body), "failed") {
			return nil, nil
		}
		if e, err := event.New(event.RAW_DNS_RECORDS, resp.Body, "hackertarget", evt); err == nil {
			results = append(results, e)
		}
		hostRe := regexp.MustCompile(`\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.` + regexp.QuoteMeta(evt.Data) + `)\b`)
		for _, m := range hostRe.FindAllStringSubmatch(resp.Body, -1) {
			host := strings.TrimSuffix(m[1], ".")
			if e, err := event.New(event.INTERNET_NAME, host, "hackertarget", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *HackerTarget) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// crt.sh (Certificate Transparency)
// ============================================================================

// CrtSh queries crt.sh for certificate transparency logs.
type CrtSh struct{ seen seenSet }

// Meta returns module metadata.
func (m *CrtSh) Meta() module.Meta {
	return module.Meta{Name: "crt", Summary: "Gather hostnames from historical certificates in crt.sh.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *CrtSh) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *CrtSh) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *CrtSh) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.RAW_RIR_DATA}
}

// crtShEntry represents one crt.sh JSON response entry.
type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// HandleEvent queries crt.sh and emits discovered hostnames.
func (m *CrtSh) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	url := "https://crt.sh/?q=%25." + evt.Data + "&output=json"
	resp, err := freeAPIClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		return nil, nil
	}
	var entries []crtShEntry
	if err := json.Unmarshal([]byte(resp.Body), &entries); err != nil {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "crt", evt); err == nil {
		results = append(results, e)
	}
	emitted := make(map[string]bool)
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || emitted[name] || !strings.HasSuffix(name, evt.Data) {
				continue
			}
			emitted[name] = true
			if e, err := event.New(event.INTERNET_NAME, name, "crt", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *CrtSh) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// CertSpotter
// ============================================================================

// CertSpotter queries the SSLMate CertSpotter public API.
type CertSpotter struct{ seen seenSet }

// Meta returns module metadata.
func (m *CertSpotter) Meta() module.Meta {
	return module.Meta{Name: "certspotter", Summary: "Gather hostnames from CertSpotter certificate transparency logs.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *CertSpotter) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *CertSpotter) WatchedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

// ProducedEvents returns emitted event types.
func (m *CertSpotter) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.RAW_RIR_DATA}
}

// certSpotterIssuance represents one issuance entry.
type certSpotterIssuance struct {
	DNSNames []string `json:"dns_names"`
}

// HandleEvent queries CertSpotter and emits discovered hostnames.
func (m *CertSpotter) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	url := "https://api.certspotter.com/v1/issuances?domain=" + evt.Data + "&include_subdomains=true&expand=dns_names"
	resp, err := freeAPIClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var entries []certSpotterIssuance
	if err := json.Unmarshal([]byte(resp.Body), &entries); err != nil {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "certspotter", evt); err == nil {
		results = append(results, e)
	}
	emitted := make(map[string]bool)
	for _, entry := range entries {
		for _, name := range entry.DNSNames {
			name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*."))
			if name == "" || emitted[name] || !strings.HasSuffix(name, evt.Data) {
				continue
			}
			emitted[name] = true
			if e, err := event.New(event.INTERNET_NAME, name, "certspotter", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *CertSpotter) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// DNSDumpster (via HackerTarget's hosted endpoint)
// ============================================================================

// DNSDumpster queries dnsdumpster.com for subdomain enumeration via its
// public HTML form. This is a best-effort port: the CSRF/cookie dance is
// brittle, and callers should consider crt.sh/certspotter as more reliable.
type DNSDumpster struct{ seen seenSet }

// Meta returns module metadata.
func (m *DNSDumpster) Meta() module.Meta {
	return module.Meta{Name: "dnsdumpster", Summary: "Passive subdomain enumeration via dnsdumpster.com.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *DNSDumpster) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *DNSDumpster) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *DNSDumpster) ProducedEvents() []event.Type { return []event.Type{event.INTERNET_NAME} }

// HandleEvent queries dnsdumpster and emits discovered hostnames.
// Note: best-effort; dnsdumpster may respond with a captcha page.
func (m *DNSDumpster) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	resp, err := freeAPIClient.FetchURL(ctx, "https://dnsdumpster.com/")
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Extract any hostnames referencing the target domain from the landing HTML.
	// (Full POST flow with CSRF is brittle and often captcha-guarded.)
	hostRe := regexp.MustCompile(`\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.` + regexp.QuoteMeta(evt.Data) + `)\b`)
	var results []*event.Event
	emitted := make(map[string]bool)
	for _, match := range hostRe.FindAllStringSubmatch(resp.Body, -1) {
		host := strings.ToLower(match[1])
		if emitted[host] {
			continue
		}
		emitted[host] = true
		if e, err := event.New(event.INTERNET_NAME, host, "dnsdumpster", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *DNSDumpster) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// CommonCrawl
// ============================================================================

// CommonCrawl queries the CommonCrawl index for URLs under a given domain.
type CommonCrawl struct {
	seen   seenSet
	mu     sync.Mutex
	indexs []string
}

// Meta returns module metadata.
func (m *CommonCrawl) Meta() module.Meta {
	return module.Meta{Name: "commoncrawl", Summary: "Searches for URLs found through CommonCrawl.org.", Categories: []string{"Passive"}}
}

// Setup initializes internal state.
func (m *CommonCrawl) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *CommonCrawl) WatchedEvents() []event.Type { return []event.Type{event.INTERNET_NAME} }

// ProducedEvents returns emitted event types.
func (m *CommonCrawl) ProducedEvents() []event.Type {
	return []event.Type{event.LINKED_URL_INTERNAL}
}

// ccIndexRe matches CommonCrawl index identifiers.
var ccIndexRe = regexp.MustCompile(`CC-MAIN-\d+-\d+`)

// getIndex lazily fetches the list of CommonCrawl indexes and returns the newest.
func (m *CommonCrawl) getIndex(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.indexs) > 0 {
		return m.indexs[0], nil
	}
	resp, err := freeAPIClient.FetchURL(ctx, "https://index.commoncrawl.org/")
	if err != nil {
		return "", err
	}
	indexes := ccIndexRe.FindAllString(resp.Body, -1)
	if len(indexes) == 0 {
		return "", fmt.Errorf("no commoncrawl indexes found")
	}
	// Deduplicate, keeping order.
	seenIdx := make(map[string]bool)
	for _, idx := range indexes {
		if !seenIdx[idx] {
			seenIdx[idx] = true
			m.indexs = append(m.indexs, idx)
		}
	}
	return m.indexs[0], nil
}

// ccEntry represents one JSON-lines entry from CommonCrawl index.
type ccEntry struct {
	URL string `json:"url"`
}

// HandleEvent queries the CommonCrawl index and emits found URLs.
func (m *CommonCrawl) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	idx, err := m.getIndex(ctx)
	if err != nil {
		return nil, nil
	}
	url := fmt.Sprintf("https://index.commoncrawl.org/%s-index?url=%s/*&output=json", idx, evt.Data)
	resp, err := freeAPIClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var results []*event.Event
	emitted := make(map[string]bool)
	for _, line := range strings.Split(resp.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry ccEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil || entry.URL == "" {
			continue
		}
		if emitted[entry.URL] {
			continue
		}
		emitted[entry.URL] = true
		if e, err := event.New(event.LINKED_URL_INTERNAL, entry.URL, "commoncrawl", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *CommonCrawl) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Archive.org (Wayback Machine)
// ============================================================================

// ArchiveOrg checks whether a URL has a snapshot in the Wayback Machine.
type ArchiveOrg struct{ seen seenSet }

// Meta returns module metadata.
func (m *ArchiveOrg) Meta() module.Meta {
	return module.Meta{Name: "archiveorg", Summary: "Check the Wayback Machine for historic snapshots of discovered URLs.", Categories: []string{"Passive"}}
}

// Setup initializes internal state.
func (m *ArchiveOrg) Setup(_ map[string]any) error { return nil }

// historicMap maps input event types to their _HISTORIC output counterparts.
var historicMap = map[event.Type]event.Type{
	event.INTERESTING_FILE:  event.INTERESTING_FILE_HISTORIC,
	event.URL_PASSWORD:      event.URL_PASSWORD_HISTORIC,
	event.URL_FORM:          event.URL_FORM_HISTORIC,
	event.URL_FLASH:         event.URL_FLASH_HISTORIC,
	event.URL_STATIC:        event.URL_STATIC_HISTORIC,
	event.URL_JAVA_APPLET:   event.URL_JAVA_APPLET_HISTORIC,
	event.URL_UPLOAD:        event.URL_UPLOAD_HISTORIC,
	event.URL_JAVASCRIPT:    event.URL_JAVASCRIPT_HISTORIC,
	event.URL_WEB_FRAMEWORK: event.URL_WEB_FRAMEWORK_HISTORIC,
}

// WatchedEvents returns consumed event types.
func (m *ArchiveOrg) WatchedEvents() []event.Type {
	out := make([]event.Type, 0, len(historicMap))
	for k := range historicMap {
		out = append(out, k)
	}
	return out
}

// ProducedEvents returns emitted event types.
func (m *ArchiveOrg) ProducedEvents() []event.Type {
	out := make([]event.Type, 0, len(historicMap))
	for _, v := range historicMap {
		out = append(out, v)
	}
	return out
}

// archiveResponse is the Wayback availability JSON payload.
type archiveResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			URL string `json:"url"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

// HandleEvent checks Wayback availability and emits *_HISTORIC events.
func (m *ArchiveOrg) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	out, ok := historicMap[evt.Type]
	if !ok {
		return nil, nil
	}
	url := "https://archive.org/wayback/available?url=" + evt.Data
	resp, err := freeAPIClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var ar archiveResponse
	if err := json.Unmarshal([]byte(resp.Body), &ar); err != nil || ar.ArchivedSnapshots.Closest.URL == "" {
		return nil, nil
	}
	e, err := event.New(out, ar.ArchivedSnapshots.Closest.URL, "archiveorg", evt)
	if err != nil {
		return nil, nil
	}
	return []*event.Event{e}, nil
}

// Finish clears state.
func (m *ArchiveOrg) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// BGPView
// ============================================================================

// BGPView queries api.bgpview.io for ASN and prefix info.
type BGPView struct{ seen seenSet }

// Meta returns module metadata.
func (m *BGPView) Meta() module.Meta {
	return module.Meta{Name: "bgpview", Summary: "Obtain network information from BGPView API.", Categories: []string{"Public Registries"}}
}

// Setup initializes internal state.
func (m *BGPView) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *BGPView) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS, event.BGP_AS_MEMBER, event.NETBLOCK_MEMBER}
}

// ProducedEvents returns emitted event types.
func (m *BGPView) ProducedEvents() []event.Type {
	return []event.Type{event.BGP_AS_MEMBER, event.NETBLOCK_MEMBER, event.PHYSICAL_ADDRESS, event.RAW_RIR_DATA}
}

// bgpViewIPResponse is the /ip/{ip} JSON payload.
type bgpViewIPResponse struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			ASN    struct {
				ASN int `json:"asn"`
			} `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

// bgpViewASNResponse is the /asn/{asn} JSON payload.
type bgpViewASNResponse struct {
	Data struct {
		OwnerAddress []string `json:"owner_address"`
	} `json:"data"`
}

// HandleEvent dispatches on event type.
func (m *BGPView) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	var results []*event.Event
	switch evt.Type {
	case event.IP_ADDRESS, event.IPV6_ADDRESS:
		resp, err := freeAPIClient.FetchURL(ctx, "https://api.bgpview.io/ip/"+evt.Data)
		if err != nil || resp.StatusCode != 200 {
			return nil, nil
		}
		if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "bgpview", evt); err == nil {
			results = append(results, e)
		}
		var payload bgpViewIPResponse
		if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
			return results, nil
		}
		for _, p := range payload.Data.Prefixes {
			if p.ASN.ASN != 0 {
				if e, err := event.New(event.BGP_AS_MEMBER, fmt.Sprintf("%d", p.ASN.ASN), "bgpview", evt); err == nil {
					results = append(results, e)
				}
			}
			if p.Prefix != "" {
				if e, err := event.New(event.NETBLOCK_MEMBER, p.Prefix, "bgpview", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	case event.BGP_AS_MEMBER:
		asn := strings.TrimPrefix(evt.Data, "AS")
		resp, err := freeAPIClient.FetchURL(ctx, "https://api.bgpview.io/asn/"+asn)
		if err != nil || resp.StatusCode != 200 {
			return nil, nil
		}
		var payload bgpViewASNResponse
		if err := json.Unmarshal([]byte(resp.Body), &payload); err == nil && len(payload.Data.OwnerAddress) > 0 {
			addr := strings.Join(payload.Data.OwnerAddress, ", ")
			if e, err := event.New(event.PHYSICAL_ADDRESS, addr, "bgpview", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *BGPView) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// RIPE stat
// ============================================================================

// RIPE queries stat.ripe.net for network and whois info.
type RIPE struct{ seen seenSet }

// Meta returns module metadata.
func (m *RIPE) Meta() module.Meta {
	return module.Meta{Name: "ripe", Summary: "Queries the RIPE stat API to identify netblocks and related info.", Categories: []string{"Public Registries"}}
}

// Setup initializes internal state.
func (m *RIPE) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *RIPE) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *RIPE) ProducedEvents() []event.Type {
	return []event.Type{event.NETBLOCK_MEMBER, event.BGP_AS_MEMBER, event.RAW_RIR_DATA}
}

// ripeNetworkInfoResponse is the /data/network-info JSON payload.
type ripeNetworkInfoResponse struct {
	Data struct {
		Prefix string   `json:"prefix"`
		ASNs   []string `json:"asns"`
	} `json:"data"`
}

// HandleEvent queries RIPE and emits discovered data.
func (m *RIPE) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	resp, err := freeAPIClient.FetchURL(ctx, "https://stat.ripe.net/data/network-info/data.json?resource="+evt.Data)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "ripe", evt); err == nil {
		results = append(results, e)
	}
	var payload ripeNetworkInfoResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return results, nil
	}
	if payload.Data.Prefix != "" {
		if e, err := event.New(event.NETBLOCK_MEMBER, payload.Data.Prefix, "ripe", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, asn := range payload.Data.ASNs {
		if e, err := event.New(event.BGP_AS_MEMBER, asn, "ripe", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *RIPE) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Robtex
// ============================================================================

// Robtex queries freeapi.robtex.com for reverse-IP passive data.
type Robtex struct{ seen seenSet }

// Meta returns module metadata.
func (m *Robtex) Meta() module.Meta {
	return module.Meta{Name: "robtex", Summary: "Search Robtex.com for hosts sharing the same IP.", Categories: []string{"Passive DNS"}}
}

// Setup initializes internal state.
func (m *Robtex) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Robtex) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *Robtex) ProducedEvents() []event.Type {
	return []event.Type{event.CO_HOSTED_SITE, event.RAW_RIR_DATA}
}

// HandleEvent queries Robtex and emits co-hosted sites.
// The freeapi.robtex.com/ipquery endpoint returns a line of JSON with a
// `pas` field containing passive hostname records. Each record has an `o`
// (hostname) field.
func (m *Robtex) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" || m.seen.add(evt.Data) {
		return nil, nil
	}
	if net.ParseIP(evt.Data) == nil {
		return nil, nil
	}
	resp, err := freeAPIClient.FetchURL(ctx, "https://freeapi.robtex.com/ipquery/"+evt.Data)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "robtex", evt); err == nil {
		results = append(results, e)
	}
	var payload struct {
		Pas []struct {
			O string `json:"o"`
		} `json:"pas"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return results, nil
	}
	emitted := make(map[string]bool)
	for _, rec := range payload.Pas {
		host := strings.TrimSpace(rec.O)
		if host == "" || emitted[host] {
			continue
		}
		emitted[host] = true
		if e, err := event.New(event.CO_HOSTED_SITE, host, "robtex", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Robtex) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registrations
// ============================================================================

func init() {
	module.Register("hackertarget", func() module.Module { return &HackerTarget{} })
	module.Register("crt", func() module.Module { return &CrtSh{} })
	module.Register("certspotter", func() module.Module { return &CertSpotter{} })
	module.Register("dnsdumpster", func() module.Module { return &DNSDumpster{} })
	module.Register("commoncrawl", func() module.Module { return &CommonCrawl{} })
	module.Register("archiveorg", func() module.Module { return &ArchiveOrg{} })
	module.Register("bgpview", func() module.Module { return &BGPView{} })
	module.Register("ripe", func() module.Module { return &RIPE{} })
	module.Register("robtex", func() module.Module { return &Robtex{} })
}
