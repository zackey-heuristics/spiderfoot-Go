// Package modules — Batch 9: Phishing & Reputation feeds.
//
// This file implements pragmatic ports of:
//   - phishtank        (data.phishtank.com online-valid CSV)
//   - openphish        (openphish.com feed.txt)
//   - emergingthreats  (rules.emergingthreats.net compromised-ips.txt)
//   - threatcrowd      (threatcrowd.org searchApi v2)
//   - phishstats       (phishstats.info JSON API)
//
// Each feed-style module lazily downloads its blocklist on first event
// and checks the watched event's data for membership. Netblock CIDR
// expansion is omitted; only IP/hostname membership is checked.
package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// repClient is the shared HTTP client used by Batch 9 modules.
var repClient = sflib.NewHTTPClient(sflib.HTTPClientOpts{
	Timeout:   30 * time.Second,
	RateLimit: 1,
})

// fetchOnce lazily downloads a feed body. Only successful fetches are
// cached; transient failures (network error or non-200) are returned as
// errors so the next event can retry.
type fetchOnce struct {
	mu     sync.Mutex
	loaded bool
	body   string
}

// get fetches the URL and caches the body on success. On error or
// non-200 status it returns an error WITHOUT populating the cache, so
// a later call can retry.
func (f *fetchOnce) get(ctx context.Context, url string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loaded {
		return f.body, nil
	}
	resp, err := repClient.FetchURL(ctx, url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("feed %s returned status %d", url, resp.StatusCode)
	}
	f.body = resp.Body
	f.loaded = true
	return f.body, nil
}

// reset clears the cached fetch state under the mutex.
func (f *fetchOnce) reset() {
	f.mu.Lock()
	f.loaded = false
	f.body = ""
	f.mu.Unlock()
}

// hostFromURL returns the hostname from a URL string, lowercased.
// Returns "" if parsing fails.
func hostFromURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	return strings.ToLower(h)
}

// hostHitTypes maps an input event type to the (blacklisted, malicious)
// output event types for hostname-style feeds.
var hostHitTypes = map[event.Type][2]event.Type{
	event.INTERNET_NAME:           {event.BLACKLISTED_INTERNET_NAME, event.MALICIOUS_INTERNET_NAME},
	event.AFFILIATE_INTERNET_NAME: {event.BLACKLISTED_AFFILIATE_INTERNET_NAME, event.MALICIOUS_AFFILIATE_INTERNET_NAME},
	event.CO_HOSTED_SITE:          {event.BLACKLISTED_COHOST, event.MALICIOUS_COHOST},
}

// ipHitTypes maps an input event type to the (blacklisted, malicious)
// output event types for IP-style feeds. Netblock events are intentionally
// not included — proper CIDR expansion is not implemented yet, so we do
// not advertise support for NETBLOCK_MEMBER/NETBLOCK_OWNER.
var ipHitTypes = map[event.Type][2]event.Type{
	event.IP_ADDRESS:       {event.BLACKLISTED_IPADDR, event.MALICIOUS_IPADDR},
	event.AFFILIATE_IPADDR: {event.BLACKLISTED_AFFILIATE_IPADDR, event.MALICIOUS_AFFILIATE_IPADDR},
}

// hostFeed is a generic blocklist module that fetches a remote feed of
// URLs (or hostnames) and checks event data membership.
type hostFeed struct {
	name    string
	summary string
	url     string
	parser  func(body string) map[string]bool
	feed    fetchOnce
	seen    seenSet
}

// Meta returns module metadata.
func (m *hostFeed) Meta() module.Meta {
	return module.Meta{Name: m.name, Summary: m.summary, Categories: []string{"Reputation Systems"}}
}

// Setup initializes internal state.
func (m *hostFeed) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *hostFeed) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.AFFILIATE_INTERNET_NAME, event.CO_HOSTED_SITE}
}

// ProducedEvents returns emitted event types.
func (m *hostFeed) ProducedEvents() []event.Type {
	return []event.Type{
		event.BLACKLISTED_INTERNET_NAME, event.BLACKLISTED_AFFILIATE_INTERNET_NAME, event.BLACKLISTED_COHOST,
		event.MALICIOUS_INTERNET_NAME, event.MALICIOUS_AFFILIATE_INTERNET_NAME, event.MALICIOUS_COHOST,
	}
}

// HandleEvent fetches the feed (cached) and checks membership.
func (m *hostFeed) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	hits, ok := hostHitTypes[evt.Type]
	if !ok {
		return nil, nil
	}
	body, err := m.feed.get(ctx, m.url)
	if err != nil || body == "" {
		return nil, nil
	}
	// Feed loaded successfully — commit the reservation made at entry.
	// Transient feed failures above fall through to the defer which
	// releases the reservation so a later event can retry.
	committed = true
	hosts := m.parser(body)
	if !hosts[strings.ToLower(evt.Data)] {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(hits[0], evt.Data, m.name, evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(hits[1], evt.Data, m.name, evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears feed and dedup state so the next scan re-downloads.
func (m *hostFeed) Finish() error {
	m.feed.reset()
	m.seen.clear()
	return nil
}

// parsePhishtank parses the PhishTank online-valid CSV. Each line is
// `phish_id,url,...`; the header is skipped.
func parsePhishtank(body string) map[string]bool {
	out := make(map[string]bool)
	for i, line := range strings.Split(body, "\n") {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.SplitN(line, ",", 3)
		if len(fields) < 2 {
			continue
		}
		if h := hostFromURL(fields[1]); h != "" {
			out[h] = true
		}
	}
	return out
}

// parseOpenphish parses the OpenPhish feed (one URL per line).
func parseOpenphish(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		if h := hostFromURL(line); h != "" {
			out[h] = true
		}
	}
	return out
}

// ipFeed is a generic blocklist module that fetches a remote IP list
// and checks event IP membership.
type ipFeed struct {
	name    string
	summary string
	url     string
	feed    fetchOnce
	seen    seenSet
}

// Meta returns module metadata.
func (m *ipFeed) Meta() module.Meta {
	return module.Meta{Name: m.name, Summary: m.summary, Categories: []string{"Reputation Systems"}}
}

// Setup initializes internal state.
func (m *ipFeed) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *ipFeed) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *ipFeed) ProducedEvents() []event.Type {
	return []event.Type{
		event.BLACKLISTED_IPADDR, event.BLACKLISTED_AFFILIATE_IPADDR,
		event.MALICIOUS_IPADDR, event.MALICIOUS_AFFILIATE_IPADDR,
	}
}

// parseIPList returns a set of IPs from a newline-separated list,
// ignoring comments and blank lines.
func parseIPList(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) != nil {
			out[line] = true
		}
	}
	return out
}

// HandleEvent fetches the IP list and checks for IP membership.
// Netblock CIDR expansion is not performed.
func (m *ipFeed) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	hits, ok := ipHitTypes[evt.Type]
	if !ok {
		return nil, nil
	}
	if evt.Type == event.IP_ADDRESS || evt.Type == event.AFFILIATE_IPADDR {
		if net.ParseIP(evt.Data) == nil {
			return nil, nil
		}
	}
	body, err := m.feed.get(ctx, m.url)
	if err != nil || body == "" {
		return nil, nil
	}
	// Feed loaded successfully — commit the reservation made at entry.
	committed = true
	ips := parseIPList(body)
	if !ips[evt.Data] {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(hits[0], evt.Data, m.name, evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(hits[1], evt.Data, m.name, evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears feed and dedup state.
func (m *ipFeed) Finish() error {
	m.feed.reset()
	m.seen.clear()
	return nil
}

// ============================================================================
// ThreatCrowd
// ============================================================================

// ThreatCrowd queries the threatcrowd.org search API per event.
type ThreatCrowd struct{ seen seenSet }

// Meta returns module metadata.
func (m *ThreatCrowd) Meta() module.Meta {
	return module.Meta{Name: "threatcrowd", Summary: "Look up data via the ThreatCrowd search API.", Categories: []string{"Reputation Systems"}}
}

// Setup initializes internal state.
func (m *ThreatCrowd) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *ThreatCrowd) WatchedEvents() []event.Type {
	return []event.Type{
		event.IP_ADDRESS, event.AFFILIATE_IPADDR, event.INTERNET_NAME,
		event.AFFILIATE_INTERNET_NAME, event.CO_HOSTED_SITE, event.EMAILADDR,
	}
}

// ProducedEvents returns emitted event types.
func (m *ThreatCrowd) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR, event.MALICIOUS_AFFILIATE_IPADDR,
		event.MALICIOUS_INTERNET_NAME, event.MALICIOUS_AFFILIATE_INTERNET_NAME,
		event.MALICIOUS_COHOST, event.MALICIOUS_EMAILADDR,
	}
}

// threatCrowdResponse is the relevant subset of the API JSON.
type threatCrowdResponse struct {
	Votes     int    `json:"votes"`
	Permalink string `json:"permalink"`
}

// tcOutputType maps an input event type to its malicious counterpart.
var tcOutputType = map[event.Type]event.Type{
	event.IP_ADDRESS:              event.MALICIOUS_IPADDR,
	event.AFFILIATE_IPADDR:        event.MALICIOUS_AFFILIATE_IPADDR,
	event.INTERNET_NAME:           event.MALICIOUS_INTERNET_NAME,
	event.AFFILIATE_INTERNET_NAME: event.MALICIOUS_AFFILIATE_INTERNET_NAME,
	event.CO_HOSTED_SITE:          event.MALICIOUS_COHOST,
	event.EMAILADDR:               event.MALICIOUS_EMAILADDR,
}

// HandleEvent picks the right ThreatCrowd endpoint and emits a malicious
// event when the API reports negative votes.
func (m *ThreatCrowd) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	out, ok := tcOutputType[evt.Type]
	if !ok {
		return nil, nil
	}
	var endpoint string
	switch evt.Type {
	case event.IP_ADDRESS, event.AFFILIATE_IPADDR:
		endpoint = "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=" + url.QueryEscape(evt.Data)
	case event.EMAILADDR:
		endpoint = "https://www.threatcrowd.org/searchApi/v2/email/report/?email=" + url.QueryEscape(evt.Data)
	default:
		endpoint = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + url.QueryEscape(evt.Data)
	}
	resp, err := repClient.FetchURL(ctx, endpoint)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	// Below this line a malformed response or a non-malicious verdict
	// still counts as "looked up" and should not be retried.
	committed = true
	var payload threatCrowdResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil || payload.Votes >= 0 {
		return nil, nil
	}
	// Emit the original indicator so the event type (MALICIOUS_IPADDR etc.)
	// remains a valid IP/domain/email. The permalink is attached via the
	// source event chain rather than overwriting the indicator string.
	e, err := event.New(out, evt.Data, "threatcrowd", evt)
	if err != nil {
		return nil, nil
	}
	return []*event.Event{e}, nil
}

// Finish clears state.
func (m *ThreatCrowd) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// PhishStats
// ============================================================================

// PhishStats queries phishstats.info per IP.
type PhishStats struct{ seen seenSet }

// Meta returns module metadata.
func (m *PhishStats) Meta() module.Meta {
	return module.Meta{Name: "phishstats", Summary: "Check if an IP is malicious according to PhishStats.info.", Categories: []string{"Reputation Systems"}}
}

// Setup initializes internal state.
func (m *PhishStats) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *PhishStats) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *PhishStats) ProducedEvents() []event.Type {
	return []event.Type{
		event.BLACKLISTED_IPADDR, event.BLACKLISTED_AFFILIATE_IPADDR,
		event.MALICIOUS_IPADDR, event.MALICIOUS_AFFILIATE_IPADDR,
		event.RAW_RIR_DATA,
	}
}

// HandleEvent queries the phishing endpoint for the event IP.
func (m *PhishStats) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	hits, ok := ipHitTypes[evt.Type]
	if !ok {
		return nil, nil
	}
	if (evt.Type == event.IP_ADDRESS || evt.Type == event.AFFILIATE_IPADDR) && net.ParseIP(evt.Data) == nil {
		return nil, nil
	}
	endpoint := "https://phishstats.info:2096/api/phishing?_where=(ip,eq," + url.QueryEscape(evt.Data) + ")&_size=1"
	resp, err := repClient.FetchURL(ctx, endpoint)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	// Upstream responded 200 — commit the reservation made at entry.
	committed = true
	var payload []struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil || len(payload) == 0 {
		return nil, nil
	}
	if payload[0].IP != evt.Data {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "phishstats", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(hits[0], evt.Data, "phishstats", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(hits[1], evt.Data, "phishstats", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *PhishStats) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registrations
// ============================================================================

func init() {
	module.Register("phishtank", func() module.Module {
		return &hostFeed{
			name:    "phishtank",
			summary: "Check if a host is in the PhishTank database of phishing sites.",
			url:     "https://data.phishtank.com/data/online-valid.csv",
			parser:  parsePhishtank,
		}
	})
	module.Register("openphish", func() module.Module {
		return &hostFeed{
			name:    "openphish",
			summary: "Check if a host is in the OpenPhish.com phishing feed.",
			url:     "https://www.openphish.com/feed.txt",
			parser:  parseOpenphish,
		}
	})
	module.Register("emergingthreats", func() module.Module {
		return &ipFeed{
			name:    "emergingthreats",
			summary: "Check if an IP is in the EmergingThreats compromised IPs list.",
			url:     "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		}
	})
	module.Register("threatcrowd", func() module.Module { return &ThreatCrowd{} })
	module.Register("phishstats", func() module.Module { return &PhishStats{} })
}
