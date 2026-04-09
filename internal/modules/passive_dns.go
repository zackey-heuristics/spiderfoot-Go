// Package modules — Batch 19: passive DNS & historical whois APIs.
//
// This file implements pragmatic ports of:
//   - dnsdb     (FarSight DNSDB v2 rrset/rdata; X-API-Key)
//   - whoxy     (Whoxy reverse-whois by email; query-param key)
//   - mnemonic  (Mnemonic PassiveDNS v3; no key)
//   - circllu   (CIRCL.LU passive DNS v1; Basic auth login+password)
//   - fullhunt  (FullHunt domain/details; X-API-KEY header)
//
// All keyed modules use vendor-prefixed opt keys with no generic
// fallback (Batch 11+ convention). All requests use HTTPS. Commits to
// the seenSet happen only after a substantive parse succeeds on a
// documented response shape.

package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// ============================================================================
// DNSDB (FarSight)
// ============================================================================

// DNSDB queries FarSight DNSDB v2 for historical passive DNS
// (rrset/rdata) records. Requires opts["dnsdb_api_key"].
type DNSDB struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *DNSDB) Meta() module.Meta {
	return module.Meta{
		Name:           "dnsdb",
		Summary:        "Query FarSight's DNSDB for historical and passive DNS data.",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *DNSDB) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "dnsdb_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *DNSDB) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *DNSDB) ProducedEvents() []event.Type {
	return []event.Type{
		event.RAW_RIR_DATA,
		event.INTERNET_NAME,
		event.PROVIDER_DNS,
		event.PROVIDER_MAIL,
		event.DNS_TXT,
		event.IP_ADDRESS,
		event.IPV6_ADDRESS,
		event.CO_HOSTED_SITE,
	}
}

// dnsdbRecord mirrors one line of DNSDB v2 ndjson output (`{"obj": ...}`).
type dnsdbRecord struct {
	Obj struct {
		RRType string   `json:"rrtype"`
		RRName string   `json:"rrname"`
		RData  []string `json:"rdata"`
	} `json:"obj"`
}

// parseDNSDBNDJSON splits and parses the documented ndjson stream
// (SAF begin/end condition markers on first+last line, records in
// between). Returns records in the middle.
func parseDNSDBNDJSON(body []byte) []dnsdbRecord {
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 3 {
		return nil
	}
	out := make([]dnsdbRecord, 0, len(lines)-2)
	for _, l := range lines[1 : len(lines)-1] {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var r dnsdbRecord
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			continue
		}
		if r.Obj.RRType == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// dnsdbQuery GETs the DNSDB endpoint and returns parsed records.
func (m *DNSDB) dnsdbQuery(ctx context.Context, endpoint, qtype, qry string) []dnsdbRecord {
	u := "https://api.dnsdb.info/dnsdb/v2/lookup/" + endpoint + "/" + qtype + "/" + url.PathEscape(qry)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Accept", "application/x-ndjson")
		h.Set("X-API-Key", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil
	}
	return parseDNSDBNDJSON(body)
}

// HandleEvent queries DNSDB for the given IP or domain.
func (m *DNSDB) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	if evt.Type == event.DOMAIN_NAME {
		rrset := m.dnsdbQuery(ctx, "rrset", "name", evt.Data)
		rdata := m.dnsdbQuery(ctx, "rdata", "name", evt.Data)
		if len(rrset) == 0 && len(rdata) == 0 {
			return nil, nil
		}
		for _, r := range rrset {
			switch r.Obj.RRType {
			case "A":
				for _, ip := range r.Obj.RData {
					if e, err := event.New(event.IP_ADDRESS, strings.TrimRight(ip, "."), "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			case "AAAA":
				for _, ip := range r.Obj.RData {
					if e, err := event.New(event.IPV6_ADDRESS, strings.TrimRight(ip, "."), "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			case "MX":
				for _, d := range r.Obj.RData {
					// MX rdata is "<pref> <host>". Guard against
					// malformed/empty upstream values — an empty
					// or whitespace-only entry would otherwise
					// panic on parts[-1]. See Codex adversarial
					// review 2026-04-09.
					parts := strings.Fields(d)
					if len(parts) == 0 {
						continue
					}
					host := strings.TrimRight(parts[len(parts)-1], ".")
					if host == "" {
						continue
					}
					if e, err := event.New(event.PROVIDER_MAIL, host, "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			case "NS":
				for _, d := range r.Obj.RData {
					if e, err := event.New(event.PROVIDER_DNS, strings.TrimRight(d, "."), "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			case "TXT":
				for _, d := range r.Obj.RData {
					if e, err := event.New(event.DNS_TXT, strings.Trim(d, `"`), "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			case "CNAME":
				for _, d := range r.Obj.RData {
					if e, err := event.New(event.CO_HOSTED_SITE, strings.TrimRight(d, "."), "dnsdb", evt); err == nil {
						results = append(results, e)
					}
				}
			}
		}
		for _, r := range rdata {
			if r.Obj.RRType != "NS" && r.Obj.RRType != "CNAME" {
				continue
			}
			name := strings.TrimRight(r.Obj.RRName, ".")
			if r.Obj.RRType == "NS" {
				if e, err := event.New(event.PROVIDER_DNS, name, "dnsdb", evt); err == nil {
					results = append(results, e)
				}
			} else {
				if e, err := event.New(event.CO_HOSTED_SITE, name, "dnsdb", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	} else { // IP_ADDRESS or IPV6_ADDRESS
		records := m.dnsdbQuery(ctx, "rdata", "ip", evt.Data)
		if len(records) == 0 {
			return nil, nil
		}
		for _, r := range records {
			if r.Obj.RRType != "A" && r.Obj.RRType != "AAAA" {
				continue
			}
			name := strings.TrimRight(r.Obj.RRName, ".")
			if name == "" {
				continue
			}
			if e, err := event.New(event.INTERNET_NAME, name, "dnsdb", evt); err == nil {
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
func (m *DNSDB) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Whoxy — reverse whois by email
// ============================================================================

// Whoxy queries whoxy.com reverse-whois-by-email and emits affiliate
// domains. Requires opts["whoxy_api_key"].
type Whoxy struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Whoxy) Meta() module.Meta {
	return module.Meta{
		Name:           "whoxy",
		Summary:        "Reverse Whois lookups using Whoxy.com.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *Whoxy) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "whoxy_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Whoxy) WatchedEvents() []event.Type { return []event.Type{event.EMAILADDR} }

// ProducedEvents returns emitted event types.
func (m *Whoxy) ProducedEvents() []event.Type {
	return []event.Type{event.AFFILIATE_INTERNET_NAME, event.AFFILIATE_DOMAIN_NAME}
}

// whoxyResp mirrors the documented whoxy.com reverse-whois shape.
type whoxyResp struct {
	Status       int `json:"status"`
	TotalPages   int `json:"total_pages"`
	CurrentPage  int `json:"current_page"`
	SearchResult []struct {
		DomainName string `json:"domain_name"`
	} `json:"search_result"`
}

// HandleEvent queries whoxy for the given email address.
func (m *Whoxy) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	seenDomain := map[string]bool{}
	// Pagination is driven by resp.TotalPages returned on page 1.
	// The absolute safety cap guards against a runaway upstream
	// advertising an unbounded page count; if it is ever hit we
	// emit an explicit RAW_RIR_DATA marker so the truncation is
	// visible rather than silent. See Codex adversarial review
	// 2026-04-09.
	const absMaxPages = 500
	totalPages := 1
	truncated := false
	for page := 1; ; page++ {
		if page > absMaxPages {
			truncated = true
			break
		}
		u := "https://api.whoxy.com/?key=" + url.QueryEscape(m.apiKey) +
			"&reverse=whois&email=" + url.QueryEscape(evt.Data) +
			"&page=" + itoa(page)
		body, ok := majorAPIFetch(ctx, u, nil)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp whoxyResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		if resp.Status != 1 {
			return nil, nil
		}
		for _, r := range resp.SearchResult {
			h := strings.ToLower(r.DomainName)
			if h == "" || seenDomain[h] {
				continue
			}
			seenDomain[h] = true
			if e, err := event.New(event.AFFILIATE_INTERNET_NAME, h, "whoxy", evt); err == nil {
				results = append(results, e)
			}
			if e, err := event.New(event.AFFILIATE_DOMAIN_NAME, h, "whoxy", evt); err == nil {
				results = append(results, e)
			}
		}
		if resp.TotalPages > totalPages {
			totalPages = resp.TotalPages
		}
		if totalPages <= 1 || resp.CurrentPage >= totalPages {
			break
		}
	}
	if truncated {
		if e, err := event.New(event.RAW_RIR_DATA,
			"whoxy: reverse-whois pagination capped at "+itoa(absMaxPages)+" pages; results may be incomplete",
			"whoxy", evt); err == nil {
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
func (m *Whoxy) Finish() error { m.seen.clear(); return nil }

// itoa is a tiny inlined int→decimal-string helper to avoid importing
// strconv just for a page counter.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	n := i
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// ============================================================================
// Mnemonic PassiveDNS (free, no key)
// ============================================================================

// Mnemonic queries api.mnemonic.no/pdns/v3 for passive DNS. No auth.
type Mnemonic struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *Mnemonic) Meta() module.Meta {
	return module.Meta{
		Name:       "mnemonic",
		Summary:    "Obtain Passive DNS information from PassiveDNS.mnemonic.no.",
		Categories: []string{"Passive DNS"},
	}
}

// Setup is a no-op.
func (m *Mnemonic) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Mnemonic) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Mnemonic) ProducedEvents() []event.Type {
	return []event.Type{
		event.IP_ADDRESS,
		event.IPV6_ADDRESS,
		event.INTERNET_NAME,
		event.CO_HOSTED_SITE,
		event.RAW_RIR_DATA,
	}
}

// mnemonicResp mirrors the documented PassiveDNS v3 shape.
type mnemonicResp struct {
	ResponseCode int `json:"responseCode"`
	Size         int `json:"size"`
	Count        int `json:"count"`
	Data         []struct {
		Query  string `json:"query"`
		Answer string `json:"answer"`
		RRType string `json:"rrtype"`
	} `json:"data"`
}

// HandleEvent queries Mnemonic PassiveDNS for the given event.
func (m *Mnemonic) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.mnemonic.no/pdns/v3/" + url.PathEscape(evt.Data) + "?limit=500&offset=0"
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp mnemonicResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if resp.ResponseCode != 200 || resp.Size == 0 || len(resp.Data) == 0 {
		return nil, nil
	}

	var results []*event.Event
	for _, r := range resp.Data {
		if strings.ContainsAny(r.Query, "*%") {
			continue
		}
		switch evt.Type {
		case event.IP_ADDRESS, event.IPV6_ADDRESS:
			if r.RRType == "a" || r.RRType == "aaaa" {
				if e, err := event.New(event.CO_HOSTED_SITE, r.Query, "mnemonic", evt); err == nil {
					results = append(results, e)
				}
			}
		case event.INTERNET_NAME, event.DOMAIN_NAME:
			if r.RRType == "ptr" {
				continue
			}
			if r.RRType == "a" {
				if e, err := event.New(event.IP_ADDRESS, r.Answer, "mnemonic", evt); err == nil {
					results = append(results, e)
				}
			} else if r.RRType == "aaaa" {
				if e, err := event.New(event.IPV6_ADDRESS, r.Answer, "mnemonic", evt); err == nil {
					results = append(results, e)
				}
			} else if r.RRType == "cname" {
				if e, err := event.New(event.INTERNET_NAME, r.Answer, "mnemonic", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "mnemonic", evt); err == nil {
		results = append(results, e)
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Mnemonic) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// CIRCL.LU passive DNS
// ============================================================================

// CIRCLLU queries www.circl.lu/pdns for passive DNS records. Requires
// opts["circllu_api_key_login"] and opts["circllu_api_key_password"].
type CIRCLLU struct {
	seen     seenSet
	login    string
	password string
}

// Meta returns module metadata.
func (m *CIRCLLU) Meta() module.Meta {
	return module.Meta{
		Name:           "circllu",
		Summary:        "Obtain information from CIRCL.LU's Passive DNS database.",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads credentials from opts.
func (m *CIRCLLU) Setup(opts map[string]any) error {
	m.login = optString(opts, "circllu_api_key_login", "")
	m.password = optString(opts, "circllu_api_key_password", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *CIRCLLU) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *CIRCLLU) ProducedEvents() []event.Type {
	return []event.Type{event.CO_HOSTED_SITE, event.RAW_RIR_DATA}
}

// circlRecord mirrors one line of the CIRCL.LU pdns ndjson stream.
type circlRecord struct {
	RRType string `json:"rrtype"`
	RRName string `json:"rrname"`
	RData  string `json:"rdata"`
}

// HandleEvent queries CIRCL.LU passive DNS for the event.
func (m *CIRCLLU) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://www.circl.lu/pdns/query/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.login, m.password))
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}

	// CIRCL.LU returns one JSON record per line (NDJSON-ish).
	var records []circlRecord
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if len(line) < 2 {
			continue
		}
		var r circlRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		records = append(records, r)
	}
	if len(records) == 0 {
		return nil, nil
	}

	var results []*event.Event
	seenOut := map[string]bool{}
	emit := func(v string) {
		v = strings.TrimRight(v, ".")
		if v == "" || seenOut[v] {
			return
		}
		seenOut[v] = true
		if e, err := event.New(event.CO_HOSTED_SITE, v, "circllu", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, r := range records {
		switch evt.Type {
		case event.IP_ADDRESS:
			// IP query: forward records have the IP in rdata
			// and the resolved name in rrname.
			if r.RRType == "A" && r.RData == evt.Data && r.RRName != "" {
				emit(r.RRName)
			}
		case event.INTERNET_NAME, event.DOMAIN_NAME:
			// Name query: the common passive-DNS shape is
			// rrname == query and rdata == resolved target
			// (CNAME / NS / MX host / etc). Accept either
			// orientation because providers occasionally
			// return the inverse for historical records. See
			// Codex adversarial review 2026-04-09 — the
			// pre-fix code only matched the inverse and
			// produced systematic false negatives for
			// domain-based lookups.
			if r.RRName == evt.Data && r.RData != "" {
				// For MX records rdata is "<pref> <host>";
				// pull the last whitespace token, guarding
				// malformed upstream values.
				if r.RRType == "MX" {
					parts := strings.Fields(r.RData)
					if len(parts) == 0 {
						continue
					}
					emit(parts[len(parts)-1])
				} else {
					emit(r.RData)
				}
			} else if r.RData == evt.Data && r.RRName != "" {
				emit(r.RRName)
			}
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "circllu", evt); err == nil {
		results = append(results, e)
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *CIRCLLU) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// FullHunt
// ============================================================================

// FullHunt queries fullhunt.io/api/v1/domain/<qry>/details for attack
// surface data. Requires opts["fullhunt_api_key"].
type FullHunt struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *FullHunt) Meta() module.Meta {
	return module.Meta{
		Name:           "fullhunt",
		Summary:        "Identify domain attack surface using FullHunt API.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *FullHunt) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "fullhunt_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *FullHunt) WatchedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

// ProducedEvents returns emitted event types.
func (m *FullHunt) ProducedEvents() []event.Type {
	return []event.Type{
		event.INTERNET_NAME,
		event.AFFILIATE_INTERNET_NAME,
		event.TCP_PORT_OPEN,
		event.PROVIDER_DNS,
		event.PROVIDER_MAIL,
		event.RAW_RIR_DATA,
	}
}

// fullhuntResp mirrors the documented fullhunt.io domain/details shape.
type fullhuntResp struct {
	Hosts []struct {
		Host string `json:"host"`
		DNS  struct {
			MX    []string `json:"mx"`
			NS    []string `json:"ns"`
			CName []string `json:"cname"`
		} `json:"dns"`
		NetworkPorts []int `json:"network_ports"`
	} `json:"hosts"`
}

// HandleEvent queries fullhunt for the given domain.
func (m *FullHunt) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://fullhunt.io/api/v1/domain/" + url.PathEscape(evt.Data) + "/details"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("X-API-KEY", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp fullhuntResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if len(resp.Hosts) == 0 {
		return nil, nil
	}

	target := strings.ToLower(evt.Data)
	var results []*event.Event
	nameservers := map[string]bool{}
	mailservers := map[string]bool{}
	hosts := map[string]bool{}

	for _, rec := range resp.Hosts {
		if rec.Host != "" {
			hosts[strings.ToLower(rec.Host)] = true
		}
		for _, mx := range rec.DNS.MX {
			mailservers[strings.ToLower(strings.TrimRight(mx, "."))] = true
		}
		for _, ns := range rec.DNS.NS {
			nameservers[strings.ToLower(strings.TrimRight(ns, "."))] = true
		}
		for _, c := range rec.DNS.CName {
			hosts[strings.ToLower(strings.TrimRight(c, "."))] = true
		}
		for _, port := range rec.NetworkPorts {
			if rec.Host == "" {
				continue
			}
			if e, err := event.New(event.TCP_PORT_OPEN, rec.Host+":"+itoa(port), "fullhunt", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	for h := range mailservers {
		hosts[h] = true
		if e, err := event.New(event.PROVIDER_MAIL, h, "fullhunt", evt); err == nil {
			results = append(results, e)
		}
	}
	for h := range nameservers {
		hosts[h] = true
		if e, err := event.New(event.PROVIDER_DNS, h, "fullhunt", evt); err == nil {
			results = append(results, e)
		}
	}
	for h := range hosts {
		if h == "" {
			continue
		}
		evType := event.AFFILIATE_INTERNET_NAME
		if h == target || strings.HasSuffix(h, "."+target) {
			evType = event.INTERNET_NAME
		}
		if e, err := event.New(evType, h, "fullhunt", evt); err == nil {
			results = append(results, e)
		}
	}
	if len(results) == 0 {
		return nil, nil
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "fullhunt", evt); err == nil {
		results = append(results, e)
	}
	committed = true
	return results, nil
}

// Finish clears state.
func (m *FullHunt) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("dnsdb", func() module.Module { return &DNSDB{} })
	module.Register("whoxy", func() module.Module { return &Whoxy{} })
	module.Register("mnemonic", func() module.Module { return &Mnemonic{} })
	module.Register("circllu", func() module.Module { return &CIRCLLU{} })
	module.Register("fullhunt", func() module.Module { return &FullHunt{} })
}
