// Package modules — Batch 17: IP / domain intelligence APIs.
//
// This file implements pragmatic ports of:
//   - pulsedive       (pulsedive.com info.php; api key via query param)
//   - binaryedge      (api.binaryedge.io v2 host/subdomain queries; X-Key)
//   - fraudguard      (api.fraudguard.io ip lookup; Basic auth user+pass)
//   - ipqualityscore  (ipqualityscore.com IP/email/phone scoring; key in path)
//   - fullcontact     (api.fullcontact.com person/company enrich; Bearer)
//   - spyonweb        (api.spyonweb.com summary/ip; access_token query)
//
// All keyed modules use vendor-prefixed opt keys with no generic
// fallback (Batch 11+ convention) and reuse the shared majorAPIFetch /
// majorAPIFetchPOST helpers from major_apis.go.

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
// Pulsedive
// ============================================================================

// Pulsedive queries pulsedive.com for IOC threat info. Requires
// opts["pulsedive_api_key"].
type Pulsedive struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Pulsedive) Meta() module.Meta {
	return module.Meta{
		Name:           "pulsedive",
		Summary:        "Obtain IOC threat info from Pulsedive's API.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *Pulsedive) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "pulsedive_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Pulsedive) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Pulsedive) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.MALICIOUS_INTERNET_NAME,
		event.TCP_PORT_OPEN,
		event.RAW_RIR_DATA,
	}
}

// pulsediveResp is the relevant subset of /api/info.php.
type pulsediveResp struct {
	IID        any `json:"iid"`
	Attributes struct {
		Port []string `json:"port"`
	} `json:"attributes"`
	Threats []struct {
		Name     string `json:"name"`
		Category string `json:"category"`
	} `json:"threats"`
}

// HandleEvent queries Pulsedive for threat info.
func (m *Pulsedive) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://pulsedive.com/api/info.php?indicator=" + url.QueryEscape(evt.Data) + "&key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp pulsediveResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "pulsedive", evt); err == nil {
		results = append(results, e)
	}
	for _, p := range resp.Attributes.Port {
		if p == "" {
			continue
		}
		if e, err := event.New(event.TCP_PORT_OPEN, evt.Data+":"+p, "pulsedive", evt); err == nil {
			results = append(results, e)
		}
	}
	if len(resp.Threats) == 0 {
		return results, nil
	}
	var malType event.Type
	switch evt.Type {
	case event.IP_ADDRESS:
		malType = event.MALICIOUS_IPADDR
	case event.AFFILIATE_IPADDR:
		malType = event.MALICIOUS_AFFILIATE_IPADDR
	case event.INTERNET_NAME:
		malType = event.MALICIOUS_INTERNET_NAME
	default:
		return results, nil
	}
	for _, t := range resp.Threats {
		descr := evt.Data + "\n - " + t.Name + " (" + t.Category + ")"
		if iid := fmt.Sprintf("%v", resp.IID); iid != "" && iid != "<nil>" {
			descr += "\n" + sfURL("Pulsedive ["+evt.Data+"]", "https://pulsedive.com/indicator/?iid="+iid)
		}
		if e, err := event.New(malType, descr, "pulsedive", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Pulsedive) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// BinaryEdge
// ============================================================================

// BinaryEdge queries api.binaryedge.io for host port/banner info and
// subdomain enumeration. Requires opts["binaryedge_api_key"].
type BinaryEdge struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *BinaryEdge) Meta() module.Meta {
	return module.Meta{
		Name:           "binaryedge",
		Summary:        "Obtain port, banner and subdomain information from BinaryEdge.io.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *BinaryEdge) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "binaryedge_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *BinaryEdge) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *BinaryEdge) ProducedEvents() []event.Type {
	return []event.Type{
		event.INTERNET_NAME,
		event.TCP_PORT_OPEN,
		event.UDP_PORT_OPEN,
		event.TCP_PORT_OPEN_BANNER,
		event.RAW_RIR_DATA,
	}
}

// binaryEdgeIPResp is the relevant subset of /v2/query/ip/{ip}.
type binaryEdgeIPResp struct {
	Events []struct {
		Results []struct {
			Target struct {
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
			} `json:"target"`
			Result struct {
				Data struct {
					Service struct {
						Banner string `json:"banner"`
					} `json:"service"`
				} `json:"data"`
			} `json:"result"`
		} `json:"results"`
	} `json:"events"`
}

// binaryEdgeSubsResp is the relevant subset of /v2/query/domains/subdomain/{d}.
type binaryEdgeSubsResp struct {
	Events []string `json:"events"`
}

// HandleEvent queries BinaryEdge for the given target.
func (m *BinaryEdge) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	header := func(h http.Header) { h.Set("X-Key", m.apiKey) }
	var results []*event.Event

	if evt.Type == event.IP_ADDRESS {
		u := "https://api.binaryedge.io/v2/query/ip/" + url.PathEscape(evt.Data)
		body, ok := majorAPIFetch(ctx, u, header)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp binaryEdgeIPResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		committed = true
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "binaryedge", evt); err == nil {
			results = append(results, e)
		}
		seenPort := make(map[string]bool)
		for _, ev := range resp.Events {
			for _, r := range ev.Results {
				if r.Target.Port == 0 {
					continue
				}
				portStr := fmt.Sprintf("%s:%d", evt.Data, r.Target.Port)
				portType := event.TCP_PORT_OPEN
				if r.Target.Protocol == "udp" {
					portType = event.UDP_PORT_OPEN
				}
				key := string(portType) + "|" + portStr
				if seenPort[key] {
					continue
				}
				seenPort[key] = true
				portEvt, err := event.New(portType, portStr, "binaryedge", evt)
				if err != nil {
					continue
				}
				results = append(results, portEvt)
				banner := r.Result.Data.Service.Banner
				if banner != "" && portType == event.TCP_PORT_OPEN {
					if be, err := event.New(event.TCP_PORT_OPEN_BANNER, banner, "binaryedge", portEvt); err == nil {
						results = append(results, be)
					}
				}
			}
		}
		return results, nil
	}

	// DOMAIN_NAME — subdomain enumeration
	u := "https://api.binaryedge.io/v2/query/domains/subdomain/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, header)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp binaryEdgeSubsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "binaryedge", evt); err == nil {
		results = append(results, e)
	}
	seenHost := make(map[string]bool)
	for _, host := range resp.Events {
		host = strings.TrimSpace(host)
		if host == "" || seenHost[host] {
			continue
		}
		seenHost[host] = true
		if e, err := event.New(event.INTERNET_NAME, host, "binaryedge", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *BinaryEdge) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// FraudGuard
// ============================================================================

// FraudGuard queries api.fraudguard.io for IP threat info. Requires
// opts["fraudguard_api_key_account"] and opts["fraudguard_api_key_password"].
type FraudGuard struct {
	seen     seenSet
	username string
	password string
}

// Meta returns module metadata.
func (m *FraudGuard) Meta() module.Meta {
	return module.Meta{
		Name:           "fraudguard",
		Summary:        "Obtain IP threat information from Fraudguard.io.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads both credentials from opts.
func (m *FraudGuard) Setup(opts map[string]any) error {
	m.username = optString(opts, "fraudguard_api_key_account", "")
	m.password = optString(opts, "fraudguard_api_key_password", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *FraudGuard) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *FraudGuard) ProducedEvents() []event.Type {
	return []event.Type{
		event.GEOINFO,
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.RAW_RIR_DATA,
	}
}

// fraudGuardResp is the relevant subset of /ip/{ip}.
type fraudGuardResp struct {
	State     string `json:"state"`
	City      string `json:"city"`
	Postal    string `json:"postal_code"`
	Country   string `json:"country"`
	Threat    string `json:"threat"`
	RiskLevel string `json:"risk_level"`
}

// HandleEvent queries FraudGuard for the given IP.
func (m *FraudGuard) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.username == "" || m.password == "" {
		return nil, nil
	}

	u := "https://api.fraudguard.io/ip/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.username, m.password))
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp fraudGuardResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "fraudguard", evt); err == nil {
		results = append(results, e)
	}
	parts := []string{}
	for _, p := range []string{resp.State, resp.City, resp.Postal, resp.Country} {
		if p != "" && p != "unknown" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 0 {
		if e, err := event.New(event.GEOINFO, strings.Join(parts, ", "), "fraudguard", evt); err == nil {
			results = append(results, e)
		}
	}
	if resp.Threat != "" && resp.Threat != "unknown" {
		malType := event.MALICIOUS_IPADDR
		if evt.Type == event.AFFILIATE_IPADDR {
			malType = event.MALICIOUS_AFFILIATE_IPADDR
		}
		descr := fmt.Sprintf("%s (risk level: %s) [%s]", resp.Threat, resp.RiskLevel, evt.Data)
		if e, err := event.New(malType, descr, "fraudguard", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *FraudGuard) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// IPQualityScore
// ============================================================================

// IPQualityScore queries ipqualityscore.com for IP, email and phone
// fraud scoring. Requires opts["ipqualityscore_api_key"].
type IPQualityScore struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IPQualityScore) Meta() module.Meta {
	return module.Meta{
		Name:           "ipqualityscore",
		Summary:        "Obtain fraud scores for IPs, emails and phone numbers from IPQualityScore.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IPQualityScore) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "ipqualityscore_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IPQualityScore) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.DOMAIN_NAME, event.EMAILADDR, event.PHONE_NUMBER}
}

// ProducedEvents returns emitted event types.
func (m *IPQualityScore) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_INTERNET_NAME,
		event.MALICIOUS_EMAILADDR,
		event.MALICIOUS_PHONE_NUMBER,
		event.GEOINFO,
		event.RAW_RIR_DATA,
	}
}

// ipqsResp is the relevant subset of the IPQualityScore JSON response.
type ipqsResp struct {
	Success       bool   `json:"success"`
	FraudScore    int    `json:"fraud_score"`
	RecentAbuse   bool   `json:"recent_abuse"`
	BotStatus     bool   `json:"bot_status"`
	City          string `json:"city"`
	Region        string `json:"region"`
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	ZipCode       string `json:"zip_code"`
	Honeypot      bool   `json:"honeypot"`
	SpamTrapScore string `json:"spam_trap_score"`
	Active        bool   `json:"active"`
	Risky         bool   `json:"risky"`
}

// HandleEvent queries IPQualityScore for the given target.
func (m *IPQualityScore) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var endpoint string
	switch evt.Type {
	case event.IP_ADDRESS, event.DOMAIN_NAME:
		endpoint = "ip"
	case event.EMAILADDR:
		endpoint = "email"
	case event.PHONE_NUMBER:
		endpoint = "phone"
	default:
		return nil, nil
	}
	u := "https://ipqualityscore.com/api/json/" + endpoint + "/" + url.PathEscape(m.apiKey) + "/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipqsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if !resp.Success {
		return nil, nil
	}

	malicious := resp.FraudScore >= 75 || resp.RecentAbuse || resp.BotStatus
	var results []*event.Event
	if malicious {
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "ipqualityscore", evt); err == nil {
			results = append(results, e)
		}
		descr := fmt.Sprintf("IPQualityScore [%s] - FRAUD SCORE: %d", evt.Data, resp.FraudScore)
		var malType event.Type
		switch evt.Type {
		case event.IP_ADDRESS:
			malType = event.MALICIOUS_IPADDR
		case event.DOMAIN_NAME:
			malType = event.MALICIOUS_INTERNET_NAME
		case event.EMAILADDR:
			malType = event.MALICIOUS_EMAILADDR
		case event.PHONE_NUMBER:
			malType = event.MALICIOUS_PHONE_NUMBER
		}
		if malType != "" {
			if e, err := event.New(malType, descr, "ipqualityscore", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	if evt.Type == event.IP_ADDRESS || evt.Type == event.DOMAIN_NAME {
		country := resp.Country
		if country == "" {
			country = resp.CountryCode
		}
		var geoParts []string
		if resp.City != "" {
			geoParts = append(geoParts, resp.City)
		}
		if resp.Region != "" {
			geoParts = append(geoParts, resp.Region)
		}
		if country != "" {
			geoParts = append(geoParts, country)
		}
		if len(geoParts) > 0 {
			if e, err := event.New(event.GEOINFO, strings.Join(geoParts, ", "), "ipqualityscore", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *IPQualityScore) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// FullContact
// ============================================================================

// FullContact queries api.fullcontact.com for company / person enrichment.
// Requires opts["fullcontact_api_key"].
type FullContact struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *FullContact) Meta() module.Meta {
	return module.Meta{
		Name:           "fullcontact",
		Summary:        "Enrich domains and emails via FullContact.",
		Categories:     []string{"Real World"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *FullContact) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "fullcontact_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *FullContact) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.EMAILADDR}
}

// ProducedEvents returns emitted event types.
func (m *FullContact) ProducedEvents() []event.Type {
	return []event.Type{
		event.EMAILADDR,
		event.EMAILADDR_GENERIC,
		event.PHONE_NUMBER,
		event.GEOINFO,
		event.PHYSICAL_ADDRESS,
		event.RAW_RIR_DATA,
	}
}

// fullContactCompanyResp is the relevant subset of /v3/company.enrich.
// Status is the API-level status code (0 or 200 on success).
type fullContactCompanyResp struct {
	Status  int `json:"status"`
	Details struct {
		Emails    []fullContactValue    `json:"emails"`
		Phones    []fullContactValue    `json:"phones"`
		Locations []fullContactLocation `json:"locations"`
		KeyPeople []struct {
			FullName string `json:"fullName"`
		} `json:"keyPeople"`
	} `json:"details"`
	// Sometimes the v3 API returns these at the top level.
	Emails    []fullContactValue    `json:"emails"`
	Phones    []fullContactValue    `json:"phones"`
	Locations []fullContactLocation `json:"locations"`
}

// fullContactValue is a generic {value: ...} entry.
type fullContactValue struct {
	Value string `json:"value"`
}

// fullContactLocation is one location record.
type fullContactLocation struct {
	City      string `json:"city"`
	Country   string `json:"country"`
	Formatted string `json:"formatted"`
}

// fullContactPersonResp is the relevant subset of /v3/person.enrich.
// Status is the API-level status code (0 or 200 on success; 404 etc on miss).
type fullContactPersonResp struct {
	Status   int    `json:"status"`
	FullName string `json:"fullName"`
}

// HandleEvent queries FullContact for the given target.
func (m *FullContact) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	header := func(h http.Header) { h.Set("Authorization", "Bearer "+m.apiKey) }
	var results []*event.Event

	if evt.Type == event.EMAILADDR {
		reqBody, err := json.Marshal(map[string]any{"email": evt.Data})
		if err != nil {
			return nil, nil
		}
		body, ok := majorAPIFetchPOST(ctx, "https://api.fullcontact.com/v3/person.enrich", header, reqBody)
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var resp fullContactPersonResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil
		}
		// Only commit when the response carries a real enrichment
		// signal. An empty/"no match"/error-with-HTTP-200 body leaves
		// committed=false so later events can still retry.
		if resp.Status != 0 && resp.Status != 200 {
			return nil, nil
		}
		if resp.FullName == "" {
			return nil, nil
		}
		committed = true
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "fullcontact", evt); err == nil {
			results = append(results, e)
		}
		if resp.FullName != "" {
			if e, err := event.New(event.RAW_RIR_DATA, "Possible full name: "+resp.FullName, "fullcontact", evt); err == nil {
				results = append(results, e)
			}
		}
		return results, nil
	}

	// DOMAIN_NAME — company enrich
	reqBody, err := json.Marshal(map[string]any{"domain": evt.Data})
	if err != nil {
		return nil, nil
	}
	body, ok := majorAPIFetchPOST(ctx, "https://api.fullcontact.com/v3/company.enrich", header, reqBody)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp fullContactCompanyResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	// API-level success check: bail out (without committing) on
	// explicit non-success status so transient errors can retry.
	if resp.Status != 0 && resp.Status != 200 {
		return nil, nil
	}
	// Require at least one substantive enrichment field before
	// committing. Matches the "silent data loss under degraded
	// upstream behavior" concern from Codex adversarial review.
	hasSignal := len(resp.Details.Emails)+len(resp.Details.Phones)+len(resp.Details.Locations)+len(resp.Details.KeyPeople) > 0 ||
		len(resp.Emails)+len(resp.Phones)+len(resp.Locations) > 0
	if !hasSignal {
		return nil, nil
	}
	committed = true
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "fullcontact", evt); err == nil {
		results = append(results, e)
	}

	emails := resp.Details.Emails
	if len(emails) == 0 {
		emails = resp.Emails
	}
	phones := resp.Details.Phones
	if len(phones) == 0 {
		phones = resp.Phones
	}
	locations := resp.Details.Locations
	if len(locations) == 0 {
		locations = resp.Locations
	}

	for _, em := range emails {
		if em.Value == "" {
			continue
		}
		etype := event.EMAILADDR
		if local := strings.SplitN(em.Value, "@", 2)[0]; isGenericEmailLocal(local) {
			etype = event.EMAILADDR_GENERIC
		}
		if e, err := event.New(etype, em.Value, "fullcontact", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, ph := range phones {
		if ph.Value == "" {
			continue
		}
		if e, err := event.New(event.PHONE_NUMBER, ph.Value, "fullcontact", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, loc := range locations {
		var parts []string
		if loc.City != "" {
			parts = append(parts, loc.City)
		}
		if loc.Country != "" {
			parts = append(parts, loc.Country)
		}
		if len(parts) > 0 {
			if e, err := event.New(event.GEOINFO, strings.Join(parts, ", "), "fullcontact", evt); err == nil {
				results = append(results, e)
			}
		}
		if len(loc.Formatted) > 10 {
			if e, err := event.New(event.PHYSICAL_ADDRESS, loc.Formatted, "fullcontact", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	for _, kp := range resp.Details.KeyPeople {
		if kp.FullName == "" {
			continue
		}
		if e, err := event.New(event.RAW_RIR_DATA, "Possible full name: "+kp.FullName, "fullcontact", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *FullContact) Finish() error { m.seen.clear(); return nil }

// isGenericEmailLocal returns true for common role/generic mailbox prefixes.
func isGenericEmailLocal(local string) bool {
	switch strings.ToLower(local) {
	case "info", "contact", "admin", "support", "sales", "hello", "marketing",
		"webmaster", "abuse", "postmaster", "noreply", "no-reply", "office", "help":
		return true
	}
	return false
}

// ============================================================================
// SpyOnWeb
// ============================================================================

// SpyOnWeb queries api.spyonweb.com for analytics-id and IP based
// hostname pivoting. Requires opts["spyonweb_api_key"].
type SpyOnWeb struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *SpyOnWeb) Meta() module.Meta {
	return module.Meta{
		Name:           "spyonweb",
		Summary:        "Find affiliate domains via SpyOnWeb analytics IDs and co-hosted IPs.",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *SpyOnWeb) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "spyonweb_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *SpyOnWeb) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME, event.WEB_ANALYTICS_ID}
}

// ProducedEvents returns emitted event types.
func (m *SpyOnWeb) ProducedEvents() []event.Type {
	return []event.Type{
		event.CO_HOSTED_SITE,
		event.AFFILIATE_INTERNET_NAME,
		event.WEB_ANALYTICS_ID,
		event.RAW_RIR_DATA,
	}
}

// spyOnWebResp is the subset of the SpyOnWeb response used by
// non-summary endpoints (ip / adsense / analytics). Their result
// buckets nest a simple {items: {<key>: <last_seen>}} map.
type spyOnWebResp struct {
	Status string                                   `json:"status"`
	Result map[string]map[string]spyOnWebResultData `json:"result"`
}

// spyOnWebResultData wraps the items map.
type spyOnWebResultData struct {
	Items map[string]string `json:"items"`
}

// spyOnWebSummaryResp is the distinct shape of the /v1/summary
// response. Per-domain records nest adsense and analytics as sibling
// objects, each carrying its own items map. Parsing against this
// explicit shape (instead of approximating via spyOnWebResp) is what
// Codex adversarial review 2026-04-09 required — the previous
// approximation would have dropped pivots whenever the real nested
// shape was returned.
type spyOnWebSummaryResp struct {
	Status string `json:"status"`
	Result struct {
		Summary map[string]struct {
			Adsense struct {
				Items map[string]string `json:"items"`
			} `json:"adsense"`
			Analytics struct {
				Items map[string]string `json:"items"`
			} `json:"analytics"`
		} `json:"summary"`
	} `json:"result"`
}

// HandleEvent queries SpyOnWeb for the given target.
func (m *SpyOnWeb) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	var endpoint, qry string
	switch evt.Type {
	case event.INTERNET_NAME, event.DOMAIN_NAME:
		endpoint = "summary"
		qry = evt.Data
	case event.IP_ADDRESS:
		endpoint = "ip"
		qry = evt.Data
	case event.WEB_ANALYTICS_ID:
		parts := strings.SplitN(evt.Data, ": ", 2)
		if len(parts) != 2 {
			return nil, nil
		}
		switch parts[0] {
		case "Google AdSense":
			endpoint = "adsense"
		case "Google Analytics":
			endpoint = "analytics"
		default:
			return nil, nil
		}
		qry = parts[1]
	default:
		return nil, nil
	}

	u := "https://api.spyonweb.com/v1/" + endpoint + "/" + url.PathEscape(qry) + "?limit=100&access_token=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}

	var results []*event.Event

	// Summary endpoint uses a distinct nested shape; parse it
	// explicitly rather than reusing spyOnWebResp.
	if endpoint == "summary" {
		var sresp spyOnWebSummaryResp
		if err := json.Unmarshal(body, &sresp); err != nil {
			return nil, nil
		}
		if sresp.Status != "found" {
			return nil, nil
		}
		rec, ok := sresp.Result.Summary[qry]
		if !ok {
			return nil, nil
		}
		committed = true
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "spyonweb", evt); err == nil {
			results = append(results, e)
		}
		for id := range rec.Adsense.Items {
			if e, err := event.New(event.WEB_ANALYTICS_ID, "Google AdSense: "+id, "spyonweb", evt); err == nil {
				results = append(results, e)
			}
		}
		for id := range rec.Analytics.Items {
			if e, err := event.New(event.WEB_ANALYTICS_ID, "Google Analytics: "+id, "spyonweb", evt); err == nil {
				results = append(results, e)
			}
		}
		return results, nil
	}

	var resp spyOnWebResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if resp.Status != "found" {
		return nil, nil
	}
	bucket, ok := resp.Result[endpoint]
	if !ok {
		return nil, nil
	}
	rdata, ok := bucket[qry]
	if !ok {
		return nil, nil
	}
	committed = true
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "spyonweb", evt); err == nil {
		results = append(results, e)
	}

	switch endpoint {
	case "ip":
		for host := range rdata.Items {
			if e, err := event.New(event.CO_HOSTED_SITE, host, "spyonweb", evt); err == nil {
				results = append(results, e)
			}
		}
	case "adsense", "analytics":
		for host := range rdata.Items {
			if e, err := event.New(event.AFFILIATE_INTERNET_NAME, host, "spyonweb", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *SpyOnWeb) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("pulsedive", func() module.Module { return &Pulsedive{} })
	module.Register("binaryedge", func() module.Module { return &BinaryEdge{} })
	module.Register("fraudguard", func() module.Module { return &FraudGuard{} })
	module.Register("ipqualityscore", func() module.Module { return &IPQualityScore{} })
	module.Register("fullcontact", func() module.Module { return &FullContact{} })
	module.Register("spyonweb", func() module.Module { return &SpyOnWeb{} })
}
