// Package modules — Batch 12: Major commercial API integrations.
//
// This file implements pragmatic ports of:
//   - shodan         (api.shodan.io host info)
//   - virustotal     (vtapi/v2/{ip-address|domain}/report)
//   - abuseipdb      (api.abuseipdb.com /v2/blacklist)
//   - censys         (search.censys.io /api/v2/hosts/{ip})
//   - greynoise      (api.greynoise.io /v2/noise/context/{ip})
//   - ipinfo         (ipinfo.io /{ip}/json)
//   - securitytrails (api.securitytrails.com /v1/domain/{domain}/subdomains)
//
// All seven modules require a per-vendor API key supplied via opts
// under a vendor-prefixed name (shodan_api_key, virustotal_api_key,
// etc.) and no-op when the key is empty. None accepts a generic
// "api_key" — see TestMajorAPIsRejectGenericAPIKey for the security
// regression that enforces this trust boundary.
//
// Each module ports a single high-value query path of its Python
// counterpart. Netblock CIDR walking, multi-page pagination, and
// secondary search variants are deferred (consistent with Batches
// 7-11 precedent).

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
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// majorAPIHTTPClient is the shared http.Client for Batch 12. We use
// net/http directly (not sflib.HTTPClient) because every module needs
// custom request headers — same rationale as Batch 11's
// emailSvcHTTPClient.
var majorAPIHTTPClient = &http.Client{Timeout: 30 * time.Second}

// majorAPIMaxBody caps upstream response bodies at 16 MiB. Censys and
// Shodan host responses can be relatively large (services arrays).
const majorAPIMaxBody = 16 << 20

// majorAPIFetch performs an HTTP GET and returns the body on 200, or
// (nil, false) on any other status or transport error. Unlike
// doJSONRequest in email_services.go, 404 is treated as a transient
// "not found / release reservation" condition: Shodan returns 404
// for hosts it has never scanned, and the seenSet should release so
// a later, possibly enriched, scan can retry.
func majorAPIFetch(ctx context.Context, rawURL string, setHeaders func(h http.Header)) (body []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spiderfoot-go")
	if setHeaders != nil {
		setHeaders(req.Header)
	}
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

// sfURL wraps a URL in the SpiderFoot inline-link marker so the web
// UI can render the source link next to a finding.
func sfURL(label, link string) string {
	return label + "\n<SFURL>" + link + "</SFURL>"
}

// majorAPIFetchPOST performs an HTTP POST and returns the body on
// 200, or (nil, false) otherwise. Content-Type defaults to
// application/json unless setHeaders overrides it.
func majorAPIFetchPOST(ctx context.Context, rawURL string, setHeaders func(h http.Header), body []byte) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spiderfoot-go")
	if setHeaders != nil {
		setHeaders(req.Header)
	}
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

// basicAuthHeader returns the "Basic <base64(user:pass)>" value.
func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// ============================================================================
// Shodan
// ============================================================================

// Shodan queries api.shodan.io for host information by IP. Requires
// opts["shodan_api_key"].
type Shodan struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *Shodan) Meta() module.Meta {
	return module.Meta{
		Name:           "shodan",
		Summary:        "Look up IP addresses on Shodan to obtain port, banner, OS, and CVE information.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *Shodan) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "shodan_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Shodan) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *Shodan) ProducedEvents() []event.Type {
	return []event.Type{
		event.OPERATING_SYSTEM,
		event.DEVICE_TYPE,
		event.GEOINFO,
		event.TCP_PORT_OPEN,
		event.TCP_PORT_OPEN_BANNER,
		event.BGP_AS_MEMBER,
		event.VULNERABILITY_GENERAL,
		event.RAW_RIR_DATA,
	}
}

// shodanService captures one entry of the host's services array.
type shodanService struct {
	Port    int      `json:"port"`
	Banner  string   `json:"data"`
	Vulns   any      `json:"vulns"`
	Product string   `json:"product"`
	Version string   `json:"version"`
	HTTP    struct{} `json:"http"`
}

// shodanHost captures the relevant subset of a /shodan/host/{ip} response.
type shodanHost struct {
	OS          string          `json:"os"`
	DeviceType  string          `json:"devtype"`
	City        string          `json:"city"`
	CountryName string          `json:"country_name"`
	ASN         string          `json:"asn"`
	Data        []shodanService `json:"data"`
}

// HandleEvent looks up the IP on Shodan and emits findings.
func (m *Shodan) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.shodan.io/shodan/host/" + url.PathEscape(evt.Data) + "?key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var host shodanHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "shodan", evt); err == nil {
		results = append(results, e)
	}
	if host.OS != "" {
		if e, err := event.New(event.OPERATING_SYSTEM, host.OS, "shodan", evt); err == nil {
			results = append(results, e)
		}
	}
	if host.DeviceType != "" {
		if e, err := event.New(event.DEVICE_TYPE, host.DeviceType, "shodan", evt); err == nil {
			results = append(results, e)
		}
	}
	if host.CountryName != "" {
		geo := host.CountryName
		if host.City != "" {
			geo = host.City + ", " + host.CountryName
		}
		if e, err := event.New(event.GEOINFO, geo, "shodan", evt); err == nil {
			results = append(results, e)
		}
	}
	if host.ASN != "" {
		asn := strings.TrimPrefix(host.ASN, "AS")
		if e, err := event.New(event.BGP_AS_MEMBER, asn, "shodan", evt); err == nil {
			results = append(results, e)
		}
	}
	emittedPort := make(map[int]bool)
	for _, s := range host.Data {
		if s.Port > 0 && !emittedPort[s.Port] {
			emittedPort[s.Port] = true
			portStr := fmt.Sprintf("%s:%d", evt.Data, s.Port)
			if e, err := event.New(event.TCP_PORT_OPEN, portStr, "shodan", evt); err == nil {
				results = append(results, e)
			}
			if s.Banner != "" {
				if e, err := event.New(event.TCP_PORT_OPEN_BANNER, s.Banner, "shodan", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		// Vulns may be a map[string]any (CVE → details) or an array.
		switch v := s.Vulns.(type) {
		case map[string]any:
			for cve := range v {
				if e, err := event.New(event.VULNERABILITY_GENERAL, cve, "shodan", evt); err == nil {
					results = append(results, e)
				}
			}
		case []any:
			for _, item := range v {
				if cve, ok := item.(string); ok {
					if e, err := event.New(event.VULNERABILITY_GENERAL, cve, "shodan", evt); err == nil {
						results = append(results, e)
					}
				}
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Shodan) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// VirusTotal
// ============================================================================

// VirusTotal queries the public v2 API for IP and domain reports.
// Requires opts["virustotal_api_key"].
type VirusTotal struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *VirusTotal) Meta() module.Meta {
	return module.Meta{
		Name:           "virustotal",
		Summary:        "Obtain information from VirusTotal about identified IP addresses and domains.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *VirusTotal) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "virustotal_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *VirusTotal) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.INTERNET_NAME, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *VirusTotal) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_INTERNET_NAME,
		event.AFFILIATE_INTERNET_NAME,
		event.INTERNET_NAME,
	}
}

// vtReport captures the relevant subset of an IP/domain report.
type vtReport struct {
	DetectedURLs   []any    `json:"detected_urls"`
	DomainSiblings []string `json:"domain_siblings"`
	Subdomains     []string `json:"subdomains"`
}

// HandleEvent queries VirusTotal for the given IP or domain.
func (m *VirusTotal) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	var maliciousType event.Type
	var detailURL string
	switch evt.Type {
	case event.IP_ADDRESS:
		u = "https://www.virustotal.com/vtapi/v2/ip-address/report?ip=" + url.QueryEscape(evt.Data) + "&apikey=" + url.QueryEscape(m.apiKey)
		maliciousType = event.MALICIOUS_IPADDR
		detailURL = "https://www.virustotal.com/en/ip-address/" + url.PathEscape(evt.Data) + "/information/"
	case event.INTERNET_NAME, event.DOMAIN_NAME:
		u = "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + url.QueryEscape(evt.Data) + "&apikey=" + url.QueryEscape(m.apiKey)
		maliciousType = event.MALICIOUS_INTERNET_NAME
		detailURL = "https://www.virustotal.com/en/domain/" + url.PathEscape(evt.Data) + "/information/"
	default:
		return nil, nil
	}

	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var report vtReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if len(report.DetectedURLs) > 0 {
		data := sfURL("VirusTotal ["+evt.Data+"]", detailURL)
		if e, err := event.New(maliciousType, data, "virustotal", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, sib := range report.DomainSiblings {
		sib = strings.TrimSpace(sib)
		if sib == "" {
			continue
		}
		if e, err := event.New(event.AFFILIATE_INTERNET_NAME, sib, "virustotal", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, sub := range report.Subdomains {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		if e, err := event.New(event.INTERNET_NAME, sub, "virustotal", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *VirusTotal) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// AbuseIPDB
// ============================================================================

// AbuseIPDB downloads the high-confidence blacklist once per scan and
// performs membership checks. Requires opts["abuseipdb_api_key"].
type AbuseIPDB struct {
	apiKey string

	seen seenSet

	// loadMu serializes the one-time blacklist fetch. It is held for
	// the entire HTTP roundtrip so concurrent callers do NOT all race
	// to issue their own fetch (thundering herd). Once loaded is
	// true, subsequent calls take the fast path under dataMu.
	loadMu sync.Mutex

	dataMu   sync.RWMutex
	loaded   bool
	loadErr  bool
	blackset map[string]bool
}

// Meta returns module metadata.
func (m *AbuseIPDB) Meta() module.Meta {
	return module.Meta{
		Name:           "abuseipdb",
		Summary:        "Check if an IP address appears in the AbuseIPDB blacklist.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *AbuseIPDB) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "abuseipdb_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *AbuseIPDB) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *AbuseIPDB) ProducedEvents() []event.Type {
	return []event.Type{
		event.BLACKLISTED_IPADDR,
		event.MALICIOUS_IPADDR,
		event.BLACKLISTED_AFFILIATE_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
	}
}

// loadBlacklist fetches the AbuseIPDB plaintext blacklist on first
// call. Returns true on success. A failed fetch resets state so the
// next event will retry. Holds loadMu across the HTTP roundtrip to
// prevent concurrent callers from stampeding the upstream.
func (m *AbuseIPDB) loadBlacklist(ctx context.Context) bool {
	m.dataMu.RLock()
	if m.loaded {
		ok := !m.loadErr
		m.dataMu.RUnlock()
		return ok
	}
	m.dataMu.RUnlock()

	m.loadMu.Lock()
	defer m.loadMu.Unlock()

	// Re-check under loadMu in case another goroutine loaded while we waited.
	m.dataMu.RLock()
	if m.loaded {
		ok := !m.loadErr
		m.dataMu.RUnlock()
		return ok
	}
	m.dataMu.RUnlock()

	u := "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000&plaintext=1"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Accept", "text/plain")
		h.Set("Key", m.apiKey)
	})

	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	if !ok || len(body) == 0 {
		// Transient failure: record error but do NOT set loaded, so
		// the next event retries. We only cache successful loads.
		m.loadErr = true
		return false
	}
	set := make(map[string]bool, 1024)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = true
	}
	m.blackset = set
	m.loaded = true
	m.loadErr = false
	return true
}

// HandleEvent checks the IP against the cached blacklist.
func (m *AbuseIPDB) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if !m.loadBlacklist(ctx) {
		return nil, nil
	}
	// Blacklist fetch succeeded — membership decision is definitive.
	committed = true
	m.dataMu.RLock()
	hit := m.blackset[evt.Data]
	m.dataMu.RUnlock()
	if !hit {
		return nil, nil
	}
	data := sfURL("AbuseIPDB ["+evt.Data+"]", "https://www.abuseipdb.com/check/"+url.PathEscape(evt.Data))
	blType := event.BLACKLISTED_IPADDR
	malType := event.MALICIOUS_IPADDR
	if evt.Type == event.AFFILIATE_IPADDR {
		blType = event.BLACKLISTED_AFFILIATE_IPADDR
		malType = event.MALICIOUS_AFFILIATE_IPADDR
	}
	var results []*event.Event
	if e, err := event.New(blType, data, "abuseipdb", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(malType, data, "abuseipdb", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish resets cached state so the next scan re-downloads the blacklist.
func (m *AbuseIPDB) Finish() error {
	m.dataMu.Lock()
	m.loaded = false
	m.loadErr = false
	m.blackset = nil
	m.dataMu.Unlock()
	m.seen.clear()
	return nil
}

// ============================================================================
// Censys
// ============================================================================

// Censys queries search.censys.io /api/v2/hosts/{ip}. Requires both
// opts["censys_api_key_uid"] and opts["censys_api_key_secret"].
type Censys struct {
	seen   seenSet
	uid    string
	secret string
}

// Meta returns module metadata.
func (m *Censys) Meta() module.Meta {
	return module.Meta{
		Name:           "censys",
		Summary:        "Obtain host information from Censys.io for a given IP address.",
		Categories:     []string{"Search Engines"},
		RequiresAPIKey: true,
	}
}

// Setup reads both API credentials from opts.
func (m *Censys) Setup(opts map[string]any) error {
	m.uid = optString(opts, "censys_api_key_uid", "")
	m.secret = optString(opts, "censys_api_key_secret", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *Censys) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *Censys) ProducedEvents() []event.Type {
	return []event.Type{
		event.TCP_PORT_OPEN,
		event.UDP_PORT_OPEN,
		event.TCP_PORT_OPEN_BANNER,
		event.SOFTWARE_USED,
		event.GEOINFO,
		event.BGP_AS_MEMBER,
		event.OPERATING_SYSTEM,
		event.RAW_RIR_DATA,
	}
}

// censysSoftware represents one entry of a service.software array.
type censysSoftware struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// censysService represents one entry of result.services.
type censysService struct {
	Port              int              `json:"port"`
	Banner            string           `json:"banner"`
	TransportProtocol string           `json:"transport_protocol"`
	Software          []censysSoftware `json:"software"`
}

// censysOS represents result.operating_system.
type censysOS struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// censysLocation represents result.location.
type censysLocation struct {
	City    string `json:"city"`
	Country string `json:"country"`
}

// censysAS represents result.autonomous_system.
type censysAS struct {
	ASN int `json:"asn"`
}

// censysHost is the relevant subset of /api/v2/hosts/{ip}.
type censysHost struct {
	Result struct {
		Services         []censysService `json:"services"`
		OperatingSystem  *censysOS       `json:"operating_system"`
		Location         censysLocation  `json:"location"`
		AutonomousSystem censysAS        `json:"autonomous_system"`
	} `json:"result"`
}

// HandleEvent queries Censys for the given IP.
func (m *Censys) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.uid == "" || m.secret == "" {
		return nil, nil
	}

	u := "https://search.censys.io/api/v2/hosts/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", basicAuthHeader(m.uid, m.secret))
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var host censysHost
	if err := json.Unmarshal(body, &host); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "censys", evt); err == nil {
		results = append(results, e)
	}
	loc := host.Result.Location
	if loc.Country != "" {
		geo := loc.Country
		if loc.City != "" {
			geo = loc.City + ", " + loc.Country
		}
		if e, err := event.New(event.GEOINFO, geo, "censys", evt); err == nil {
			results = append(results, e)
		}
	}
	if asn := host.Result.AutonomousSystem.ASN; asn > 0 {
		if e, err := event.New(event.BGP_AS_MEMBER, fmt.Sprintf("%d", asn), "censys", evt); err == nil {
			results = append(results, e)
		}
	}
	if os := host.Result.OperatingSystem; os != nil {
		osStr := strings.TrimSpace(os.Vendor + " " + os.Product + " " + os.Version)
		if osStr != "" {
			if e, err := event.New(event.OPERATING_SYSTEM, osStr, "censys", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	emittedPort := make(map[string]bool)
	for _, s := range host.Result.Services {
		if s.Port <= 0 {
			continue
		}
		portType := event.TCP_PORT_OPEN
		if strings.EqualFold(s.TransportProtocol, "UDP") {
			portType = event.UDP_PORT_OPEN
		}
		key := fmt.Sprintf("%s/%d", s.TransportProtocol, s.Port)
		if !emittedPort[key] {
			emittedPort[key] = true
			portStr := fmt.Sprintf("%s:%d", evt.Data, s.Port)
			if e, err := event.New(portType, portStr, "censys", evt); err == nil {
				results = append(results, e)
			}
			if s.Banner != "" && portType == event.TCP_PORT_OPEN {
				if e, err := event.New(event.TCP_PORT_OPEN_BANNER, s.Banner, "censys", evt); err == nil {
					results = append(results, e)
				}
			}
		}
		for _, sw := range s.Software {
			swStr := strings.TrimSpace(sw.Vendor + " " + sw.Product + " " + sw.Version)
			if swStr == "" {
				continue
			}
			if e, err := event.New(event.SOFTWARE_USED, swStr, "censys", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Censys) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// GreyNoise
// ============================================================================

// GreyNoise queries api.greynoise.io /v2/noise/context/{ip}. Requires
// opts["greynoise_api_key"].
type GreyNoise struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *GreyNoise) Meta() module.Meta {
	return module.Meta{
		Name:           "greynoise",
		Summary:        "Check GreyNoise for context about an IP address (mass-scanning detection).",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *GreyNoise) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "greynoise_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *GreyNoise) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
}

// ProducedEvents returns emitted event types.
func (m *GreyNoise) ProducedEvents() []event.Type {
	return []event.Type{
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
		event.COMPANY_NAME,
		event.GEOINFO,
		event.BGP_AS_MEMBER,
		event.OPERATING_SYSTEM,
		event.RAW_RIR_DATA,
	}
}

// gnContext is the relevant subset of /v2/noise/context/{ip}.
type gnContext struct {
	Seen           bool   `json:"seen"`
	Classification string `json:"classification"`
	Metadata       struct {
		Country      string `json:"country"`
		ASN          string `json:"asn"`
		Organization string `json:"organization"`
		OS           string `json:"os"`
	} `json:"metadata"`
	Tags []string `json:"tags"`
	CVE  []string `json:"cve"`
}

// HandleEvent queries GreyNoise for the given IP.
func (m *GreyNoise) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.greynoise.io/v2/noise/context/" + url.PathEscape(evt.Data)
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("key", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var ctxResp gnContext
	if err := json.Unmarshal(body, &ctxResp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "greynoise", evt); err == nil {
		results = append(results, e)
	}
	if ctxResp.Metadata.Country != "" {
		if e, err := event.New(event.GEOINFO, ctxResp.Metadata.Country, "greynoise", evt); err == nil {
			results = append(results, e)
		}
	}
	if ctxResp.Metadata.ASN != "" {
		asn := strings.TrimPrefix(ctxResp.Metadata.ASN, "AS")
		if e, err := event.New(event.BGP_AS_MEMBER, asn, "greynoise", evt); err == nil {
			results = append(results, e)
		}
	}
	if ctxResp.Metadata.Organization != "" {
		if e, err := event.New(event.COMPANY_NAME, ctxResp.Metadata.Organization, "greynoise", evt); err == nil {
			results = append(results, e)
		}
	}
	if ctxResp.Metadata.OS != "" {
		if e, err := event.New(event.OPERATING_SYSTEM, ctxResp.Metadata.OS, "greynoise", evt); err == nil {
			results = append(results, e)
		}
	}
	if ctxResp.Seen {
		var sb strings.Builder
		sb.WriteString("GreyNoise - Mass-Scanning IP Detected [")
		sb.WriteString(evt.Data)
		sb.WriteString("]")
		if ctxResp.Classification != "" {
			sb.WriteString("\n - Classification: ")
			sb.WriteString(ctxResp.Classification)
		}
		if len(ctxResp.Tags) > 0 {
			sb.WriteString("\n - Scans For Tags: ")
			sb.WriteString(strings.Join(ctxResp.Tags, ", "))
		}
		if len(ctxResp.CVE) > 0 {
			sb.WriteString("\n - Scans For CVEs: ")
			sb.WriteString(strings.Join(ctxResp.CVE, ", "))
		}
		data := sfURL(sb.String(), "https://viz.greynoise.io/ip/"+url.PathEscape(evt.Data))
		malType := event.MALICIOUS_IPADDR
		if evt.Type == event.AFFILIATE_IPADDR {
			malType = event.MALICIOUS_AFFILIATE_IPADDR
		}
		if e, err := event.New(malType, data, "greynoise", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *GreyNoise) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// IPInfo
// ============================================================================

// IPInfo queries ipinfo.io for geolocation. Requires opts["ipinfo_api_key"].
type IPInfo struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IPInfo) Meta() module.Meta {
	return module.Meta{
		Name:           "ipinfo",
		Summary:        "Look up IP addresses on ipinfo.io for geolocation information.",
		Categories:     []string{"Real World"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IPInfo) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "ipinfo_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IPInfo) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *IPInfo) ProducedEvents() []event.Type {
	return []event.Type{event.GEOINFO, event.RAW_RIR_DATA}
}

// ipInfoResp is the relevant subset of ipinfo.io /{ip}/json.
type ipInfoResp struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

// HandleEvent queries ipinfo.io for the given IP.
func (m *IPInfo) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://ipinfo.io/" + url.PathEscape(evt.Data) + "/json"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("Authorization", "Bearer "+m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipInfoResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	if resp.Country == "" {
		return nil, nil
	}
	parts := []string{}
	if resp.City != "" {
		parts = append(parts, resp.City)
	}
	if resp.Region != "" {
		parts = append(parts, resp.Region)
	}
	parts = append(parts, resp.Country)
	geo := strings.Join(parts, ", ")
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "ipinfo", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(event.GEOINFO, geo, "ipinfo", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *IPInfo) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// SecurityTrails
// ============================================================================

// SecurityTrails queries api.securitytrails.com /v1/domain/{domain}/subdomains.
// Requires opts["securitytrails_api_key"].
type SecurityTrails struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *SecurityTrails) Meta() module.Meta {
	return module.Meta{
		Name:           "securitytrails",
		Summary:        "Obtain passive DNS subdomain information from SecurityTrails.com.",
		Categories:     []string{"Passive DNS"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *SecurityTrails) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "securitytrails_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *SecurityTrails) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns emitted event types.
func (m *SecurityTrails) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.RAW_RIR_DATA}
}

// stSubdomains is the relevant subset of /v1/domain/{domain}/subdomains.
type stSubdomains struct {
	Subdomains []string `json:"subdomains"`
}

// HandleEvent queries SecurityTrails for subdomains of the given domain.
func (m *SecurityTrails) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.securitytrails.com/v1/domain/" + url.PathEscape(evt.Data) + "/subdomains"
	body, ok := majorAPIFetch(ctx, u, func(h http.Header) {
		h.Set("APIKEY", m.apiKey)
	})
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp stSubdomains
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "securitytrails", evt); err == nil {
		results = append(results, e)
	}
	for _, sub := range resp.Subdomains {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		host := sub + "." + evt.Data
		if e, err := event.New(event.INTERNET_NAME, host, "securitytrails", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *SecurityTrails) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("shodan", func() module.Module { return &Shodan{} })
	module.Register("virustotal", func() module.Module { return &VirusTotal{} })
	module.Register("abuseipdb", func() module.Module { return &AbuseIPDB{} })
	module.Register("censys", func() module.Module { return &Censys{} })
	module.Register("greynoise", func() module.Module { return &GreyNoise{} })
	module.Register("ipinfo", func() module.Module { return &IPInfo{} })
	module.Register("securitytrails", func() module.Module { return &SecurityTrails{} })
}
