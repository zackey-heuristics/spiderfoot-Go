// Package modules — Batch 18: IP geolocation & enrichment APIs.
//
// This file implements pragmatic ports of:
//   - ipapico       (ipapi.co /json/; no key, free tier)
//   - ipapicom      (api.ipapi.com /api/{ip}?access_key=; keyed)
//   - ipregistry    (api.ipregistry.co /{ip}?key=; keyed, geo + reputation)
//   - ipstack       (api.ipstack.com /{ip}?access_key=; keyed, geo only)
//   - neutrinoapi   (neutrinoapi.com ip-info/ip-blocklist/host-reputation/phone-validate; user_id + api_key)
//
// All keyed modules use vendor-prefixed opt keys with no generic
// fallback (Batch 11+ convention). All requests use HTTPS even where
// the Python source used plaintext HTTP (Batch 15-17 review rule).
// Commits to the seenSet happen only after a substantive, documented
// success field is observed in the response body.

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
// ipapi.co (free, no key)
// ============================================================================

// IPAPICo queries ipapi.co for IP geolocation. No API key required.
type IPAPICo struct {
	seen seenSet
}

// Meta returns module metadata.
func (m *IPAPICo) Meta() module.Meta {
	return module.Meta{
		Name:       "ipapico",
		Summary:    "Queries ipapi.co to identify geolocation of IP addresses.",
		Categories: []string{"Real World"},
	}
}

// Setup is a no-op; ipapi.co does not require credentials.
func (m *IPAPICo) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *IPAPICo) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *IPAPICo) ProducedEvents() []event.Type {
	return []event.Type{event.GEOINFO, event.RAW_RIR_DATA}
}

// ipapiCoResp mirrors the documented ipapi.co /json/ shape.
type ipapiCoResp struct {
	City        string `json:"city"`
	Region      string `json:"region"`
	RegionCode  string `json:"region_code"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	Error       bool   `json:"error"`
}

// HandleEvent queries ipapi.co for the address in evt.
func (m *IPAPICo) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://ipapi.co/" + url.PathEscape(evt.Data) + "/json/"
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipapiCoResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if resp.Error || resp.Country == "" {
		return nil, nil
	}
	committed = true

	parts := []string{}
	for _, p := range []string{resp.City, resp.Region, resp.RegionCode, resp.CountryName, resp.Country} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	var results []*event.Event
	if e, err := event.New(event.GEOINFO, strings.Join(parts, ", "), "ipapico", evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "ipapico", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *IPAPICo) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// ipapi.com (keyed)
// ============================================================================

// IPAPICom queries api.ipapi.com for IP geolocation. Requires
// opts["ipapicom_api_key"].
type IPAPICom struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IPAPICom) Meta() module.Meta {
	return module.Meta{
		Name:           "ipapicom",
		Summary:        "Queries ipapi.com to identify geolocation of IP addresses.",
		Categories:     []string{"Real World"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IPAPICom) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "ipapicom_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IPAPICom) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *IPAPICom) ProducedEvents() []event.Type {
	return []event.Type{event.GEOINFO, event.PHYSICAL_COORDINATES, event.RAW_RIR_DATA}
}

// ipapiComResp mirrors the documented api.ipapi.com response shape.
type ipapiComResp struct {
	Success     *bool   `json:"success"`
	City        string  `json:"city"`
	RegionName  string  `json:"region_name"`
	RegionCode  string  `json:"region_code"`
	CountryName string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// HandleEvent queries api.ipapi.com for the given IP.
func (m *IPAPICom) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.ipapi.com/api/" + url.PathEscape(evt.Data) + "?access_key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipapiComResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	// Error responses carry success:false; success field absent on OK.
	if resp.Success != nil && !*resp.Success {
		return nil, nil
	}
	if resp.CountryName == "" {
		return nil, nil
	}
	committed = true

	parts := []string{}
	for _, p := range []string{resp.City, resp.RegionName, resp.RegionCode, resp.CountryName, resp.CountryCode} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	var results []*event.Event
	if e, err := event.New(event.GEOINFO, strings.Join(parts, ", "), "ipapicom", evt); err == nil {
		results = append(results, e)
	}
	if resp.Latitude != 0 && resp.Longitude != 0 {
		coord := fmt.Sprintf("%v, %v", resp.Latitude, resp.Longitude)
		if e, err := event.New(event.PHYSICAL_COORDINATES, coord, "ipapicom", evt); err == nil {
			results = append(results, e)
		}
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "ipapicom", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *IPAPICom) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// ipregistry
// ============================================================================

// IPRegistry queries api.ipregistry.co for IP geolocation and
// reputation. Requires opts["ipregistry_api_key"].
type IPRegistry struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IPRegistry) Meta() module.Meta {
	return module.Meta{
		Name:           "ipregistry",
		Summary:        "Query the ipregistry.co database for reputation and geo-location.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IPRegistry) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "ipregistry_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IPRegistry) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.IPV6_ADDRESS}
}

// ProducedEvents returns emitted event types.
func (m *IPRegistry) ProducedEvents() []event.Type {
	return []event.Type{
		event.GEOINFO,
		event.MALICIOUS_IPADDR,
		event.PHYSICAL_COORDINATES,
		event.RAW_RIR_DATA,
	}
}

// ipRegistryResp mirrors the documented ipregistry.co response shape.
type ipRegistryResp struct {
	Location struct {
		City    string `json:"city"`
		Postal  string `json:"postal"`
		Country struct {
			Name string `json:"name"`
		} `json:"country"`
		Region struct {
			Name string `json:"name"`
		} `json:"region"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"location"`
	Security struct {
		IsAbuser   bool `json:"is_abuser"`
		IsAttacker bool `json:"is_attacker"`
		IsThreat   bool `json:"is_threat"`
	} `json:"security"`
}

// HandleEvent queries ipregistry.co for the given IP.
func (m *IPRegistry) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.ipregistry.co/" + url.PathEscape(evt.Data) + "?key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipRegistryResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	loc := resp.Location
	hasGeo := loc.City != "" || loc.Region.Name != "" || loc.Country.Name != "" || loc.Postal != ""
	hasCoord := loc.Latitude != 0 && loc.Longitude != 0
	hasSec := resp.Security.IsAbuser || resp.Security.IsAttacker || resp.Security.IsThreat
	if !hasGeo && !hasCoord && !hasSec {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if hasGeo {
		parts := []string{}
		for _, p := range []string{loc.City, loc.Region.Name, loc.Postal, loc.Country.Name} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		if len(parts) > 0 {
			if e, err := event.New(event.GEOINFO, strings.Join(parts, ", "), "ipregistry", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	if hasCoord {
		coord := fmt.Sprintf("%v, %v", loc.Latitude, loc.Longitude)
		if e, err := event.New(event.PHYSICAL_COORDINATES, coord, "ipregistry", evt); err == nil {
			results = append(results, e)
		}
	}
	if hasSec {
		if e, err := event.New(event.MALICIOUS_IPADDR, "ipregistry ["+evt.Data+"]", "ipregistry", evt); err == nil {
			results = append(results, e)
		}
	}
	if e, err := event.New(event.RAW_RIR_DATA, string(body), "ipregistry", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *IPRegistry) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// ipstack
// ============================================================================

// IPStack queries api.ipstack.com for IP geolocation. Requires
// opts["ipstack_api_key"].
type IPStack struct {
	seen   seenSet
	apiKey string
}

// Meta returns module metadata.
func (m *IPStack) Meta() module.Meta {
	return module.Meta{
		Name:           "ipstack",
		Summary:        "Identifies the physical location of IP addresses identified using ipstack.com.",
		Categories:     []string{"Real World"},
		RequiresAPIKey: true,
	}
}

// Setup reads the API key from opts.
func (m *IPStack) Setup(opts map[string]any) error {
	m.apiKey = optString(opts, "ipstack_api_key", "")
	return nil
}

// WatchedEvents returns consumed event types.
func (m *IPStack) WatchedEvents() []event.Type { return []event.Type{event.IP_ADDRESS} }

// ProducedEvents returns emitted event types.
func (m *IPStack) ProducedEvents() []event.Type { return []event.Type{event.GEOINFO} }

// ipStackResp mirrors the documented ipstack.com response shape.
type ipStackResp struct {
	Success     *bool  `json:"success"`
	CountryName string `json:"country_name"`
}

// HandleEvent queries ipstack.com for the given IP.
func (m *IPStack) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	u := "https://api.ipstack.com/" + url.PathEscape(evt.Data) + "?access_key=" + url.QueryEscape(m.apiKey)
	body, ok := majorAPIFetch(ctx, u, nil)
	if !ok || len(body) == 0 {
		return nil, nil
	}
	var resp ipStackResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil
	}
	if resp.Success != nil && !*resp.Success {
		return nil, nil
	}
	if resp.CountryName == "" {
		return nil, nil
	}
	committed = true

	var results []*event.Event
	if e, err := event.New(event.GEOINFO, resp.CountryName, "ipstack", evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish clears state.
func (m *IPStack) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// NeutrinoAPI
// ============================================================================

// NeutrinoAPI queries neutrinoapi.com for IP info, IP blocklist, host
// reputation, and phone-validate data. Requires
// opts["neutrinoapi_api_key_user"] and opts["neutrinoapi_api_key_secret"].
type NeutrinoAPI struct {
	seen   seenSet
	userID string
	apiKey string
}

// Meta returns module metadata.
func (m *NeutrinoAPI) Meta() module.Meta {
	return module.Meta{
		Name:           "neutrinoapi",
		Summary:        "Search NeutrinoAPI for phone location, IP info, and host reputation.",
		Categories:     []string{"Reputation Systems"},
		RequiresAPIKey: true,
	}
}

// Setup reads the user ID and API key from opts.
func (m *NeutrinoAPI) Setup(opts map[string]any) error {
	m.userID = optString(opts, "neutrinoapi_api_key_user", "")
	m.apiKey = optString(opts, "neutrinoapi_api_key_secret", "")
	return nil
}

// WatchedEvents returns consumed event types. Host-reputation is
// routed on INTERNET_NAME / DOMAIN_NAME events; ip-info and
// ip-blocklist are routed on IP events; phone-validate on phones.
func (m *NeutrinoAPI) WatchedEvents() []event.Type {
	return []event.Type{
		event.IP_ADDRESS,
		event.IPV6_ADDRESS,
		event.INTERNET_NAME,
		event.DOMAIN_NAME,
		event.PHONE_NUMBER,
	}
}

// ProducedEvents returns emitted event types.
func (m *NeutrinoAPI) ProducedEvents() []event.Type {
	return []event.Type{
		event.RAW_RIR_DATA,
		event.BLACKLISTED_IPADDR,
		event.MALICIOUS_IPADDR,
		event.GEOINFO,
	}
}

// neutrinoIPInfoResp mirrors NeutrinoAPI ip-info response shape.
type neutrinoIPInfoResp struct {
	City        string `json:"city"`
	Region      string `json:"region"`
	CountryCode string `json:"country-code"`
}

// neutrinoIPBlocklistResp mirrors NeutrinoAPI ip-blocklist response.
type neutrinoIPBlocklistResp struct {
	IsListed bool `json:"is-listed"`
}

// neutrinoHostReputationResp mirrors NeutrinoAPI host-reputation.
type neutrinoHostReputationResp struct {
	IsListed bool `json:"is-listed"`
}

// neutrinoPhoneValidateResp mirrors NeutrinoAPI phone-validate.
type neutrinoPhoneValidateResp struct {
	Valid    bool   `json:"valid"`
	Location string `json:"location"`
	Country  string `json:"country"`
}

// neutrinoPost performs a form-encoded POST to a neutrino endpoint.
func (m *NeutrinoAPI) neutrinoPost(ctx context.Context, path string, form url.Values) ([]byte, bool) {
	form.Set("output-format", "json")
	form.Set("user-id", m.userID)
	form.Set("api-key", m.apiKey)
	return majorAPIFetchPOST(ctx, "https://neutrinoapi.com/"+path, func(h http.Header) {
		h.Set("Content-Type", "application/x-www-form-urlencoded")
	}, []byte(form.Encode()))
}

// HandleEvent queries NeutrinoAPI for the given event.
func (m *NeutrinoAPI) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if m.userID == "" || m.apiKey == "" {
		return nil, nil
	}

	var results []*event.Event

	if evt.Type == event.PHONE_NUMBER {
		body, ok := m.neutrinoPost(ctx, "phone-validate", url.Values{"number": {evt.Data}})
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var p neutrinoPhoneValidateResp
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, nil
		}
		if !p.Valid || (p.Location == "" && p.Country == "") {
			return nil, nil
		}
		committed = true
		loc := p.Location
		if p.Country != "" && p.Country != p.Location {
			if loc == "" {
				loc = p.Country
			} else {
				loc = loc + ", " + p.Country
			}
		}
		if e, err := event.New(event.GEOINFO, loc, "neutrinoapi", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "neutrinoapi", evt); err == nil {
			results = append(results, e)
		}
		return results, nil
	}

	emitted := false

	// Host/domain events → host-reputation only. Routing
	// host-reputation on IP data (as the pre-review code did) was
	// both wrong and an unnecessary credit burn. See Codex
	// adversarial review 2026-04-09.
	if evt.Type == event.INTERNET_NAME || evt.Type == event.DOMAIN_NAME {
		body, ok := m.neutrinoPost(ctx, "host-reputation", url.Values{"host": {evt.Data}})
		if !ok || len(body) == 0 {
			return nil, nil
		}
		var hr neutrinoHostReputationResp
		if err := json.Unmarshal(body, &hr); err != nil {
			return nil, nil
		}
		if !hr.IsListed {
			return nil, nil
		}
		if e, err := event.New(event.MALICIOUS_IPADDR, "NeutrinoAPI - Host Reputation ["+evt.Data+"]", "neutrinoapi", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(event.BLACKLISTED_IPADDR, "NeutrinoAPI - Host Reputation ["+evt.Data+"]", "neutrinoapi", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(event.RAW_RIR_DATA, string(body), "neutrinoapi", evt); err == nil {
			results = append(results, e)
		}
		committed = true
		return results, nil
	}

	// IP_ADDRESS / IPV6_ADDRESS → ip-info + ip-blocklist.
	if body, ok := m.neutrinoPost(ctx, "ip-info", url.Values{"ip": {evt.Data}}); ok && len(body) > 0 {
		var ipi neutrinoIPInfoResp
		if err := json.Unmarshal(body, &ipi); err == nil {
			if ipi.City != "" && ipi.Region != "" && ipi.CountryCode != "" {
				loc := ipi.City + ", " + ipi.Region + ", " + ipi.CountryCode
				if e, err := event.New(event.GEOINFO, loc, "neutrinoapi", evt); err == nil {
					results = append(results, e)
					emitted = true
				}
			}
		}
	}
	if body, ok := m.neutrinoPost(ctx, "ip-blocklist", url.Values{"ip": {evt.Data}, "vpn-lookup": {"true"}}); ok && len(body) > 0 {
		var ibl neutrinoIPBlocklistResp
		if err := json.Unmarshal(body, &ibl); err == nil && ibl.IsListed {
			if e, err := event.New(event.MALICIOUS_IPADDR, "NeutrinoAPI - IP Blocklist ["+evt.Data+"]", "neutrinoapi", evt); err == nil {
				results = append(results, e)
			}
			if e, err := event.New(event.BLACKLISTED_IPADDR, "NeutrinoAPI - IP Blocklist ["+evt.Data+"]", "neutrinoapi", evt); err == nil {
				results = append(results, e)
			}
			if e, err := event.New(event.RAW_RIR_DATA, string(body), "neutrinoapi", evt); err == nil {
				results = append(results, e)
			}
			emitted = true
		}
	}
	if emitted {
		committed = true
	}
	return results, nil
}

// Finish clears state.
func (m *NeutrinoAPI) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registration
// ============================================================================

func init() {
	module.Register("ipapico", func() module.Module { return &IPAPICo{} })
	module.Register("ipapicom", func() module.Module { return &IPAPICom{} })
	module.Register("ipregistry", func() module.Module { return &IPRegistry{} })
	module.Register("ipstack", func() module.Module { return &IPStack{} })
	module.Register("neutrinoapi", func() module.Module { return &NeutrinoAPI{} })
}
