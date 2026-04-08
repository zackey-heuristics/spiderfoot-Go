// Package modules — Batch 10: Social media and username enumeration.
//
// This file ports the social-network family of modules from Python
// SpiderFoot:
//   - social      (regex extraction of social-profile URLs from links)
//   - accounts    (WhatsMyName username enumeration; sequential, capped)
//   - github      (api.github.com user/repo lookups)
//   - twitter     (legacy HTML scrape — best-effort)
//   - flickr      (homepage API-key extraction — best-effort)
//   - keybase     (keybase.io user/lookup.json)
//   - gravatar    (secure.gravatar.com/<md5>.json)
//   - slideshare  (slideshare HTML meta scrape)
//
// Implementations are pragmatic — multi-threaded enumeration, post-body
// checks, and DNS re-resolution from the Python originals are omitted.
package modules

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// socialClient is the shared HTTP client used by Batch 10 modules.
var socialClient = sflib.NewHTTPClient(sflib.HTTPClientOpts{
	Timeout:   20 * time.Second,
	RateLimit: 2,
})

// ============================================================================
// social — regex-based social URL extractor
// ============================================================================

// socialPatterns maps a service name to a regex matching profile URLs.
// The first capture group must be the username/identifier.
var socialPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"LinkedIn", regexp.MustCompile(`https?://[a-z]+\.linkedin\.com/(?:in|company|pub)/([A-Za-z0-9_\-]+)`)},
	{"GitHub", regexp.MustCompile(`https?://(?:www\.)?github\.com/([A-Za-z0-9_\-]+)/?`)},
	{"Bitbucket", regexp.MustCompile(`https?://(?:www\.)?bitbucket\.org/([A-Za-z0-9_\-]+)/?`)},
	{"GitLab", regexp.MustCompile(`https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_\-]+)/?`)},
	{"Facebook", regexp.MustCompile(`https?://(?:www\.)?facebook\.com/([A-Za-z0-9_\-.]+)/?`)},
	{"YouTube", regexp.MustCompile(`https?://(?:www\.)?youtube\.com/(?:user|channel|c)/([A-Za-z0-9_\-]+)`)},
	{"Twitter", regexp.MustCompile(`https?://(?:www\.)?twitter\.com/([A-Za-z0-9_]{1,15})/?`)},
	{"SlideShare", regexp.MustCompile(`https?://(?:www\.)?slideshare\.net/([A-Za-z0-9_\-]+)/?`)},
	{"Instagram", regexp.MustCompile(`https?://(?:www\.)?instagram\.com/([A-Za-z0-9_\-.]+)/?`)},
}

// Social extracts social-network references from external links.
type Social struct{ seen seenSet }

// Meta returns module metadata.
func (m *Social) Meta() module.Meta {
	return module.Meta{Name: "social", Summary: "Identify social-media profile URLs in linked pages.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Social) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Social) WatchedEvents() []event.Type { return []event.Type{event.LINKED_URL_EXTERNAL} }

// ProducedEvents returns emitted event types.
func (m *Social) ProducedEvents() []event.Type {
	return []event.Type{event.SOCIAL_MEDIA, event.USERNAME}
}

// HandleEvent matches each social-media regex and emits hits.
func (m *Social) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	for _, p := range socialPatterns {
		match := p.re.FindStringSubmatch(evt.Data)
		if match == nil {
			continue
		}
		if e, err := event.New(event.SOCIAL_MEDIA, p.name+": "+match[0], "social", evt); err == nil {
			results = append(results, e)
		}
		if e, err := event.New(event.USERNAME, match[1], "social", evt); err == nil {
			results = append(results, e)
		}
	}
	// Pure regex work, no network — mark seen unconditionally at the end.
	committed = true
	return results, nil
}

// Finish clears state.
func (m *Social) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// accounts — WhatsMyName username enumeration (pragmatic, capped)
// ============================================================================

// wmnSite is one entry from the WhatsMyName JSON dataset.
type wmnSite struct {
	Name      string `json:"name"`
	URICheck  string `json:"uri_check"`
	URIPretty string `json:"uri_pretty"`
	EString   string `json:"e_string"`
	ECode     int    `json:"e_code"`
	MString   string `json:"m_string"`
	MCode     int    `json:"m_code"`
}

// wmnDataset is the wmn-data.json container.
type wmnDataset struct {
	Sites []wmnSite `json:"sites"`
}

// Accounts checks USERNAME values against the WhatsMyName site list.
type Accounts struct {
	seen    seenSet
	mu      sync.Mutex
	dataset *wmnDataset
}

// Meta returns module metadata.
func (m *Accounts) Meta() module.Meta {
	return module.Meta{Name: "accounts", Summary: "Look up usernames on social sites via the WhatsMyName dataset.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Accounts) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Accounts) WatchedEvents() []event.Type { return []event.Type{event.USERNAME} }

// ProducedEvents returns emitted event types.
func (m *Accounts) ProducedEvents() []event.Type { return []event.Type{event.ACCOUNT_EXTERNAL_OWNED} }

// loadDataset lazily downloads the WhatsMyName dataset.
func (m *Accounts) loadDataset(ctx context.Context) (*wmnDataset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dataset != nil {
		return m.dataset, nil
	}
	url := "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
	resp, err := socialClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch wmn-data: %w", err)
	}
	var ds wmnDataset
	if err := json.Unmarshal([]byte(resp.Body), &ds); err != nil {
		return nil, err
	}
	m.dataset = &ds
	return m.dataset, nil
}

// accountsMaxSites caps the number of sites probed per username to keep
// scans bounded. The Python module uses 20 worker threads with no cap.
const accountsMaxSites = 50

// HandleEvent probes up to accountsMaxSites sites for the given username.
func (m *Accounts) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	ds, err := m.loadDataset(ctx)
	if err != nil || ds == nil {
		return nil, nil
	}
	// Dataset loaded — mark as processed. Per-site probe errors below
	// are best-effort and do not affect the overall indicator state.
	committed = true
	var results []*event.Event
	count := 0
	for _, site := range ds.Sites {
		if count >= accountsMaxSites {
			break
		}
		count++
		if site.URICheck == "" {
			continue
		}
		url := strings.ReplaceAll(site.URICheck, "{account}", evt.Data)
		resp, err := socialClient.FetchURL(ctx, url)
		if err != nil {
			continue
		}
		// Match: e_code AND e_string present; if m_string is also present,
		// it's a false positive — skip.
		if site.ECode != 0 && resp.StatusCode != site.ECode {
			continue
		}
		if site.EString != "" && !strings.Contains(resp.Body, site.EString) {
			continue
		}
		if site.MString != "" && strings.Contains(resp.Body, site.MString) {
			continue
		}
		pretty := site.URIPretty
		if pretty == "" {
			pretty = site.URICheck
		}
		pretty = strings.ReplaceAll(pretty, "{account}", evt.Data)
		if e, err := event.New(event.ACCOUNT_EXTERNAL_OWNED, site.Name+": "+pretty, "accounts", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Accounts) Finish() error {
	m.seen.clear()
	m.mu.Lock()
	m.dataset = nil
	m.mu.Unlock()
	return nil
}

// ============================================================================
// github
// ============================================================================

// GitHub queries the public GitHub REST API for user and repo data.
type GitHub struct{ seen seenSet }

// Meta returns module metadata.
func (m *GitHub) Meta() module.Meta {
	return module.Meta{Name: "github", Summary: "Identify associated public code repositories on GitHub.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *GitHub) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *GitHub) WatchedEvents() []event.Type {
	return []event.Type{event.USERNAME, event.SOCIAL_MEDIA}
}

// ProducedEvents returns emitted event types.
func (m *GitHub) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.GEOINFO, event.PUBLIC_CODE_REPO}
}

// githubUser is the relevant subset of /users/{name}.
type githubUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Location string `json:"location"`
	ReposURL string `json:"repos_url"`
}

// githubRepo is one repository entry.
type githubRepo struct {
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	Fork        bool   `json:"fork"`
}

// extractGithubUsername returns the username from a SOCIAL_MEDIA value
// like `GitHub: https://github.com/foo` or just a bare username.
func extractGithubUsername(data string) string {
	if strings.HasPrefix(data, "GitHub:") {
		s := strings.TrimSuffix(strings.TrimSpace(data), "/")
		idx := strings.LastIndex(s, "/")
		if idx == -1 {
			return ""
		}
		return s[idx+1:]
	}
	return data
}

// HandleEvent fetches the GitHub user profile and repo list.
func (m *GitHub) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	username := evt.Data
	if evt.Type == event.SOCIAL_MEDIA {
		if !strings.HasPrefix(evt.Data, "GitHub:") {
			return nil, nil
		}
		username = extractGithubUsername(evt.Data)
	}
	if username == "" {
		return nil, nil
	}
	resp, err := socialClient.FetchURL(ctx, "https://api.github.com/users/"+username)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var user githubUser
	if err := json.Unmarshal([]byte(resp.Body), &user); err != nil {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "github", evt); err == nil {
		results = append(results, e)
	}
	if user.Location != "" {
		if e, err := event.New(event.GEOINFO, user.Location, "github", evt); err == nil {
			results = append(results, e)
		}
	}
	if user.ReposURL != "" {
		repoResp, err := socialClient.FetchURL(ctx, user.ReposURL)
		if err == nil && repoResp.StatusCode == 200 {
			var repos []githubRepo
			if err := json.Unmarshal([]byte(repoResp.Body), &repos); err == nil {
				for _, r := range repos {
					if r.Fork || r.HTMLURL == "" {
						continue
					}
					if e, err := event.New(event.PUBLIC_CODE_REPO, r.HTMLURL, "github", evt); err == nil {
						results = append(results, e)
					}
				}
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *GitHub) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// twitter — legacy HTML scrape (best-effort; upstream often broken)
// ============================================================================

// twitterNameRe matches the legacy fullname div.
var twitterNameRe = regexp.MustCompile(`<div class="fullname">([^<]+)\s*</div>`)

// twitterLocRe matches the legacy location div.
var twitterLocRe = regexp.MustCompile(`<div class="location">([^<]+)</div>`)

// Twitter scrapes a Twitter profile HTML page for name/location.
type Twitter struct{ seen seenSet }

// Meta returns module metadata.
func (m *Twitter) Meta() module.Meta {
	return module.Meta{Name: "twitter", Summary: "Extract a name and location from a Twitter profile (legacy HTML scrape).", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Twitter) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Twitter) WatchedEvents() []event.Type { return []event.Type{event.SOCIAL_MEDIA} }

// ProducedEvents returns emitted event types.
func (m *Twitter) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.GEOINFO}
}

// HandleEvent fetches a Twitter profile and parses fullname/location.
func (m *Twitter) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if !strings.HasPrefix(evt.Data, "Twitter:") {
		return nil, nil
	}
	idx := strings.Index(evt.Data, "http")
	if idx == -1 {
		return nil, nil
	}
	url := evt.Data[idx:]
	resp, err := socialClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "twitter", evt); err == nil {
		results = append(results, e)
	}
	if loc := twitterLocRe.FindStringSubmatch(resp.Body); loc != nil {
		if e, err := event.New(event.GEOINFO, strings.TrimSpace(loc[1]), "twitter", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Twitter) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// flickr — best-effort homepage API key extraction
// ============================================================================

// flickrSiteKeyRe matches the YUI_config site_key embedded in flickr.com.
var flickrSiteKeyRe = regexp.MustCompile(`"api":\s*\{\s*"site_key":\s*"([0-9a-f]+)"`)

// Flickr searches Flickr photo metadata for emails/URLs related to a domain.
type Flickr struct{ seen seenSet }

// Meta returns module metadata.
func (m *Flickr) Meta() module.Meta {
	return module.Meta{Name: "flickr", Summary: "Search Flickr photo metadata for references to a target domain.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Flickr) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Flickr) WatchedEvents() []event.Type { return []event.Type{event.DOMAIN_NAME} }

// ProducedEvents returns emitted event types.
func (m *Flickr) ProducedEvents() []event.Type {
	return []event.Type{event.EMAILADDR, event.LINKED_URL_INTERNAL, event.RAW_RIR_DATA}
}

// HandleEvent runs a single-page Flickr photo search and harvests emails/URLs.
func (m *Flickr) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	homeResp, err := socialClient.FetchURL(ctx, "https://www.flickr.com/")
	if err != nil || homeResp.StatusCode != 200 {
		return nil, nil
	}
	keyMatch := flickrSiteKeyRe.FindStringSubmatch(homeResp.Body)
	if keyMatch == nil {
		return nil, nil
	}
	apiKey := keyMatch[1]
	url := fmt.Sprintf("https://api.flickr.com/services/rest?method=flickr.photos.search&api_key=%s&text=%s&format=json&nojsoncallback=1&per_page=100&page=1", apiKey, evt.Data)
	resp, err := socialClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "flickr", evt); err == nil {
		results = append(results, e)
	}
	emitted := make(map[string]bool)
	for _, addr := range sflib.ExtractEmails(resp.Body) {
		addr = strings.ToLower(addr)
		if !strings.HasSuffix(addr, "@"+evt.Data) && !strings.HasSuffix(addr, "."+evt.Data) {
			continue
		}
		if emitted[addr] {
			continue
		}
		emitted[addr] = true
		if e, err := event.New(event.EMAILADDR, addr, "flickr", evt); err == nil {
			results = append(results, e)
		}
	}
	for _, link := range sflib.ExtractURLs(resp.Body) {
		if !strings.Contains(link, evt.Data) || emitted[link] {
			continue
		}
		emitted[link] = true
		if e, err := event.New(event.LINKED_URL_INTERNAL, link, "flickr", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Flickr) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// keybase
// ============================================================================

// Keybase queries keybase.io for user profile data.
type Keybase struct{ seen seenSet }

// Meta returns module metadata.
func (m *Keybase) Meta() module.Meta {
	return module.Meta{Name: "keybase", Summary: "Look up user profile data on keybase.io.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Keybase) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Keybase) WatchedEvents() []event.Type {
	return []event.Type{event.USERNAME, event.DOMAIN_NAME}
}

// ProducedEvents returns emitted event types.
func (m *Keybase) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.SOCIAL_MEDIA, event.GEOINFO, event.BITCOIN_ADDRESS, event.PGP_KEY, event.HUMAN_NAME}
}

// keybaseResponse is the relevant subset of the lookup payload.
type keybaseResponse struct {
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
	Them []struct {
		Basics struct {
			Username string `json:"username"`
		} `json:"basics"`
		Profile struct {
			FullName string `json:"full_name"`
			Location string `json:"location"`
		} `json:"profile"`
		ProofsSummary struct {
			All []struct {
				ProofType       string `json:"proof_type"`
				ServiceURL      string `json:"service_url"`
				PresentableName string `json:"presentable_name"`
			} `json:"all"`
		} `json:"proofs_summary"`
		CryptocurrencyAddresses struct {
			Bitcoin []struct {
				Address string `json:"address"`
			} `json:"bitcoin"`
		} `json:"cryptocurrency_addresses"`
		PublicKeys struct {
			Primary struct {
				Bundle string `json:"bundle"`
			} `json:"primary"`
		} `json:"public_keys"`
	} `json:"them"`
}

// HandleEvent looks up the user/domain on keybase.io.
func (m *Keybase) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	var url string
	if evt.Type == event.USERNAME {
		url = "https://keybase.io/_/api/1.0/user/lookup.json?usernames=" + evt.Data
	} else {
		url = "https://keybase.io/_/api/1.0/user/lookup.json?domain=" + evt.Data
	}
	resp, err := socialClient.FetchURL(ctx, url)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var payload keybaseResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil || payload.Status.Code != 0 {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "keybase", evt); err == nil {
		results = append(results, e)
	}
	for _, them := range payload.Them {
		if them.Profile.FullName != "" {
			if e, err := event.New(event.HUMAN_NAME, them.Profile.FullName, "keybase", evt); err == nil {
				results = append(results, e)
			}
		}
		if them.Profile.Location != "" {
			if e, err := event.New(event.GEOINFO, them.Profile.Location, "keybase", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, p := range them.ProofsSummary.All {
			if p.ServiceURL == "" {
				continue
			}
			label := p.PresentableName
			if label == "" {
				label = p.ProofType
			}
			if e, err := event.New(event.SOCIAL_MEDIA, label+": "+p.ServiceURL, "keybase", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, b := range them.CryptocurrencyAddresses.Bitcoin {
			if b.Address == "" {
				continue
			}
			if e, err := event.New(event.BITCOIN_ADDRESS, b.Address, "keybase", evt); err == nil {
				results = append(results, e)
			}
		}
		if strings.Contains(them.PublicKeys.Primary.Bundle, "BEGIN PGP") {
			if e, err := event.New(event.PGP_KEY, them.PublicKeys.Primary.Bundle, "keybase", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Keybase) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// gravatar
// ============================================================================

// Gravatar looks up the public Gravatar profile for an email.
type Gravatar struct{ seen seenSet }

// Meta returns module metadata.
func (m *Gravatar) Meta() module.Meta {
	return module.Meta{Name: "gravatar", Summary: "Look up Gravatar profile data for an email address.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *Gravatar) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *Gravatar) WatchedEvents() []event.Type { return []event.Type{event.EMAILADDR} }

// ProducedEvents returns emitted event types.
func (m *Gravatar) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.USERNAME, event.PHONE_NUMBER, event.GEOINFO, event.ACCOUNT_EXTERNAL_OWNED, event.SOCIAL_MEDIA, event.HUMAN_NAME}
}

// gravatarResponse is the relevant subset of the JSON profile.
type gravatarResponse struct {
	Entry []struct {
		PreferredUsername string `json:"preferredUsername"`
		Name              struct {
			Formatted string `json:"formatted"`
		} `json:"name"`
		PhoneNumbers []struct {
			Value string `json:"value"`
		} `json:"phoneNumbers"`
		CurrentLocation string `json:"currentLocation"`
		Accounts        []struct {
			Domain   string `json:"domain"`
			Username string `json:"username"`
			URL      string `json:"url"`
		} `json:"accounts"`
	} `json:"entry"`
}

// HandleEvent fetches the Gravatar JSON profile for the email.
func (m *Gravatar) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(evt.Data))))
	hash := hex.EncodeToString(sum[:])
	resp, err := socialClient.FetchURL(ctx, "https://secure.gravatar.com/"+hash+".json")
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var payload gravatarResponse
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return nil, nil
	}
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "gravatar", evt); err == nil {
		results = append(results, e)
	}
	for _, entry := range payload.Entry {
		if entry.PreferredUsername != "" {
			if e, err := event.New(event.USERNAME, entry.PreferredUsername, "gravatar", evt); err == nil {
				results = append(results, e)
			}
		}
		if entry.Name.Formatted != "" {
			if e, err := event.New(event.HUMAN_NAME, entry.Name.Formatted, "gravatar", evt); err == nil {
				results = append(results, e)
			}
		}
		if entry.CurrentLocation != "" {
			if e, err := event.New(event.GEOINFO, entry.CurrentLocation, "gravatar", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, p := range entry.PhoneNumbers {
			if p.Value == "" {
				continue
			}
			if e, err := event.New(event.PHONE_NUMBER, p.Value, "gravatar", evt); err == nil {
				results = append(results, e)
			}
		}
		for _, acc := range entry.Accounts {
			if acc.URL == "" {
				continue
			}
			label := acc.Domain
			if label == "" {
				label = "account"
			}
			if e, err := event.New(event.ACCOUNT_EXTERNAL_OWNED, label+": "+acc.URL, "gravatar", evt); err == nil {
				results = append(results, e)
			}
		}
	}
	return results, nil
}

// Finish clears state.
func (m *Gravatar) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// slideshare
// ============================================================================

// slideshareLocRe matches the og location meta on SlideShare profile pages.
var slideshareLocRe = regexp.MustCompile(`<meta\s+property="slideshare:location"\s+content="([^"]+)"`)

// SlideShare scrapes a SlideShare profile URL for location info.
type SlideShare struct{ seen seenSet }

// Meta returns module metadata.
func (m *SlideShare) Meta() module.Meta {
	return module.Meta{Name: "slideshare", Summary: "Extract location information from SlideShare profile pages.", Categories: []string{"Social Media"}}
}

// Setup initializes internal state.
func (m *SlideShare) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns consumed event types.
func (m *SlideShare) WatchedEvents() []event.Type { return []event.Type{event.SOCIAL_MEDIA} }

// ProducedEvents returns emitted event types.
func (m *SlideShare) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_RIR_DATA, event.GEOINFO}
}

// HandleEvent fetches a SlideShare profile and parses meta tags.
func (m *SlideShare) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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
	if !strings.HasPrefix(evt.Data, "SlideShare:") {
		return nil, nil
	}
	idx := strings.Index(evt.Data, "http")
	if idx == -1 {
		return nil, nil
	}
	resp, err := socialClient.FetchURL(ctx, evt.Data[idx:])
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	committed = true
	var results []*event.Event
	if e, err := event.New(event.RAW_RIR_DATA, resp.Body, "slideshare", evt); err == nil {
		results = append(results, e)
	}
	if loc := slideshareLocRe.FindStringSubmatch(resp.Body); loc != nil {
		if e, err := event.New(event.GEOINFO, loc[1], "slideshare", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish clears state.
func (m *SlideShare) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registrations
// ============================================================================

func init() {
	module.Register("social", func() module.Module { return &Social{} })
	module.Register("accounts", func() module.Module { return &Accounts{} })
	module.Register("github", func() module.Module { return &GitHub{} })
	module.Register("twitter", func() module.Module { return &Twitter{} })
	module.Register("flickr", func() module.Module { return &Flickr{} })
	module.Register("keybase", func() module.Module { return &Keybase{} })
	module.Register("gravatar", func() module.Module { return &Gravatar{} })
	module.Register("slideshare", func() module.Module { return &SlideShare{} })
}
