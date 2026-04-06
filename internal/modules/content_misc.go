package modules

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// companyRe matches company names ending in common business suffixes.
var companyRe = regexp.MustCompile(`\b(?:[A-Z][A-Za-z0-9&.\-]{1,40}\s){0,4}[A-Z][A-Za-z0-9&.\-]{1,40}\s(?:Inc|Incorporated|LLC|Ltd|Limited|Corp|Corporation|Co|Company|GmbH|AG|S\.A\.|SA|SAS|SARL|Pty|PLC|N\.V\.|NV|BV|AB|AS|Oy|Sp\. z o\.o\.)\.?`)

// extractCompanies returns plausible company names from text.
func extractCompanies(data string) []string {
	matches := companyRe.FindAllString(data, -1)
	return dedupExtractor(matches)
}

// extractCountryNames returns country names found in text.
func extractCountryNames(data string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, name := range sflib.AllCountryNames() {
		if strings.Contains(data, name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// intFilePatterns matches paths to interesting files (admin, config, backup, etc).
var intFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/admin(?:istrator)?/`),
	regexp.MustCompile(`(?i)/wp-admin/`),
	regexp.MustCompile(`(?i)/phpmyadmin/`),
	regexp.MustCompile(`(?i)/\.git/`),
	regexp.MustCompile(`(?i)/\.svn/`),
	regexp.MustCompile(`(?i)/\.env\b`),
	regexp.MustCompile(`(?i)/config\.(?:php|json|yaml|yml|xml|ini)\b`),
	regexp.MustCompile(`(?i)/backup\.(?:sql|tar|zip|gz)\b`),
	regexp.MustCompile(`(?i)/web\.config\b`),
	regexp.MustCompile(`(?i)/robots\.txt\b`),
	regexp.MustCompile(`(?i)/sitemap\.xml\b`),
	regexp.MustCompile(`(?i)/\.htaccess\b`),
	regexp.MustCompile(`(?i)/server-status\b`),
	regexp.MustCompile(`(?i)/server-info\b`),
}

// extractInterestingFiles returns interesting file/path mentions found in text.
func extractInterestingFiles(data string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, re := range intFilePatterns {
		for _, match := range re.FindAllString(data, -1) {
			if !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	return out
}

// junkFileExtensions are file extensions that often indicate forgotten/leftover files.
var junkFileExtensions = []string{
	".bak", ".old", ".swp", ".tmp", ".backup", ".orig", ".save", ".copy", ".~",
	".bkp", ".back", "~", ".old1", ".old2",
}

// junkFileRe matches URLs ending in junk extensions.
var junkFileRe = regexp.MustCompile(`https?://[^\s<>"']+?(?:\.bak|\.old|\.swp|\.tmp|\.backup|\.orig|\.save|\.copy|\.bkp|\.back)\b`)

// extractJunkFiles returns junk file URLs from text.
func extractJunkFiles(data string) []string {
	return dedupExtractor(junkFileRe.FindAllString(data, -1))
}

// webAnalyticsPatterns matches common analytics tracker IDs.
var webAnalyticsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`UA-\d{4,10}-\d{1,4}`),                  // Google Analytics (legacy)
	regexp.MustCompile(`G-[A-Z0-9]{10}`),                       // Google Analytics 4
	regexp.MustCompile(`GTM-[A-Z0-9]{6,8}`),                    // Google Tag Manager
	regexp.MustCompile(`AW-\d{9,11}`),                          // Google Ads
	regexp.MustCompile(`fbq\(['"]init['"],\s*['"](\d+)['"]\)`), // Facebook Pixel
}

// extractWebAnalyticsIDs returns analytics tracker IDs found in text.
func extractWebAnalyticsIDs(data string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, re := range webAnalyticsPatterns {
		for _, match := range re.FindAllString(data, -1) {
			if !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	return out
}

// pgpKeyRe matches PGP key blocks.
var pgpKeyRe = regexp.MustCompile(`(?s)-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----`)

// extractPGPKeys returns PGP public key blocks found in text.
func extractPGPKeys(data string) []string {
	return dedupExtractor(pgpKeyRe.FindAllString(data, -1))
}

// SimilarDomain emits SIMILARDOMAIN events for typosquatting candidates of
// a target domain. This is a structural variant of contentExtractor that needs
// the source domain to compute similarity.
type SimilarDomain struct {
	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata for SimilarDomain.
func (m *SimilarDomain) Meta() module.Meta {
	return module.Meta{
		Name:       "similar",
		Summary:    "Identifies similar-looking domain names (typosquatting candidates)",
		Categories: []string{"DNS"},
	}
}

// Setup initializes SimilarDomain state.
func (m *SimilarDomain) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types SimilarDomain consumes.
func (m *SimilarDomain) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME}
}

// ProducedEvents returns event types SimilarDomain may emit.
func (m *SimilarDomain) ProducedEvents() []event.Type {
	return []event.Type{event.SIMILARDOMAIN}
}

// HandleEvent generates a small set of typosquat variants of the input domain.
func (m *SimilarDomain) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	domain := strings.ToLower(strings.TrimSpace(evt.Data))
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	base, tld := parts[0], parts[1]

	if m.markSeen(domain) {
		return nil, nil
	}

	variants := generateTyposquats(base, tld)
	var results []*event.Event
	for _, v := range variants {
		if v == domain {
			continue
		}
		if e, err := event.New(event.SIMILARDOMAIN, v, "similar", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by SimilarDomain.
func (m *SimilarDomain) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *SimilarDomain) markSeen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		return false
	}
	if m.seen[key] {
		return true
	}
	m.seen[key] = true
	return false
}

// generateTyposquats produces simple typosquat variants of a base domain:
// character omission, doubling, and adjacent swaps.
func generateTyposquats(base, tld string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(v string) {
		full := v + "." + tld
		if !seen[full] && v != "" && v != base {
			seen[full] = true
			out = append(out, full)
		}
	}

	// Omission: drop one character.
	for i := 0; i < len(base); i++ {
		add(base[:i] + base[i+1:])
	}
	// Doubling: duplicate one character.
	for i := 0; i < len(base); i++ {
		add(base[:i+1] + string(base[i]) + base[i+1:])
	}
	// Adjacent swap.
	for i := 0; i < len(base)-1; i++ {
		add(base[:i] + string(base[i+1]) + string(base[i]) + base[i+2:])
	}
	return out
}

// FileMeta detects URLs to common document types whose metadata could be analyzed.
// The Python module uses external parsers (PyPDF, exifread); this Go port reports
// document URLs as RAW_FILE_META_DATA placeholders so downstream tools can fetch
// and parse them.
type FileMeta struct {
	seen map[string]bool
	mu   sync.Mutex
}

// fileMetaRe matches URLs to documents whose metadata is interesting.
var fileMetaRe = regexp.MustCompile(`(?i)https?://[^\s<>"']+?\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|odt|jpg|jpeg|png|tiff)\b`)

// Meta returns module metadata for FileMeta.
func (m *FileMeta) Meta() module.Meta {
	return module.Meta{
		Name:       "filemeta",
		Summary:    "Identifies document URLs whose metadata can reveal authors and software",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes FileMeta state.
func (m *FileMeta) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types FileMeta consumes.
func (m *FileMeta) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT, event.LINKED_URL_INTERNAL}
}

// ProducedEvents returns event types FileMeta may emit.
func (m *FileMeta) ProducedEvents() []event.Type {
	return []event.Type{event.RAW_FILE_META_DATA}
}

// HandleEvent identifies document URLs from event data.
func (m *FileMeta) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	matches := fileMetaRe.FindAllString(evt.Data, -1)
	var results []*event.Event
	for _, url := range matches {
		m.mu.Lock()
		if m.seen != nil && m.seen[url] {
			m.mu.Unlock()
			continue
		}
		if m.seen != nil {
			m.seen[url] = true
		}
		m.mu.Unlock()

		if e, err := event.New(event.RAW_FILE_META_DATA, url, "filemeta", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by FileMeta.
func (m *FileMeta) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// Module registrations.

func init() {
	module.Register("company", func() module.Module {
		return &contentExtractor{
			name:     "company",
			summary:  "Identifies company names with corporate suffixes in web content",
			produces: event.COMPANY_NAME,
			extract:  extractCompanies,
		}
	})

	module.Register("countryname", func() module.Module {
		return &contentExtractor{
			name:     "countryname",
			summary:  "Identifies country names mentioned in web content",
			produces: event.COUNTRY_NAME,
			extract:  extractCountryNames,
		}
	})

	module.Register("intfiles", func() module.Module {
		return &contentExtractor{
			name:     "intfiles",
			summary:  "Identifies references to interesting files and paths in web content",
			produces: event.INTERESTING_FILE,
			extract:  extractInterestingFiles,
		}
	})

	module.Register("junkfiles", func() module.Module {
		return &contentExtractor{
			name:     "junkfiles",
			summary:  "Identifies leftover/junk file URLs (.bak, .old, .tmp, etc.)",
			produces: event.JUNK_FILE,
			extract:  extractJunkFiles,
		}
	})

	module.Register("webanalytics", func() module.Module {
		return &contentExtractor{
			name:     "webanalytics",
			summary:  "Identifies web analytics tracker IDs (Google Analytics, GTM, Facebook)",
			produces: event.WEB_ANALYTICS_ID,
			extract:  extractWebAnalyticsIDs,
		}
	})

	module.Register("pgp", func() module.Module {
		return &contentExtractor{
			name:     "pgp",
			summary:  "Identifies PGP public key blocks in web content",
			produces: event.PGP_KEY,
			extract:  extractPGPKeys,
		}
	})

	module.Register("similar", func() module.Module { return &SimilarDomain{} })
	module.Register("filemeta", func() module.Module { return &FileMeta{} })
}
