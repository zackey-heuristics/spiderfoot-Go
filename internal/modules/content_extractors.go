package modules

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

// contentExtractor is a generic module that consumes TARGET_WEB_CONTENT and
// emits a specific event type for each match returned by an extraction func.
type contentExtractor struct {
	name     string
	summary  string
	produces event.Type
	extract  func(string) []string
	seen     map[string]bool
	mu       sync.Mutex
}

// Meta returns module metadata for the contentExtractor.
func (m *contentExtractor) Meta() module.Meta {
	return module.Meta{
		Name:       m.name,
		Summary:    m.summary,
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes the dedup map.
func (m *contentExtractor) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types this extractor consumes.
func (m *contentExtractor) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT}
}

// ProducedEvents returns the single event type emitted by this extractor.
func (m *contentExtractor) ProducedEvents() []event.Type {
	return []event.Type{m.produces}
}

// HandleEvent runs the extractor function and emits one event per unique match.
func (m *contentExtractor) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}
	if evt.Data == "" {
		return nil, nil
	}

	matches := m.extract(evt.Data)
	if len(matches) == 0 {
		return nil, nil
	}

	var results []*event.Event
	for _, match := range matches {
		if match == "" {
			continue
		}
		if m.markSeen(match) {
			continue
		}
		if e, err := event.New(m.produces, match, m.name, evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by the extractor.
func (m *contentExtractor) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *contentExtractor) markSeen(key string) bool {
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

// Hash extractor with a different signature requires its own implementation.

// HashExtractor extracts MD5/SHA1/SHA256 hashes from web content.
type HashExtractor struct {
	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata for HashExtractor.
func (m *HashExtractor) Meta() module.Meta {
	return module.Meta{
		Name:       "hashes",
		Summary:    "Extracts MD5, SHA1, and SHA256 hash values from web content",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes HashExtractor state.
func (m *HashExtractor) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types HashExtractor consumes.
func (m *HashExtractor) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT}
}

// ProducedEvents returns event types HashExtractor may emit.
func (m *HashExtractor) ProducedEvents() []event.Type {
	return []event.Type{event.HASH}
}

// HandleEvent extracts hashes from event content.
func (m *HashExtractor) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	var results []*event.Event
	for _, h := range sflib.ExtractHashes(evt.Data) {
		key := h.Type + ":" + h.Value
		m.mu.Lock()
		if m.seen != nil && m.seen[key] {
			m.mu.Unlock()
			continue
		}
		if m.seen != nil {
			m.seen[key] = true
		}
		m.mu.Unlock()

		if e, err := event.New(event.HASH, h.Type+":"+h.Value, "hashes", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by HashExtractor.
func (m *HashExtractor) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// Base64 extractor finds plausible base64 strings and decodes them.

// base64StringRe matches plausible base64-encoded blobs of >= 24 chars.
var base64StringRe = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

// Base64Extractor identifies and decodes base64-encoded data in web content.
type Base64Extractor struct {
	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata for Base64Extractor.
func (m *Base64Extractor) Meta() module.Meta {
	return module.Meta{
		Name:       "base64",
		Summary:    "Identifies base64-encoded strings in web content",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes Base64Extractor state.
func (m *Base64Extractor) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types Base64Extractor consumes.
func (m *Base64Extractor) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT}
}

// ProducedEvents returns event types Base64Extractor may emit.
func (m *Base64Extractor) ProducedEvents() []event.Type {
	return []event.Type{event.BASE64_DATA}
}

// HandleEvent finds and emits base64 blobs from event content.
func (m *Base64Extractor) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	var results []*event.Event
	for _, candidate := range base64StringRe.FindAllString(evt.Data, -1) {
		// Verify it actually decodes.
		if _, err := base64.StdEncoding.DecodeString(candidate); err != nil {
			continue
		}
		m.mu.Lock()
		if m.seen != nil && m.seen[candidate] {
			m.mu.Unlock()
			continue
		}
		if m.seen != nil {
			m.seen[candidate] = true
		}
		m.mu.Unlock()

		if e, err := event.New(event.BASE64_DATA, candidate, "base64", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by Base64Extractor.
func (m *Base64Extractor) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// Error message extractor finds common server-side error patterns.

// errorPatterns lists regex patterns for common server-side error messages.
var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Warning:\s*[a-z_]+\(\)`),
	regexp.MustCompile(`(?i)Fatal error:`),
	regexp.MustCompile(`(?i)Notice:\s*Undefined`),
	regexp.MustCompile(`(?i)mysql_\w+\(\):`),
	regexp.MustCompile(`(?i)ORA-\d{5}`),
	regexp.MustCompile(`(?i)Microsoft.*ODBC.*SQL Server`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)Stack trace:`),
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)<b>Warning</b>:`),
	regexp.MustCompile(`(?i)Internal Server Error`),
}

// extractErrors returns server-side error messages found in data.
func extractErrors(data string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, re := range errorPatterns {
		for _, match := range re.FindAllString(data, -1) {
			match = strings.TrimSpace(match)
			if match != "" && !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	return out
}

// Cookie extractor reports session cookies present in HTTP headers.

// CookieExtractor reports HTTP cookies from web server response headers.
type CookieExtractor struct {
	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata for CookieExtractor.
func (m *CookieExtractor) Meta() module.Meta {
	return module.Meta{
		Name:       "cookie",
		Summary:    "Extracts HTTP cookies from web server response headers",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes CookieExtractor state.
func (m *CookieExtractor) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types CookieExtractor consumes.
func (m *CookieExtractor) WatchedEvents() []event.Type {
	return []event.Type{event.WEBSERVER_HTTPHEADERS}
}

// ProducedEvents returns event types CookieExtractor may emit.
func (m *CookieExtractor) ProducedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_COOKIE}
}

// HandleEvent extracts Set-Cookie headers from the input.
func (m *CookieExtractor) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	var results []*event.Event
	for _, line := range strings.Split(evt.Data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			continue
		}
		val := strings.TrimSpace(line[len("Set-Cookie:"):])
		if val == "" {
			continue
		}
		m.mu.Lock()
		if m.seen != nil && m.seen[val] {
			m.mu.Unlock()
			continue
		}
		if m.seen != nil {
			m.seen[val] = true
		}
		m.mu.Unlock()

		if e, err := event.New(event.TARGET_WEB_COOKIE, val, "cookie", evt); err == nil {
			results = append(results, e)
		}
	}
	return results, nil
}

// Finish releases resources held by CookieExtractor.
func (m *CookieExtractor) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// Binary string extractor: detects unusual long alphanumeric blobs that may
// indicate embedded binary content.

// binStringRe matches plausible binary/hex strings >= 60 chars.
var binStringRe = regexp.MustCompile(`[A-Za-z0-9+/=]{60,}`)

// Human name extractor: matches sequences of two capitalized words.

// humanNameRe matches simple "Firstname Lastname" patterns.
var humanNameRe = regexp.MustCompile(`\b[A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20}\b`)

// extractHumanNames returns plausible human names from text.
func extractHumanNames(data string) []string {
	return dedupExtractor(humanNameRe.FindAllString(data, -1))
}

// extractBinStrings returns long blobs of base64/hex characters.
func extractBinStrings(data string) []string {
	return dedupExtractor(binStringRe.FindAllString(data, -1))
}

// dedupExtractor returns a deduplicated copy of the input.
func dedupExtractor(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// Module registrations.

func init() {
	module.Register("email", func() module.Module {
		return &contentExtractor{
			name:     "email",
			summary:  "Identifies email addresses in web content",
			produces: event.EMAILADDR,
			extract:  sflib.ExtractEmails,
		}
	})

	module.Register("bitcoin", func() module.Module {
		return &contentExtractor{
			name:     "bitcoin",
			summary:  "Identifies Bitcoin addresses in web content",
			produces: event.BITCOIN_ADDRESS,
			extract:  sflib.ExtractBitcoinAddresses,
		}
	})

	module.Register("ethereum", func() module.Module {
		return &contentExtractor{
			name:     "ethereum",
			summary:  "Identifies Ethereum addresses in web content",
			produces: event.ETHEREUM_ADDRESS,
			extract:  sflib.ExtractEthereumAddresses,
		}
	})

	module.Register("creditcard", func() module.Module {
		return &contentExtractor{
			name:     "creditcard",
			summary:  "Identifies credit card numbers in web content",
			produces: event.CREDIT_CARD_NUMBER,
			extract:  sflib.ExtractCreditCards,
		}
	})

	module.Register("iban", func() module.Module {
		return &contentExtractor{
			name:     "iban",
			summary:  "Identifies IBAN bank account numbers in web content",
			produces: event.IBAN_NUMBER,
			extract:  sflib.ExtractIBANs,
		}
	})

	module.Register("phone", func() module.Module {
		return &contentExtractor{
			name:     "phone",
			summary:  "Identifies phone numbers in web content",
			produces: event.PHONE_NUMBER,
			extract:  sflib.ExtractPhoneNumbers,
		}
	})

	module.Register("names", func() module.Module {
		return &contentExtractor{
			name:     "names",
			summary:  "Identifies plausible human names in web content",
			produces: event.HUMAN_NAME,
			extract:  extractHumanNames,
		}
	})

	module.Register("errors", func() module.Module {
		return &contentExtractor{
			name:     "errors",
			summary:  "Identifies server-side error messages in web content",
			produces: event.ERROR_MESSAGE,
			extract:  extractErrors,
		}
	})

	module.Register("binstring", func() module.Module {
		return &contentExtractor{
			name:     "binstring",
			summary:  "Identifies long binary/encoded strings in web content",
			produces: event.BASE64_DATA,
			extract:  extractBinStrings,
		}
	})

	module.Register("hashes", func() module.Module { return &HashExtractor{} })
	module.Register("base64", func() module.Module { return &Base64Extractor{} })
	module.Register("cookie", func() module.Module { return &CookieExtractor{} })
}
