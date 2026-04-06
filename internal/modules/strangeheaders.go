package modules

import (
	"context"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("strangeheaders", func() module.Module { return &StrangeHeaders{} })
}

// StrangeHeaders identifies non-standard HTTP headers in web server responses,
// which can reveal custom applications, debugging info, or security misconfigurations.
type StrangeHeaders struct {
	seen map[string]bool
	mu   sync.Mutex
}

// standardHeaders is the set of well-known HTTP response headers (lowercase).
var standardHeaders = func() map[string]bool {
	headers := []string{
		"accept-patch", "accept-ranges", "access-control-allow-credentials",
		"access-control-allow-headers", "access-control-allow-methods",
		"access-control-allow-origin", "access-control-expose-headers",
		"access-control-max-age", "age", "allow", "alt-svc", "cache-control",
		"connection", "content-disposition", "content-encoding",
		"content-language", "content-length", "content-location",
		"content-md5", "content-range", "content-security-policy",
		"content-type", "date", "delta-base", "etag", "expires", "im",
		"last-modified", "link", "location", "p3p", "pragma",
		"proxy-authenticate", "public-key-pins", "refresh", "retry-after",
		"server", "set-cookie", "status", "strict-transport-security",
		"timing-allow-origin", "tk", "trailer", "transfer-encoding",
		"upgrade", "vary", "via", "warning", "www-authenticate",
		"x-content-duration", "x-content-security-policy",
		"x-content-type-options", "x-correlation-id", "x-frame-options",
		"x-powered-by", "x-request-id", "x-ua-compatible",
		"x-webkit-csp", "x-xss-protection",
	}
	m := make(map[string]bool, len(headers))
	for _, h := range headers {
		m[h] = true
	}
	return m
}()

// Meta returns module metadata for StrangeHeaders.
func (m *StrangeHeaders) Meta() module.Meta {
	return module.Meta{
		Name:       "strangeheaders",
		Summary:    "Identifies non-standard HTTP response headers that may reveal useful information",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes StrangeHeaders state.
func (m *StrangeHeaders) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that StrangeHeaders consumes.
func (m *StrangeHeaders) WatchedEvents() []event.Type {
	return []event.Type{event.WEBSERVER_HTTPHEADERS}
}

// ProducedEvents returns event types that StrangeHeaders may emit.
func (m *StrangeHeaders) ProducedEvents() []event.Type {
	return []event.Type{event.WEBSERVER_STRANGEHEADER}
}

// HandleEvent checks HTTP headers for non-standard entries.
func (m *StrangeHeaders) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	headers := evt.Data
	if headers == "" {
		return nil, nil
	}

	var results []*event.Event

	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		keyLower := strings.ToLower(key)

		if standardHeaders[keyLower] {
			continue
		}

		entry := key + ": " + val
		if !m.markSeen(keyLower) {
			if e, err := event.New(event.WEBSERVER_STRANGEHEADER, entry, "strangeheaders", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by StrangeHeaders.
func (m *StrangeHeaders) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *StrangeHeaders) markSeen(key string) bool {
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
