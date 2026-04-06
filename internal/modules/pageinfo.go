package modules

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("pageinfo", func() module.Module { return &PageInfo{} })
}

// PageInfo analyzes web page content to classify pages by type
// (JavaScript, forms, password fields, uploads, applets, Flash)
// and detects external JavaScript providers.
type PageInfo struct {
	seen map[string]bool
	mu   sync.Mutex
}

// pageTypeSignature pairs an event type with detection patterns.
type pageTypeSignature struct {
	EventType event.Type
	Patterns  []*regexp.Regexp
}

// pageTypeSignatures contains compiled regex patterns for each page type.
var pageTypeSignatures = func() []pageTypeSignature {
	raw := map[event.Type][]string{
		event.URL_JAVASCRIPT:  {`text/javascript`, `<script `},
		event.URL_FORM:        {`<form `, `method=[PG]`, `<input `},
		event.URL_PASSWORD:    {`<input[^>]*type=["\']?password`},
		event.URL_UPLOAD:      {`type=["\']?file`},
		event.URL_JAVA_APPLET: {`<applet `},
		event.URL_FLASH:       {`\.swf[ '"]`},
	}
	var sigs []pageTypeSignature
	for typ, patterns := range raw {
		var compiled []*regexp.Regexp
		for _, p := range patterns {
			compiled = append(compiled, regexp.MustCompile(`(?i)`+p))
		}
		sigs = append(sigs, pageTypeSignature{EventType: typ, Patterns: compiled})
	}
	return sigs
}()

// extJSRe extracts external script src attributes.
var extJSRe = regexp.MustCompile(`(?i)<script[^>]+src=['"']?([^'">\s]+)`)

// Meta returns module metadata for PageInfo.
func (m *PageInfo) Meta() module.Meta {
	return module.Meta{
		Name:       "pageinfo",
		Summary:    "Classifies web page content by type and detects external JavaScript providers",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes PageInfo state.
func (m *PageInfo) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that PageInfo consumes.
func (m *PageInfo) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT}
}

// ProducedEvents returns event types that PageInfo may emit.
func (m *PageInfo) ProducedEvents() []event.Type {
	return []event.Type{
		event.URL_STATIC,
		event.URL_JAVASCRIPT,
		event.URL_FORM,
		event.URL_PASSWORD,
		event.URL_UPLOAD,
		event.URL_JAVA_APPLET,
		event.URL_FLASH,
		event.PROVIDER_JAVASCRIPT,
	}
}

// HandleEvent classifies the web page content and detects external JS.
func (m *PageInfo) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	content := evt.Data
	if content == "" {
		return nil, nil
	}

	var results []*event.Event
	matched := false

	for _, sig := range pageTypeSignatures {
		for _, re := range sig.Patterns {
			if re.MatchString(content) {
				if e, err := event.New(sig.EventType, string(sig.EventType), "pageinfo", evt); err == nil {
					results = append(results, e)
				}
				matched = true
				break
			}
		}
	}

	// If no dynamic content matched, classify as static.
	if !matched {
		if e, err := event.New(event.URL_STATIC, "URL_STATIC", "pageinfo", evt); err == nil {
			results = append(results, e)
		}
	}

	// Detect external JavaScript providers.
	matches := extJSRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		src := match[1]
		if !strings.Contains(src, "://") {
			continue
		}
		if !m.markSeen("js:" + src) {
			if e, err := event.New(event.PROVIDER_JAVASCRIPT, src, "pageinfo", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by PageInfo.
func (m *PageInfo) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *PageInfo) markSeen(key string) bool {
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
