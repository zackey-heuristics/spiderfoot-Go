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
	module.Register("webframework", func() module.Module { return &WebFramework{} })
}

// WebFramework detects JavaScript frameworks and CMS platforms in web content
// by matching known signatures and patterns.
type WebFramework struct {
	seen map[string]bool
	mu   sync.Mutex
}

// frameworkSignature pairs a framework name with compiled regex patterns.
type frameworkSignature struct {
	Name     string
	Patterns []*regexp.Regexp
}

// frameworkSignatures contains the detection patterns for each framework.
var frameworkSignatures = func() []frameworkSignature {
	raw := map[string][]string{
		"jQuery":            {`jquery`},
		"YUI":               {`/yui/`, `yui-`, `yui\.`},
		"Prototype":         {`/prototype/`, `prototype-`, `prototype\.js`},
		"ZURB Foundation":   {`/foundation/`, `foundation-`, `foundation\.js`},
		"Bootstrap":         {`/bootstrap/`, `bootstrap-`, `bootstrap\.js`},
		"ExtJS":             {`['\"=]ext\.js`, `extjs`, `/ext/.*\.js`},
		"Mootools":          {`/mootools/`, `mootools-`, `mootools\.js`},
		"Dojo":              {`/dojo/`, `['\"=]dojo-`, `['\"=]dojo\.js`},
		"Wordpress":         {`/wp-includes/`, `/wp-content/`},
		"React":             {`react\.production\.min\.js`, `react-dom`},
		"Vue.js":            {`vue\.min\.js`, `vue\.global`},
		"Angular":           {`angular\.min\.js`, `ng-app=`, `ng-controller=`},
		"Ember.js":          {`ember\.min\.js`, `/ember/`},
		"Backbone.js":       {`backbone\.min\.js`, `backbone-`},
		"Modernizr":         {`modernizr`},
		"Lodash/Underscore": {`lodash`, `underscore\.js`},
	}
	var sigs []frameworkSignature
	for name, patterns := range raw {
		var compiled []*regexp.Regexp
		for _, p := range patterns {
			compiled = append(compiled, regexp.MustCompile(`(?i)`+p))
		}
		sigs = append(sigs, frameworkSignature{Name: name, Patterns: compiled})
	}
	return sigs
}()

// Meta returns module metadata for WebFramework.
func (m *WebFramework) Meta() module.Meta {
	return module.Meta{
		Name:       "webframework",
		Summary:    "Identifies JavaScript frameworks and CMS platforms in web page content",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes WebFramework state.
func (m *WebFramework) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that WebFramework consumes.
func (m *WebFramework) WatchedEvents() []event.Type {
	return []event.Type{event.TARGET_WEB_CONTENT}
}

// ProducedEvents returns event types that WebFramework may emit.
func (m *WebFramework) ProducedEvents() []event.Type {
	return []event.Type{event.URL_WEB_FRAMEWORK}
}

// HandleEvent scans web content for framework signatures.
func (m *WebFramework) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	content := evt.Data
	if content == "" {
		return nil, nil
	}

	var results []*event.Event
	for _, sig := range frameworkSignatures {
		for _, re := range sig.Patterns {
			if re.MatchString(content) {
				key := sig.Name
				if !m.markSeen(key) {
					if e, err := event.New(event.URL_WEB_FRAMEWORK, sig.Name, "webframework", evt); err == nil {
						results = append(results, e)
					}
				}
				break
			}
		}
	}

	return results, nil
}

// Finish releases resources held by WebFramework.
func (m *WebFramework) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *WebFramework) markSeen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		return false
	}
	lk := strings.ToLower(key)
	if m.seen[lk] {
		return true
	}
	m.seen[lk] = true
	return false
}
