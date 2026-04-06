package modules

import (
	"context"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("webserver", func() module.Module { return &WebServer{} })
}

// WebServer identifies web server software and technologies from HTTP headers,
// including server banners, powered-by headers, and cookie-based detection.
type WebServer struct {
	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata for WebServer.
func (m *WebServer) Meta() module.Meta {
	return module.Meta{
		Name:       "webserver",
		Summary:    "Identifies web server software and technologies from HTTP response headers",
		Categories: []string{"Content Analysis"},
	}
}

// Setup initializes WebServer state.
func (m *WebServer) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that WebServer consumes.
func (m *WebServer) WatchedEvents() []event.Type {
	return []event.Type{event.WEBSERVER_HTTPHEADERS}
}

// ProducedEvents returns event types that WebServer may emit.
func (m *WebServer) ProducedEvents() []event.Type {
	return []event.Type{
		event.WEBSERVER_BANNER,
		event.WEBSERVER_TECHNOLOGY,
	}
}

// HandleEvent parses HTTP headers to extract server information.
func (m *WebServer) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	headers := evt.Data
	if headers == "" {
		return nil, nil
	}

	var results []*event.Event
	var techs []string

	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "server":
			if val != "" && !m.markSeen("banner:"+val) {
				if e, err := event.New(event.WEBSERVER_BANNER, val, "webserver", evt); err == nil {
					results = append(results, e)
				}
			}
		case "x-powered-by":
			if val != "" {
				techs = append(techs, val)
			}
		case "x-aspnet-version":
			techs = append(techs, "ASP.NET")
		case "set-cookie":
			lower := strings.ToLower(val)
			if strings.Contains(lower, "phpsess") {
				techs = append(techs, "PHP")
			}
			if strings.Contains(lower, "jsessionid") {
				techs = append(techs, "Java/JSP")
			}
			if strings.Contains(lower, "asp.net") {
				techs = append(techs, "ASP.NET")
			}
		}
	}

	for _, tech := range techs {
		if !m.markSeen("tech:" + strings.ToLower(tech)) {
			if e, err := event.New(event.WEBSERVER_TECHNOLOGY, tech, "webserver", evt); err == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by WebServer.
func (m *WebServer) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *WebServer) markSeen(key string) bool {
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
