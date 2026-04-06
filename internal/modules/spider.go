package modules

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/sflib"
)

func init() {
	module.Register("spider", func() module.Module { return &Spider{} })
}

// Spider crawls web pages starting from discovered hostnames or internal URLs,
// extracting links, content, headers, and HTTP status codes.
type Spider struct {
	seen      map[string]bool
	mu        sync.Mutex
	maxPages  int
	maxLevels int
	timeout   time.Duration
	client    *http.Client
	// filterExts lists file extensions to skip (no leading dot).
	filterExts map[string]bool
}

// defaultFilterExts are file extensions that Spider will not fetch.
var defaultFilterExts = []string{
	"png", "gif", "jpg", "jpeg", "tiff", "tif", "tar", "pdf", "ico",
	"flv", "mp4", "mp3", "avi", "mpg", "gz", "mpeg", "iso", "dat",
	"mov", "swf", "rar", "exe", "zip", "bin", "bz2", "xsl",
	"doc", "docx", "ppt", "pptx", "xls", "xlsx", "csv",
}

// Meta returns module metadata for Spider.
func (m *Spider) Meta() module.Meta {
	return module.Meta{
		Name:       "spider",
		Summary:    "Crawls web pages to discover links, content, and HTTP headers",
		Categories: []string{"Crawling"},
	}
}

// Setup initializes Spider configuration.
func (m *Spider) Setup(opts map[string]any) error {
	m.seen = make(map[string]bool)
	m.maxPages = 100
	m.maxLevels = 3
	m.timeout = 15 * time.Second
	m.filterExts = make(map[string]bool)
	for _, ext := range defaultFilterExts {
		m.filterExts[ext] = true
	}

	if v, ok := opts["maxpages"].(int); ok && v > 0 {
		m.maxPages = v
	}
	if v, ok := opts["maxlevels"].(int); ok && v > 0 {
		m.maxLevels = v
	}
	if v, ok := opts["timeout"].(int); ok && v > 0 {
		m.timeout = time.Duration(v) * time.Second
	}

	m.client = &http.Client{
		Timeout: m.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return nil
}

// WatchedEvents returns event types that Spider consumes.
func (m *Spider) WatchedEvents() []event.Type {
	return []event.Type{event.LINKED_URL_INTERNAL, event.INTERNET_NAME}
}

// ProducedEvents returns event types that Spider may emit.
func (m *Spider) ProducedEvents() []event.Type {
	return []event.Type{
		event.WEBSERVER_HTTPHEADERS,
		event.HTTP_CODE,
		event.LINKED_URL_INTERNAL,
		event.LINKED_URL_EXTERNAL,
		event.TARGET_WEB_CONTENT,
		event.TARGET_WEB_CONTENT_TYPE,
	}
}

// HandleEvent crawls the given URL or hostname.
func (m *Spider) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	data := strings.TrimSpace(evt.Data)
	if data == "" {
		return nil, nil
	}

	var startURL string
	switch evt.Type {
	case event.INTERNET_NAME:
		startURL = "https://" + data
	case event.LINKED_URL_INTERNAL:
		startURL = data
	default:
		return nil, nil
	}

	m.mu.Lock()
	if m.seen[startURL] {
		m.mu.Unlock()
		return nil, nil
	}
	m.mu.Unlock()

	return m.crawl(ctx, evt, startURL)
}

// Finish releases resources held by Spider.
func (m *Spider) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *Spider) crawl(ctx context.Context, source *event.Event, startURL string) ([]*event.Event, error) {
	var results []*event.Event
	queue := []string{startURL}
	fetched := 0

	base, err := url.Parse(startURL)
	if err != nil {
		return nil, nil
	}

	for level := 0; level <= m.maxLevels && len(queue) > 0; level++ {
		var nextQueue []string
		for _, u := range queue {
			if ctx.Err() != nil {
				return results, nil
			}
			if fetched >= m.maxPages {
				return results, nil
			}
			if m.markSeen(u) {
				continue
			}
			if m.shouldSkip(u) {
				continue
			}

			pageResults, links := m.fetchPage(ctx, source, u, base.Host)
			results = append(results, pageResults...)
			nextQueue = append(nextQueue, links...)
			fetched++
		}
		queue = nextQueue
	}

	return results, nil
}

func (m *Spider) fetchPage(ctx context.Context, source *event.Event, pageURL, baseHost string) ([]*event.Event, []string) {
	var results []*event.Event
	var internalLinks []string

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "SpiderFoot-Go/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// HTTP code.
	if e, err2 := event.New(event.HTTP_CODE, resp.Status, "spider", source); err2 == nil {
		results = append(results, e)
	}

	// Headers as concatenated string.
	var headerLines []string
	for k, vals := range resp.Header {
		for _, v := range vals {
			headerLines = append(headerLines, k+": "+v)
		}
	}
	if len(headerLines) > 0 {
		if e, err2 := event.New(event.WEBSERVER_HTTPHEADERS, strings.Join(headerLines, "\n"), "spider", source); err2 == nil {
			results = append(results, e)
		}
	}

	// Content type.
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		if e, err2 := event.New(event.TARGET_WEB_CONTENT_TYPE, ct, "spider", source); err2 == nil {
			results = append(results, e)
		}
	}

	// Read body.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil || len(body) == 0 {
		return results, nil
	}

	bodyStr := string(body)
	if e, err2 := event.New(event.TARGET_WEB_CONTENT, bodyStr, "spider", source); err2 == nil {
		results = append(results, e)
	}

	// Extract links.
	links := sflib.ExtractLinksFromHTML(pageURL, bodyStr)
	for _, link := range links {
		linkURL, err := url.Parse(link.URL)
		if err != nil {
			continue
		}
		if linkURL.Host == "" || strings.EqualFold(linkURL.Host, baseHost) {
			if e, err2 := event.New(event.LINKED_URL_INTERNAL, link.URL, "spider", source); err2 == nil {
				results = append(results, e)
			}
			internalLinks = append(internalLinks, link.URL)
		} else {
			if e, err2 := event.New(event.LINKED_URL_EXTERNAL, link.URL, "spider", source); err2 == nil {
				results = append(results, e)
			}
		}
	}

	return results, internalLinks
}

func (m *Spider) shouldSkip(u string) bool {
	lower := strings.ToLower(u)
	for ext := range m.filterExts {
		if strings.HasSuffix(lower, "."+ext) {
			return true
		}
	}
	return false
}

func (m *Spider) markSeen(key string) bool {
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
