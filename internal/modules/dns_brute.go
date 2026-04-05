package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("dns_brute", func() module.Module { return &DNSBrute{} })
}

// DNSBrute attempts to identify hostnames through brute-forcing common
// subdomain names and numeric suffixes against discovered domains.
type DNSBrute struct {
	resolver   *net.Resolver
	seen       map[string]bool
	mu         sync.Mutex
	maxWorkers int
	domainOnly bool
	numSuffix  bool
	subdomains []string
}

// commonSubdomains is a built-in list of frequently used subdomain prefixes.
var commonSubdomains = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3", "ns4",
	"blog", "dev", "staging", "api", "app", "admin", "test", "portal", "vpn",
	"mx", "cloud", "git", "ssh", "login", "remote", "m", "mobile", "shop",
	"store", "cdn", "web", "email", "support", "wiki", "docs", "status",
	"monitor", "beta", "demo", "lab", "intranet", "gateway", "proxy", "db",
	"sql", "mysql", "redis", "cache", "search", "media", "images", "img",
	"static", "assets", "files", "download", "backup", "archive", "old", "new",
	"uat", "qa", "prod", "jenkins", "ci", "gitlab", "jira", "grafana",
	"kibana", "elastic", "docker", "registry", "vault", "ntp", "ldap", "dns",
	"relay", "imap", "exchange", "autodiscover", "cpanel",
}

// Meta returns module metadata for DNSBrute.
func (m *DNSBrute) Meta() module.Meta {
	return module.Meta{
		Name:       "dns_brute",
		Summary:    "Attempts to identify hostnames through brute-forcing common names and suffixes",
		Categories: []string{"DNS"},
	}
}

// Setup initializes configuration for DNSBrute.
func (m *DNSBrute) Setup(opts map[string]any) error {
	m.resolver = net.DefaultResolver
	m.seen = make(map[string]bool)
	m.maxWorkers = 50
	m.domainOnly = true
	m.numSuffix = true
	m.subdomains = commonSubdomains

	if v, ok := opts["maxworkers"].(int); ok && v > 0 {
		m.maxWorkers = v
	}
	if v, ok := opts["domainonly"].(bool); ok {
		m.domainOnly = v
	}
	if v, ok := opts["numbersuffix"].(bool); ok {
		m.numSuffix = v
	}
	if v, ok := opts["subdomains"].([]string); ok && len(v) > 0 {
		m.subdomains = v
	}
	return nil
}

// WatchedEvents returns event types that DNSBrute consumes.
func (m *DNSBrute) WatchedEvents() []event.Type {
	return []event.Type{event.DOMAIN_NAME, event.INTERNET_NAME}
}

// ProducedEvents returns event types that DNSBrute may emit.
func (m *DNSBrute) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME}
}

// HandleEvent brute-forces subdomains for domain events.
func (m *DNSBrute) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	domain := strings.ToLower(strings.TrimSpace(evt.Data))
	if domain == "" {
		return nil, nil
	}

	if evt.Type == event.INTERNET_NAME && m.domainOnly {
		return nil, nil
	}

	if m.markSeen(domain) {
		return nil, nil
	}

	var candidates []string
	for _, sub := range m.subdomains {
		candidates = append(candidates, sub+"."+domain)
	}

	if m.numSuffix && evt.Type == event.INTERNET_NAME {
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			for i := 1; i <= 10; i++ {
				candidates = append(candidates, fmt.Sprintf("%s%d.%s", parts[0], i, parts[1]))
				candidates = append(candidates, fmt.Sprintf("%s-%d.%s", parts[0], i, parts[1]))
			}
		}
	}

	return m.resolveAll(ctx, evt, candidates), nil
}

// Finish releases resources held by DNSBrute.
func (m *DNSBrute) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *DNSBrute) resolveAll(ctx context.Context, source *event.Event, candidates []string) []*event.Event {
	var (
		results []*event.Event
		resMu   sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, m.maxWorkers)
	)

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		candidate := candidate
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			rCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			addrs, err := m.resolver.LookupHost(rCtx, candidate)
			if err != nil || len(addrs) == 0 {
				return
			}

			resMu.Lock()
			defer resMu.Unlock()
			if m.markSeenLocked(candidate) {
				return
			}
			e, err := event.New(event.INTERNET_NAME, candidate, "dns_brute", source)
			if err == nil {
				results = append(results, e)
			}
		}()
	}

	wg.Wait()
	return results
}

func (m *DNSBrute) markSeen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.markSeenLocked(key)
}

func (m *DNSBrute) markSeenLocked(key string) bool {
	if m.seen == nil {
		return false
	}
	if m.seen[key] {
		return true
	}
	m.seen[key] = true
	return false
}
