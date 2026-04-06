package modules

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("whois", func() module.Module { return &Whois{} })
}

// Whois performs WHOIS lookups on domains and netblocks, extracting
// registrar information and raw WHOIS data.
type Whois struct {
	seen map[string]bool
	mu   sync.Mutex
}

// whoisEventMap maps input event types to their corresponding WHOIS output types.
var whoisEventMap = map[event.Type]event.Type{
	event.DOMAIN_NAME:           event.DOMAIN_WHOIS,
	event.DOMAIN_NAME_PARENT:    event.DOMAIN_WHOIS,
	event.CO_HOSTED_SITE_DOMAIN: event.CO_HOSTED_SITE_DOMAIN_WHOIS,
	event.AFFILIATE_DOMAIN_NAME: event.AFFILIATE_DOMAIN_WHOIS,
}

// Meta returns module metadata for Whois.
func (m *Whois) Meta() module.Meta {
	return module.Meta{
		Name:       "whois",
		Summary:    "Performs WHOIS lookups on domains to obtain registration data",
		Categories: []string{"Footprint"},
	}
}

// Setup initializes Whois state.
func (m *Whois) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that Whois consumes.
func (m *Whois) WatchedEvents() []event.Type {
	return []event.Type{
		event.DOMAIN_NAME,
		event.DOMAIN_NAME_PARENT,
		event.CO_HOSTED_SITE_DOMAIN,
		event.AFFILIATE_DOMAIN_NAME,
	}
}

// ProducedEvents returns event types that Whois may emit.
func (m *Whois) ProducedEvents() []event.Type {
	return []event.Type{
		event.DOMAIN_WHOIS,
		event.DOMAIN_REGISTRAR,
		event.CO_HOSTED_SITE_DOMAIN_WHOIS,
		event.AFFILIATE_DOMAIN_WHOIS,
	}
}

// HandleEvent performs a WHOIS query for the given domain.
func (m *Whois) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	domain := strings.TrimSpace(evt.Data)
	if domain == "" {
		return nil, nil
	}

	if m.markSeen(domain) {
		return nil, nil
	}

	outType, ok := whoisEventMap[evt.Type]
	if !ok {
		return nil, nil
	}

	data, err := m.queryWhois(ctx, domain)
	if err != nil || len(data) < 50 {
		return nil, nil
	}

	var results []*event.Event

	if e, err2 := event.New(outType, data, "whois", evt); err2 == nil {
		results = append(results, e)
	}

	// Extract registrar for domain events.
	if evt.Type == event.DOMAIN_NAME || evt.Type == event.DOMAIN_NAME_PARENT {
		registrar := extractWhoisField(data, "Registrar:")
		if registrar != "" {
			if e, err2 := event.New(event.DOMAIN_REGISTRAR, registrar, "whois", evt); err2 == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by Whois.
func (m *Whois) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// queryWhois connects to the appropriate WHOIS server and retrieves data.
func (m *Whois) queryWhois(ctx context.Context, domain string) (string, error) {
	server := whoisServer(domain)
	if server == "" {
		server = "whois.iana.org"
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("whois dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", fmt.Errorf("whois write: %w", err)
	}

	buf, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("whois read: %w", err)
	}
	return string(buf), nil
}

// whoisServer returns the WHOIS server for common TLDs.
func whoisServer(domain string) string {
	tld := domain
	if idx := strings.LastIndex(domain, "."); idx >= 0 {
		tld = domain[idx+1:]
	}
	servers := map[string]string{
		"com":  "whois.verisign-grs.com",
		"net":  "whois.verisign-grs.com",
		"org":  "whois.pir.org",
		"info": "whois.afilias.net",
		"io":   "whois.nic.io",
		"co":   "whois.nic.co",
		"me":   "whois.nic.me",
		"us":   "whois.nic.us",
		"uk":   "whois.nic.uk",
		"de":   "whois.denic.de",
		"jp":   "whois.jprs.jp",
		"fr":   "whois.nic.fr",
		"au":   "whois.auda.org.au",
		"ca":   "whois.cira.ca",
		"nl":   "whois.sidn.nl",
		"ru":   "whois.tcinet.ru",
		"cn":   "whois.cnnic.cn",
		"br":   "whois.registro.br",
		"eu":   "whois.eu",
	}
	if s, ok := servers[strings.ToLower(tld)]; ok {
		return s
	}
	return ""
}

// extractWhoisField extracts a field value from raw WHOIS text.
func extractWhoisField(data, field string) string {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, field) {
			val := strings.TrimSpace(strings.TrimPrefix(line, field))
			if val != "" {
				return val
			}
		}
	}
	return ""
}

func (m *Whois) markSeen(key string) bool {
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
