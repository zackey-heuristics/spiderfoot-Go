package modules

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("dns_raw", func() module.Module { return &DNSRaw{} })
}

// DNSRaw collects raw DNS records (MX, NS, CNAME, TXT/SPF) for domains
// and hostnames, extracting mail providers, DNS providers, and related names.
type DNSRaw struct {
	resolver *net.Resolver
	seen     map[string]bool
	mu       sync.Mutex
}

// spfIncludeRe extracts domain names from SPF include directives.
var spfIncludeRe = regexp.MustCompile(`include:(\S+)`)

// Meta returns module metadata for DNSRaw.
func (m *DNSRaw) Meta() module.Meta {
	return module.Meta{
		Name:       "dns_raw",
		Summary:    "Retrieves raw DNS records including MX, NS, CNAME, and TXT/SPF",
		Categories: []string{"DNS"},
	}
}

// Setup initializes DNSRaw state.
func (m *DNSRaw) Setup(_ map[string]any) error {
	m.resolver = net.DefaultResolver
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that DNSRaw consumes.
func (m *DNSRaw) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.DOMAIN_NAME, event.DOMAIN_NAME_PARENT}
}

// ProducedEvents returns event types that DNSRaw may emit.
func (m *DNSRaw) ProducedEvents() []event.Type {
	return []event.Type{
		event.PROVIDER_MAIL,
		event.PROVIDER_DNS,
		event.RAW_DNS_RECORDS,
		event.DNS_TXT,
		event.DNS_SPF,
		event.INTERNET_NAME,
	}
}

// HandleEvent queries DNS records for the given hostname or domain.
func (m *DNSRaw) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	domain := strings.ToLower(strings.TrimSpace(evt.Data))
	if domain == "" {
		return nil, nil
	}

	if m.markSeen(domain) {
		return nil, nil
	}

	var results []*event.Event

	// MX records
	rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	mxs, err := m.resolver.LookupMX(rCtx, domain)
	cancel()
	if err == nil {
		for _, mx := range mxs {
			host := strings.TrimSuffix(mx.Host, ".")
			if host == "" {
				continue
			}
			raw := domain + " MX " + host
			if e, err2 := event.New(event.RAW_DNS_RECORDS, raw, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}
			if e, err2 := event.New(event.PROVIDER_MAIL, host, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}
			if !m.markSeen(host) {
				if e, err2 := event.New(event.INTERNET_NAME, host, "dns_raw", evt); err2 == nil {
					results = append(results, e)
				}
			}
		}
	}

	// NS records
	rCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	nss, err := m.resolver.LookupNS(rCtx, domain)
	cancel()
	if err == nil {
		for _, ns := range nss {
			host := strings.TrimSuffix(ns.Host, ".")
			if host == "" {
				continue
			}
			raw := domain + " NS " + host
			if e, err2 := event.New(event.RAW_DNS_RECORDS, raw, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}
			if e, err2 := event.New(event.PROVIDER_DNS, host, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}
			if !m.markSeen(host) {
				if e, err2 := event.New(event.INTERNET_NAME, host, "dns_raw", evt); err2 == nil {
					results = append(results, e)
				}
			}
		}
	}

	// CNAME records
	rCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	cname, err := m.resolver.LookupCNAME(rCtx, domain)
	cancel()
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, domain) {
			raw := domain + " CNAME " + cname
			if e, err2 := event.New(event.RAW_DNS_RECORDS, raw, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}
			if !m.markSeen(cname) {
				if e, err2 := event.New(event.INTERNET_NAME, cname, "dns_raw", evt); err2 == nil {
					results = append(results, e)
				}
			}
		}
	}

	// TXT records
	rCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	txts, err := m.resolver.LookupTXT(rCtx, domain)
	cancel()
	if err == nil {
		for _, txt := range txts {
			if e, err2 := event.New(event.DNS_TXT, txt, "dns_raw", evt); err2 == nil {
				results = append(results, e)
			}

			lower := strings.ToLower(txt)
			if strings.Contains(lower, "v=spf") || strings.Contains(lower, "spf2.0/") {
				if e, err2 := event.New(event.DNS_SPF, txt, "dns_raw", evt); err2 == nil {
					results = append(results, e)
				}
				for _, match := range spfIncludeRe.FindAllStringSubmatch(txt, -1) {
					incDomain := strings.TrimSpace(match[1])
					if incDomain != "" && !m.markSeen(incDomain) {
						if e, err2 := event.New(event.INTERNET_NAME, incDomain, "dns_raw", evt); err2 == nil {
							results = append(results, e)
						}
					}
				}
			}
		}
	}

	return results, nil
}

// Finish releases resources held by DNSRaw.
func (m *DNSRaw) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *DNSRaw) markSeen(key string) bool {
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
