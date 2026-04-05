package modules

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("dns_commonsrv", func() module.Module { return &DNSCommonSRV{} })
}

// DNSCommonSRV checks for common DNS SRV records associated with a domain,
// such as LDAP, Kerberos, SIP, XMPP, and other well-known services.
type DNSCommonSRV struct {
	resolver *net.Resolver
	seen     map[string]bool
	mu       sync.Mutex
}

// srvRecords lists the common SRV service prefixes to probe.
var srvRecords = []string{
	"_ldap._tcp", "_gc._msdcs", "_ldap._tcp.pdc._msdcs", "_ldap._tcp.gc._msdcs",
	"_kerberos._tcp.dc._msdcs", "_kerberos._tcp", "_kerberos._udp",
	"_kerberos-master._tcp", "_kerberos-master._udp",
	"_kpasswd._tcp", "_kpasswd._udp", "_ntp._udp",
	"_sip._tcp", "_sip._udp", "_sip._tls", "_sips._tcp",
	"_stun._tcp", "_stun._udp", "_stuns._tcp",
	"_turn._tcp", "_turn._udp", "_turns._tcp",
	"_jabber._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
}

// Meta returns module metadata for DNSCommonSRV.
func (m *DNSCommonSRV) Meta() module.Meta {
	return module.Meta{
		Name:       "dns_commonsrv",
		Summary:    "Attempts to identify hostnames via common DNS SRV records",
		Categories: []string{"DNS"},
	}
}

// Setup initializes DNSCommonSRV state.
func (m *DNSCommonSRV) Setup(_ map[string]any) error {
	m.resolver = net.DefaultResolver
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents returns event types that DNSCommonSRV consumes.
func (m *DNSCommonSRV) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.DOMAIN_NAME}
}

// ProducedEvents returns event types that DNSCommonSRV may emit.
func (m *DNSCommonSRV) ProducedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.DNS_SRV}
}

// HandleEvent queries SRV records for the given domain or hostname.
func (m *DNSCommonSRV) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
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

	for _, srv := range srvRecords {
		if ctx.Err() != nil {
			break
		}

		query := srv + "." + domain
		rCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, addrs, err := m.resolver.LookupSRV(rCtx, "", "", query)
		cancel()

		if err != nil || len(addrs) == 0 {
			continue
		}

		for _, addr := range addrs {
			target := strings.TrimSuffix(addr.Target, ".")
			if target == "" || target == "." {
				continue
			}

			srvData := query + " -> " + target
			if e, err := event.New(event.DNS_SRV, srvData, "dns_commonsrv", evt); err == nil {
				results = append(results, e)
			}

			if !m.markSeen(target) {
				if e, err := event.New(event.INTERNET_NAME, target, "dns_commonsrv", evt); err == nil {
					results = append(results, e)
				}
			}
		}
	}

	return results, nil
}

// Finish releases resources held by DNSCommonSRV.
func (m *DNSCommonSRV) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *DNSCommonSRV) markSeen(key string) bool {
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
