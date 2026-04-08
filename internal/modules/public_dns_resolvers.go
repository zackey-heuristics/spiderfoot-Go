// Package modules — public DNS resolver blocklist checks.
//
// Each public DNS resolver (Quad9, Cloudflare, OpenDNS, etc.) offers a
// filtered DNS service that refuses to resolve hosts it considers malicious.
// The generic publicDNSResolver module checks whether a host resolves via
// the default system resolver (i.e. actually exists) but fails to resolve
// via the filtered resolver — if so, the host is reported as blacklisted
// and malicious by that provider.

package modules

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// publicDNSResolver is a generic module that checks whether hosts are
// blocked by a specific public filtering DNS resolver.
type publicDNSResolver struct {
	name        string
	displayName string
	summary     string
	nameservers []string // "ip:53"
	resultURL   string   // optional URL template with %s for host

	resolver *net.Resolver
	seen     seenSet
}

// Meta returns module metadata.
func (m *publicDNSResolver) Meta() module.Meta {
	return module.Meta{
		Name:       m.name,
		Summary:    m.summary,
		Categories: []string{"Reputation Systems"},
	}
}

// Setup initializes the custom resolver and dedup state.
func (m *publicDNSResolver) Setup(_ map[string]any) error {
	m.seen.clear()
	nsList := append([]string(nil), m.nameservers...)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			d.Timeout = 3 * time.Second
			var lastErr error
			for _, ns := range nsList {
				conn, err := d.DialContext(ctx, network, ns)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no nameservers configured")
			}
			return nil, lastErr
		},
	}
	return nil
}

// WatchedEvents lists the event types this module consumes.
func (m *publicDNSResolver) WatchedEvents() []event.Type {
	return []event.Type{
		event.INTERNET_NAME,
		event.AFFILIATE_INTERNET_NAME,
		event.CO_HOSTED_SITE,
	}
}

// ProducedEvents lists the event types this module may emit.
func (m *publicDNSResolver) ProducedEvents() []event.Type {
	return []event.Type{
		event.BLACKLISTED_INTERNET_NAME,
		event.BLACKLISTED_AFFILIATE_INTERNET_NAME,
		event.BLACKLISTED_COHOST,
		event.MALICIOUS_INTERNET_NAME,
		event.MALICIOUS_AFFILIATE_INTERNET_NAME,
		event.MALICIOUS_COHOST,
	}
}

// HandleEvent checks whether the host resolves via the default resolver
// but is blocked by the filtered resolver, and emits blacklist/malicious
// events if so.
func (m *publicDNSResolver) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	var blacklistType, maliciousType event.Type
	switch evt.Type {
	case event.INTERNET_NAME:
		blacklistType = event.BLACKLISTED_INTERNET_NAME
		maliciousType = event.MALICIOUS_INTERNET_NAME
	case event.AFFILIATE_INTERNET_NAME:
		blacklistType = event.BLACKLISTED_AFFILIATE_INTERNET_NAME
		maliciousType = event.MALICIOUS_AFFILIATE_INTERNET_NAME
	case event.CO_HOSTED_SITE:
		blacklistType = event.BLACKLISTED_COHOST
		maliciousType = event.MALICIOUS_COHOST
	default:
		return nil, nil
	}

	// Atomically reserve the indicator via seenSet.begin. Concurrent
	// callers for the same indicator wait on the in-flight owner
	// and retry if the owner fails transiently.
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()

	// Must resolve via default resolver to be considered a real host.
	defCtx, defCancel := context.WithTimeout(ctx, 5*time.Second)
	defer defCancel()
	addrs, err := net.DefaultResolver.LookupHost(defCtx, evt.Data)
	if err != nil && !isDNSNotFoundErr(err) {
		// Transient error on the default resolver — defer releases the
		// reservation so a later event can retry.
		return nil, nil
	}
	if err != nil || len(addrs) == 0 {
		// Definitive NXDOMAIN — this isn't a real host. Keep the
		// reservation so we don't re-query for the same non-host.
		committed = true
		return nil, nil
	}

	// If it also resolves via the filtered resolver, it's not blocked.
	filCtx, filCancel := context.WithTimeout(ctx, 5*time.Second)
	defer filCancel()
	fAddrs, fErr := m.resolver.LookupHost(filCtx, evt.Data)
	if fErr != nil && !isDNSNotFoundErr(fErr) {
		// Transient error on the filter resolver — defer releases so
		// a later event can retry. Also avoids a false-positive
		// blacklisting when the filter resolver is flaky.
		return nil, nil
	}
	committed = true
	if fErr == nil && len(fAddrs) > 0 {
		return nil, nil
	}

	msg := fmt.Sprintf("%s [%s]", m.displayName, evt.Data)
	if m.resultURL != "" {
		msg = fmt.Sprintf("%s [%s]\n<SFURL>%s</SFURL>", m.displayName, evt.Data, fmt.Sprintf(m.resultURL, evt.Data))
	}

	var results []*event.Event
	if e, err := event.New(blacklistType, msg, m.name, evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(maliciousType, msg, m.name, evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish releases resources held by the module.
func (m *publicDNSResolver) Finish() error {
	m.seen.clear()
	return nil
}

func init() {
	module.Register("adguard_dns", func() module.Module {
		return &publicDNSResolver{
			name:        "adguard_dns",
			displayName: "AdGuard DNS",
			summary:     "Check if a host would be blocked by AdGuard DNS.",
			nameservers: []string{"94.140.14.15:53", "94.140.15.16:53"},
		}
	})

	module.Register("cleanbrowsing", func() module.Module {
		return &publicDNSResolver{
			name:        "cleanbrowsing",
			displayName: "CleanBrowsing",
			summary:     "Check if a host would be blocked by CleanBrowsing DNS (security filter).",
			nameservers: []string{"185.228.168.9:53", "185.228.169.9:53"},
		}
	})

	module.Register("cloudflaredns", func() module.Module {
		return &publicDNSResolver{
			name:        "cloudflaredns",
			displayName: "Cloudflare DNS",
			summary:     "Check if a host would be blocked by Cloudflare DNS (malware filter, 1.1.1.2).",
			nameservers: []string{"1.1.1.2:53", "1.0.0.2:53"},
		}
	})

	module.Register("comodo", func() module.Module {
		return &publicDNSResolver{
			name:        "comodo",
			displayName: "Comodo Secure DNS",
			summary:     "Check if a host would be blocked by Comodo Secure DNS.",
			nameservers: []string{"8.26.56.26:53", "8.20.247.20:53"},
		}
	})

	module.Register("opendns", func() module.Module {
		return &publicDNSResolver{
			name:        "opendns",
			displayName: "OpenDNS",
			summary:     "Check if a host would be blocked by OpenDNS (FamilyShield).",
			nameservers: []string{"208.67.222.123:53", "208.67.220.123:53"},
		}
	})

	module.Register("quad9", func() module.Module {
		return &publicDNSResolver{
			name:        "quad9",
			displayName: "Quad9",
			summary:     "Check if a host would be blocked by Quad9 DNS.",
			nameservers: []string{"9.9.9.9:53", "149.112.112.112:53"},
			resultURL:   "https://quad9.net/result/?url=%s",
		}
	})

	module.Register("yandexdns", func() module.Module {
		return &publicDNSResolver{
			name:        "yandexdns",
			displayName: "Yandex DNS",
			summary:     "Check if a host would be blocked by Yandex DNS (Safe).",
			nameservers: []string{"77.88.8.88:53", "77.88.8.2:53"},
		}
	})
}
