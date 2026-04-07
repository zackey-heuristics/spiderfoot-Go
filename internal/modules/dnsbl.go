// Package modules — DNS-based IP/domain blacklist (DNSBL) checks.
//
// A DNSBL is queried by constructing a hostname from the target (reversed
// IPv4 octets for IPs, or the bare domain for domain-based zones) and
// appending a zone suffix, then looking up the A record via the default
// DNS resolver. If any A record comes back, the target is listed.

package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// isDNSNotFoundErr reports whether err is a definitive DNS result —
// either a successful lookup (nil error) or an NXDOMAIN-style "not
// found" response. Transient failures (SERVFAIL, timeout, network
// errors) return false so callers can retry them on later events
// instead of permanently marking an indicator as processed.
func isDNSNotFoundErr(err error) bool {
	if err == nil {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// ipDNSBL is a generic module that checks whether an IP address is listed
// in a specific DNSBL zone.
type ipDNSBL struct {
	name         string
	displayName  string
	summary      string
	zones        []string // one or more DNSBL zone suffixes to query
	checkDomains bool     // if true, also watch INTERNET_NAME and query domain directly

	seen map[string]bool
	mu   sync.Mutex
}

// Meta returns module metadata.
func (m *ipDNSBL) Meta() module.Meta {
	return module.Meta{
		Name:       m.name,
		Summary:    m.summary,
		Categories: []string{"Reputation Systems"},
	}
}

// Setup initializes the dedup map.
func (m *ipDNSBL) Setup(_ map[string]any) error {
	m.seen = make(map[string]bool)
	return nil
}

// WatchedEvents lists the event types this module consumes.
func (m *ipDNSBL) WatchedEvents() []event.Type {
	events := []event.Type{event.IP_ADDRESS, event.AFFILIATE_IPADDR}
	if m.checkDomains {
		events = append(events,
			event.INTERNET_NAME,
			event.AFFILIATE_INTERNET_NAME,
			event.CO_HOSTED_SITE,
		)
	}
	return events
}

// ProducedEvents lists the event types this module may emit.
func (m *ipDNSBL) ProducedEvents() []event.Type {
	events := []event.Type{
		event.BLACKLISTED_IPADDR,
		event.BLACKLISTED_AFFILIATE_IPADDR,
		event.MALICIOUS_IPADDR,
		event.MALICIOUS_AFFILIATE_IPADDR,
	}
	if m.checkDomains {
		events = append(events,
			event.BLACKLISTED_INTERNET_NAME,
			event.BLACKLISTED_AFFILIATE_INTERNET_NAME,
			event.BLACKLISTED_COHOST,
			event.MALICIOUS_INTERNET_NAME,
			event.MALICIOUS_AFFILIATE_INTERNET_NAME,
			event.MALICIOUS_COHOST,
		)
	}
	return events
}

// HandleEvent queries the DNSBL zones for the event target and emits
// blacklist/malicious events if the target is listed.
func (m *ipDNSBL) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}

	var blType, malType event.Type
	var lookupKey string

	switch evt.Type {
	case event.IP_ADDRESS:
		rev := reverseIPv4(evt.Data)
		if rev == "" {
			return nil, nil
		}
		lookupKey = rev
		blType = event.BLACKLISTED_IPADDR
		malType = event.MALICIOUS_IPADDR
	case event.AFFILIATE_IPADDR:
		rev := reverseIPv4(evt.Data)
		if rev == "" {
			return nil, nil
		}
		lookupKey = rev
		blType = event.BLACKLISTED_AFFILIATE_IPADDR
		malType = event.MALICIOUS_AFFILIATE_IPADDR
	case event.INTERNET_NAME:
		if !m.checkDomains {
			return nil, nil
		}
		lookupKey = evt.Data
		blType = event.BLACKLISTED_INTERNET_NAME
		malType = event.MALICIOUS_INTERNET_NAME
	case event.AFFILIATE_INTERNET_NAME:
		if !m.checkDomains {
			return nil, nil
		}
		lookupKey = evt.Data
		blType = event.BLACKLISTED_AFFILIATE_INTERNET_NAME
		malType = event.MALICIOUS_AFFILIATE_INTERNET_NAME
	case event.CO_HOSTED_SITE:
		if !m.checkDomains {
			return nil, nil
		}
		lookupKey = evt.Data
		blType = event.BLACKLISTED_COHOST
		malType = event.MALICIOUS_COHOST
	default:
		return nil, nil
	}

	// Atomically reserve the indicator. If another goroutine is
	// already handling it (or it has been definitively processed),
	// skip without doing duplicate DNS work.
	if m.markSeen(evt.Data) {
		return nil, nil
	}
	committed := false
	defer func() {
		if !committed {
			m.releaseSeen(evt.Data)
		}
	}()

	listed := false
	anyDefinitive := false
	for _, zone := range m.zones {
		host := lookupKey + "." + strings.TrimPrefix(zone, ".")
		qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(qCtx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			listed = true
			anyDefinitive = true
			break
		}
		if isDNSNotFoundErr(err) {
			// Definitive "not listed" for this zone — keep looking
			// across remaining zones, but remember we have at least
			// one authoritative answer.
			anyDefinitive = true
			continue
		}
		// Transient error (SERVFAIL / timeout / network) — try next
		// zone; it may still return a definitive answer.
	}
	if !anyDefinitive {
		// Every zone returned a transient error — defer releases the
		// reservation so a later event for the same indicator can retry.
		return nil, nil
	}
	committed = true
	if !listed {
		return nil, nil
	}

	msg := fmt.Sprintf("%s [%s]", m.displayName, evt.Data)
	var results []*event.Event
	if e, err := event.New(blType, msg, m.name, evt); err == nil {
		results = append(results, e)
	}
	if e, err := event.New(malType, msg, m.name, evt); err == nil {
		results = append(results, e)
	}
	return results, nil
}

// Finish releases resources held by the module.
func (m *ipDNSBL) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

// releaseSeen deletes key from the dedup set so a later event for the
// same indicator can retry. Used to undo a markSeen reservation when
// every zone returned a transient DNS error.
func (m *ipDNSBL) releaseSeen(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen != nil {
		delete(m.seen, key)
	}
}

// markSeen atomically records and checks key. Returns true if the key
// was already present (caller should skip), false if it was newly
// reserved (caller must call releaseSeen on transient failure).
func (m *ipDNSBL) markSeen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = make(map[string]bool)
	}
	if m.seen[key] {
		return true
	}
	m.seen[key] = true
	return false
}

// reverseIPv4 returns the dot-reversed form of an IPv4 address, or "" if
// the input is not a valid IPv4 address.
func reverseIPv4(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

func init() {
	module.Register("spamhaus", func() module.Module {
		return &ipDNSBL{
			name:        "spamhaus",
			displayName: "Spamhaus Zen",
			summary:     "Check if an IP is listed in the Spamhaus Zen DNSBL.",
			zones:       []string{"zen.spamhaus.org"},
		}
	})

	module.Register("sorbs", func() module.Module {
		return &ipDNSBL{
			name:        "sorbs",
			displayName: "SORBS",
			summary:     "Check if an IP is listed in the SORBS DNSBL.",
			zones:       []string{"dnsbl.sorbs.net"},
		}
	})

	module.Register("spamcop", func() module.Module {
		return &ipDNSBL{
			name:        "spamcop",
			displayName: "SpamCop",
			summary:     "Check if an IP is listed in the SpamCop DNSBL.",
			zones:       []string{"bl.spamcop.net"},
		}
	})

	module.Register("uceprotect", func() module.Module {
		return &ipDNSBL{
			name:        "uceprotect",
			displayName: "UCEPROTECT",
			summary:     "Check if an IP is listed in the UCEPROTECT Level 1/2 DNSBLs.",
			zones:       []string{"dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net"},
		}
	})

	module.Register("dronebl", func() module.Module {
		return &ipDNSBL{
			name:        "dronebl",
			displayName: "DroneBL",
			summary:     "Check if an IP is listed in the DroneBL DNSBL.",
			zones:       []string{"dnsbl.dronebl.org"},
		}
	})

	module.Register("surbl", func() module.Module {
		return &ipDNSBL{
			name:         "surbl",
			displayName:  "SURBL",
			summary:      "Check if an IP or domain is listed in the SURBL multi blocklist.",
			zones:        []string{"multi.surbl.org"},
			checkDomains: true,
		}
	})
}
