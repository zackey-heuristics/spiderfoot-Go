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
	module.Register("dns_resolve", func() module.Module { return &DNSResolve{} })
}

// DNSResolve performs forward and reverse DNS lookups.
type DNSResolve struct {
	resolver *net.Resolver
	seen     map[string]bool
	mu       sync.Mutex
}

// Meta returns module metadata.
func (d *DNSResolve) Meta() module.Meta {
	return module.Meta{
		Name:       "dns_resolve",
		Summary:    "Performs DNS resolution of hostnames and IPs",
		Categories: []string{"DNS"},
	}
}

// Setup initializes the resolver and dedup map.
func (d *DNSResolve) Setup(_ map[string]any) error {
	d.resolver = net.DefaultResolver
	d.seen = make(map[string]bool)
	return nil
}

// WatchedEvents lists the event types this module consumes.
func (d *DNSResolve) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.IP_ADDRESS, event.DOMAIN_NAME}
}

// ProducedEvents lists the event types this module may emit.
func (d *DNSResolve) ProducedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS, event.INTERNET_NAME, event.IPV6_ADDRESS}
}

// HandleEvent performs DNS lookups and returns discovered events.
func (d *DNSResolve) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	var results []*event.Event
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	switch evt.Type {
	case event.INTERNET_NAME, event.DOMAIN_NAME:
		addrs, err := d.resolver.LookupHost(ctx, evt.Data)
		if err != nil {
			return nil, nil
		}
		for _, addr := range addrs {
			if d.markSeen(addr) {
				continue
			}
			typ := event.IP_ADDRESS
			if strings.Contains(addr, ":") {
				typ = event.IPV6_ADDRESS
			}
			e, err := event.New(typ, addr, "dns_resolve", evt)
			if err != nil {
				continue
			}
			results = append(results, e)
		}

	case event.IP_ADDRESS:
		names, err := d.resolver.LookupAddr(ctx, evt.Data)
		if err != nil {
			return nil, nil
		}
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			if name == "" || d.markSeen(name) {
				continue
			}
			e, err := event.New(event.INTERNET_NAME, name, "dns_resolve", evt)
			if err != nil {
				continue
			}
			results = append(results, e)
		}
	}

	return results, nil
}

// Finish clears the dedup map.
func (d *DNSResolve) Finish() error {
	d.mu.Lock()
	d.seen = nil
	d.mu.Unlock()
	return nil
}

func (d *DNSResolve) markSeen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		return false
	}
	if d.seen[key] {
		return true
	}
	d.seen[key] = true
	return false
}
