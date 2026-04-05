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
	module.Register("dns_neighbor", func() module.Module { return &DNSNeighbor{} })
}

// DNSNeighbor discovers IP addresses neighboring a given IP by performing
// reverse DNS lookups on adjacent addresses within a configurable CIDR range.
type DNSNeighbor struct {
	resolver      *net.Resolver
	seen          map[string]bool
	mu            sync.Mutex
	lookasideBits int
}

// Meta returns module metadata for DNSNeighbor.
func (m *DNSNeighbor) Meta() module.Meta {
	return module.Meta{
		Name:       "dns_neighbor",
		Summary:    "Attempts to find neighboring hosts via reverse DNS on nearby IPs",
		Categories: []string{"DNS"},
	}
}

// Setup initializes DNSNeighbor state.
func (m *DNSNeighbor) Setup(opts map[string]any) error {
	m.resolver = net.DefaultResolver
	m.seen = make(map[string]bool)
	m.lookasideBits = 4

	if v, ok := opts["lookasidebits"].(int); ok && v > 0 && v <= 8 {
		m.lookasideBits = v
	}
	return nil
}

// WatchedEvents returns event types that DNSNeighbor consumes.
func (m *DNSNeighbor) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS}
}

// ProducedEvents returns event types that DNSNeighbor may emit.
func (m *DNSNeighbor) ProducedEvents() []event.Type {
	return []event.Type{event.AFFILIATE_IPADDR, event.INTERNET_NAME}
}

// HandleEvent performs reverse DNS lookups on neighboring IP addresses.
func (m *DNSNeighbor) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	ipStr := strings.TrimSpace(evt.Data)
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return nil, nil
	}

	if m.markSeen(ipStr) {
		return nil, nil
	}

	maskBits := 32 - m.lookasideBits
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipStr, maskBits))
	if err != nil {
		return nil, nil
	}

	var results []*event.Event
	for neighbor := incrementIP(copyIP(network.IP)); network.Contains(neighbor); neighbor = incrementIP(neighbor) {
		if ctx.Err() != nil {
			break
		}
		nStr := neighbor.String()
		if nStr == ipStr || m.markSeen(nStr) {
			continue
		}

		rCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		names, err := m.resolver.LookupAddr(rCtx, nStr)
		cancel()

		if err != nil || len(names) == 0 {
			if e, err2 := event.New(event.AFFILIATE_IPADDR, nStr, "dns_neighbor", evt); err2 == nil {
				results = append(results, e)
			}
			continue
		}

		if e, err2 := event.New(event.AFFILIATE_IPADDR, nStr, "dns_neighbor", evt); err2 == nil {
			results = append(results, e)
		}

		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			if name == "" {
				continue
			}
			if e, err2 := event.New(event.INTERNET_NAME, name, "dns_neighbor", evt); err2 == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by DNSNeighbor.
func (m *DNSNeighbor) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *DNSNeighbor) markSeen(key string) bool {
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

// copyIP returns a copy of an IP address.
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// incrementIP adds 1 to an IP address in place and returns it.
func incrementIP(ip net.IP) net.IP {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	return ip
}
