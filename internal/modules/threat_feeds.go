// Package modules — Batch 15: Free threat-intel feeds & blockchain lookup.
//
// This file implements pragmatic ports of eight free, no-auth modules:
//
//   - abusechfeodo     — abuse.ch Feodo Tracker IP blocklist
//   - abusechssl       — abuse.ch SSL Blacklist (IP CSV)
//   - abusechurlhaus   — abuse.ch URLhaus host blocklist
//   - botvrij          — botvrij.eu domain blocklist
//   - cinsscore        — CINS Army (Sentinel IPS) bad-guys IP list
//   - blocklistde      — blocklist.de aggregated abusive IPs
//   - coinblocker      — CoinBlockerLists cryptojacking domain feed
//   - blockchain       — blockchain.info Bitcoin wallet balance lookup
//
// The first seven all reuse the existing hostFeed/ipFeed generics from
// internal/modules/phishing_reputation.go. blockchain is a per-event
// JSON API call (no feed cache) and is implemented inline.
package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// parseAbusechFeodo parses the Feodo Tracker plaintext IP blocklist.
// Lines beginning with '#' are comments. Each remaining line is an IP.
func parseAbusechFeodo(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) != nil {
			out[line] = true
		}
	}
	return out
}

// parseAbusechSSL parses the abuse.ch SSL Blacklist CSV. Each non-comment
// line has the form `Listingdate,DstIP,DstPort,...`.
func parseAbusechSSL(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		ip := strings.Trim(fields[1], "\"")
		if net.ParseIP(ip) != nil {
			out[ip] = true
		}
	}
	return out
}

// parseAbusechURLHaus parses the URLhaus recent CSV. Each non-comment
// line is a quoted CSV row whose third column is the URL. The Python
// port takes a fast-path approach: split the URL on '/' to extract the
// host portion. We replicate that behaviour and look for any token
// containing a '.' that follows a `://` separator.
func parseAbusechURLHaus(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip surrounding quotes from CSV fields and find a URL.
		fields := strings.Split(line, ",")
		for _, f := range fields {
			f = strings.Trim(f, "\" ")
			idx := strings.Index(f, "://")
			if idx < 0 {
				continue
			}
			rest := f[idx+3:]
			parts := strings.SplitN(rest, "/", 2)
			host := strings.SplitN(parts[0], ":", 2)[0]
			host = strings.ToLower(host)
			if host == "" || !strings.Contains(host, ".") {
				continue
			}
			out[host] = true
			break
		}
	}
	return out
}

// parseBotvrij parses the botvrij.eu blocklist CSV. Each non-comment
// line's first field is a hostname.
func parseBotvrij(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := strings.ToLower(strings.SplitN(line, ",", 2)[0])
		if host != "" && strings.Contains(host, ".") {
			out[host] = true
		}
	}
	return out
}

// parseCoinBlocker parses the CoinBlockerLists hosts file. Lines are
// either `0.0.0.0 host` (hosts format) or bare hostnames; we accept
// either by taking the last whitespace-separated token.
func parseCoinBlocker(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		host := strings.ToLower(fields[len(fields)-1])
		if host == "" || !strings.Contains(host, ".") {
			continue
		}
		out[host] = true
	}
	return out
}

// ============================================================================
// Blockchain (per-event API call)
// ============================================================================

// Blockchain queries blockchain.info for the balance of a Bitcoin wallet
// address found by an upstream module. It is a free, no-auth API.
type Blockchain struct{ seen seenSet }

// Meta returns module metadata.
func (m *Blockchain) Meta() module.Meta {
	return module.Meta{
		Name:       "blockchain",
		Summary:    "Queries blockchain.info to find the balance of identified bitcoin wallet addresses.",
		Categories: []string{"Public Registries"},
	}
}

// Setup initializes internal state. blockchain takes no options.
func (m *Blockchain) Setup(_ map[string]any) error { return nil }

// WatchedEvents returns the consumed event types.
func (m *Blockchain) WatchedEvents() []event.Type {
	return []event.Type{event.BITCOIN_ADDRESS}
}

// ProducedEvents returns the emitted event types.
func (m *Blockchain) ProducedEvents() []event.Type {
	return []event.Type{event.BITCOIN_BALANCE}
}

// HandleEvent fetches the balance for a single wallet address and
// emits a BITCOIN_BALANCE event of the form "<value> BTC".
func (m *Blockchain) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil || evt.Data == "" {
		return nil, nil
	}
	skip, finish, err := m.seen.begin(ctx, string(evt.Type)+":"+evt.Data)
	if err != nil {
		return nil, err
	}
	if skip {
		return nil, nil
	}
	committed := false
	defer func() { finish(committed) }()
	if evt.Type != event.BITCOIN_ADDRESS {
		return nil, nil
	}
	endpoint := "https://blockchain.info/balance?active=" + evt.Data
	resp, err := repClient.FetchURL(ctx, endpoint)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil
	}
	var payload map[string]struct {
		FinalBalance int64 `json:"final_balance"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &payload); err != nil {
		return nil, nil
	}
	entry, ok := payload[evt.Data]
	if !ok {
		// Upstream responded successfully but with no entry for this
		// wallet — that is a definitive answer; mark committed.
		committed = true
		return nil, nil
	}
	committed = true
	btc := float64(entry.FinalBalance) / 100000000.0
	out, err := event.New(event.BITCOIN_BALANCE, fmt.Sprintf("%g BTC", btc), "blockchain", evt)
	if err != nil {
		return nil, nil
	}
	return []*event.Event{out}, nil
}

// Finish clears dedup state.
func (m *Blockchain) Finish() error { m.seen.clear(); return nil }

// ============================================================================
// Registrations
// ============================================================================

func init() {
	module.Register("abusechfeodo", func() module.Module {
		return &ipFeed{
			name:    "abusechfeodo",
			summary: "Check if an IP is in the abuse.ch Feodo Tracker botnet C2 blocklist.",
			url:     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		}
	})
	module.Register("abusechssl", func() module.Module {
		return &ipFeed{
			name:    "abusechssl",
			summary: "Check if an IP is in the abuse.ch SSL Blacklist.",
			url:     "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
		}
	})
	module.Register("abusechurlhaus", func() module.Module {
		return &hostFeed{
			name:    "abusechurlhaus",
			summary: "Check if a host is in the abuse.ch URLhaus malware URL blocklist.",
			url:     "https://urlhaus.abuse.ch/downloads/csv_recent/",
			parser:  parseAbusechURLHaus,
		}
	})
	module.Register("botvrij", func() module.Module {
		return &hostFeed{
			name:    "botvrij",
			summary: "Check if a host is in the botvrij.eu domain blocklist.",
			url:     "https://www.botvrij.eu/data/blocklist/blocklist_full.csv",
			parser:  parseBotvrij,
		}
	})
	module.Register("cinsscore", func() module.Module {
		return &ipFeed{
			name:    "cinsscore",
			summary: "Check if an IP is in the CINS Army (Sentinel IPS) bad-guys list.",
			url:     "https://cinsscore.com/list/ci-badguys.txt",
		}
	})
	module.Register("blocklistde", func() module.Module {
		return &ipFeed{
			name:    "blocklistde",
			summary: "Check if an IP is in the blocklist.de aggregated abusive-IP feed.",
			url:     "https://lists.blocklist.de/lists/all.txt",
		}
	})
	module.Register("coinblocker", func() module.Module {
		return &hostFeed{
			name:    "coinblocker",
			summary: "Check if a host is in the CoinBlockerLists cryptojacking blocklist.",
			url:     "https://zerodot1.gitlab.io/CoinBlockerLists/list.txt",
			parser:  parseCoinBlocker,
		}
	})
	module.Register("blockchain", func() module.Module { return &Blockchain{} })
}

// Compile-time assertion that Blockchain satisfies the module.Module
// interface; the registry registration above relies on it.
var _ module.Module = (*Blockchain)(nil)
