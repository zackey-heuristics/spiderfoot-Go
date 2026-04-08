// Package modules — Batch 16: More free reputation & blocklist feeds.
//
// This file ports four additional no-auth feed modules that all reuse
// the existing ipFeed / hostFeed generics from phishing_reputation.go:
//
//   - talosintel       — Cisco Talos (Snort) IP block list
//   - alienvaultiprep  — AlienVault OTX IP reputation (legacy generic feed)
//   - greensnow        — greensnow.co abusive IP feed
//   - stevenblack      — StevenBlack consolidated hosts blocklist
//
// Note: vxvault and multiproxy were deliberately dropped because their
// upstream sources are plaintext HTTP only. Ingesting unauthenticated
// reputation data would let any on-path attacker inject false
// positives/negatives into scan results; see Codex adversarial review
// 2026-04-09 for the trust-boundary rationale.
package modules

import (
	"net"
	"strings"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// parseAlienvaultIPRep parses the AlienVault reputation.generic feed.
// Each non-comment line is "<ip> #<score>" or just "<ip>"; the first
// whitespace-separated token is the IP address.
func parseAlienvaultIPRep(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// AlienVault uses "IP #description" — split on " #" first.
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) != nil {
			out[ip] = true
		}
	}
	return out
}

// parseStevenBlack parses the StevenBlack hosts file. Non-comment lines
// have the form "0.0.0.0 host1 [host2 ...]"; every hostname token after
// the leading IP is recorded (hosts-file syntax permits multiple aliases
// on one line, and taking only the first would silently drop entries).
// Inline comments introduced with '#' are stripped.
func parseStevenBlack(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments.
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[0] is the address (usually 0.0.0.0); everything after
		// is one or more host aliases.
		for _, raw := range fields[1:] {
			host := strings.ToLower(raw)
			if host == "" || !strings.Contains(host, ".") || host == "0.0.0.0" {
				continue
			}
			if host == "localhost" || host == "localhost.localdomain" {
				continue
			}
			out[host] = true
		}
	}
	return out
}

func init() {
	module.Register("talosintel", func() module.Module {
		return &ipFeed{
			name:    "talosintel",
			summary: "Check if an IP is in the Cisco Talos (Snort) IP block list.",
			url:     "https://snort.org/downloads/ip-block-list",
		}
	})
	module.Register("alienvaultiprep", func() module.Module {
		return &ipFeed{
			name:    "alienvaultiprep",
			summary: "Check if an IP is in the AlienVault IP reputation feed.",
			url:     "https://reputation.alienvault.com/reputation.generic",
			parser:  parseAlienvaultIPRep,
		}
	})
	module.Register("greensnow", func() module.Module {
		return &ipFeed{
			name:    "greensnow",
			summary: "Check if an IP is in the greensnow.co abusive-IP feed.",
			url:     "https://blocklist.greensnow.co/greensnow.txt",
		}
	})
	module.Register("stevenblack", func() module.Module {
		return &hostFeed{
			name:    "stevenblack",
			summary: "Check if a host is in the StevenBlack consolidated hosts blocklist.",
			url:     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			parser:  parseStevenBlack,
		}
	})
}
