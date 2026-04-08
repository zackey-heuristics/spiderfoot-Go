// Package modules — Batch 16: More free reputation & blocklist feeds.
//
// This file ports six additional no-auth feed modules that all reuse
// the existing ipFeed / hostFeed generics from phishing_reputation.go:
//
//   - talosintel       — Cisco Talos (Snort) IP block list
//   - alienvaultiprep  — AlienVault OTX IP reputation (legacy generic feed)
//   - greensnow        — greensnow.co abusive IP feed
//   - vxvault          — vxvault.net malware URL list (host extract)
//   - stevenblack      — StevenBlack consolidated hosts blocklist
//   - multiproxy       — multiproxy.org open proxy IP list (ip:port)
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

// parseVxVault parses the vxvault.net URL list. Only lines beginning
// with "http" are URLs; the host is the third '/' segment.
func parseVxVault(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "http") {
			continue
		}
		parts := strings.Split(line, "/")
		if len(parts) < 3 {
			continue
		}
		host := strings.SplitN(parts[2], ":", 2)[0]
		host = strings.ToLower(host)
		if host == "" || !strings.Contains(host, ".") {
			continue
		}
		out[host] = true
	}
	return out
}

// parseStevenBlack parses the StevenBlack hosts file. Non-comment lines
// have the form "0.0.0.0 host"; we take the second whitespace token.
func parseStevenBlack(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := strings.ToLower(fields[1])
		if host == "" || !strings.Contains(host, ".") || host == "0.0.0.0" {
			continue
		}
		// Skip loopback aliases that Steven Black's base file carries.
		if host == "localhost" || host == "localhost.localdomain" {
			continue
		}
		out[host] = true
	}
	return out
}

// parseMultiProxy parses the multiproxy.org proxy list. Each line is
// "<ip>:<port>"; we keep the IP half and discard malformed entries.
func parseMultiProxy(body string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := strings.SplitN(line, ":", 2)[0]
		if net.ParseIP(ip) != nil {
			out[ip] = true
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
	module.Register("vxvault", func() module.Module {
		return &hostFeed{
			name:    "vxvault",
			summary: "Check if a host is in the vxvault.net malware URL list.",
			url:     "http://vxvault.net/URL_List.php",
			parser:  parseVxVault,
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
	module.Register("multiproxy", func() module.Module {
		return &ipFeed{
			name:    "multiproxy",
			summary: "Check if an IP is in the multiproxy.org open proxy list.",
			url:     "http://multiproxy.org/txt_all/proxy.txt",
			parser:  parseMultiProxy,
		}
	})
}
