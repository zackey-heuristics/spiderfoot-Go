package sflib

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ResolveHost performs a forward DNS lookup for A and AAAA records.
func ResolveHost(ctx context.Context, host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// ResolveIP performs a reverse DNS lookup for an IP address.
func ResolveIP(ctx context.Context, ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return nil, err
	}
	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}
	return names, nil
}

// CustomResolve performs a DNS lookup using specific nameservers.
func CustomResolve(ctx context.Context, host string, nameservers []string) ([]string, error) {
	if len(nameservers) == 0 {
		return ResolveHost(ctx, host)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			ns := nameservers[0]
			if !strings.Contains(ns, ":") {
				ns = ns + ":53"
			}
			return d.DialContext(dialCtx, "udp", ns)
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return resolver.LookupHost(ctx, host)
}

// DNSBLCheck checks if an IP is listed in a DNS blacklist zone.
// It reverses the IP octets and queries the DNSBL zone.
// Returns true if the IP is listed (query returns a result).
func DNSBLCheck(ctx context.Context, ip, zone string) (bool, error) {
	reversed, err := reverseIP(ip)
	if err != nil {
		return false, err
	}

	query := reversed + "." + zone
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		// NXDOMAIN = not listed.
		return false, nil
	}
	return len(addrs) > 0, nil
}

// CheckDNSWildcard checks if a domain has wildcard DNS by resolving a
// random non-existent subdomain and seeing if it returns results.
func CheckDNSWildcard(ctx context.Context, domain string) bool {
	random := "sf-wildcard-check-7x9q2m." + domain
	addrs, err := ResolveHost(ctx, random)
	return err == nil && len(addrs) > 0
}

func reverseIP(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP: %s", ip)
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", fmt.Errorf("IPv6 DNSBL not supported: %s", ip)
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0]), nil
}
