package sflib

import (
	"net"
	"strings"
)

// ValidIP returns true if addr is a valid IPv4 address.
func ValidIP(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() != nil
}

// ValidIP6 returns true if addr is a valid IPv6 address.
func ValidIP6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// ValidIPNetwork returns true if cidr is a valid CIDR notation network.
func ValidIPNetwork(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsPublicIP returns true if the IP address is globally routable (not private/loopback/link-local).
func IsPublicIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// HostDomain extracts the registered domain from a hostname.
// For "mail.example.com" it returns "example.com".
// For a plain domain like "example.com" it returns "example.com".
func HostDomain(hostname string) string {
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// IsDomain returns true if the string looks like a domain name (not an IP, has at least one dot).
func IsDomain(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || net.ParseIP(s) != nil {
		return false
	}
	return strings.Contains(s, ".") && !strings.Contains(s, " ")
}

// ValidHost returns true if the hostname is syntactically valid.
func ValidHost(hostname string) bool {
	hostname = strings.TrimSuffix(hostname, ".")
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	for _, part := range strings.Split(hostname, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
	}
	return true
}

// ExpandCIDR returns all host IPs in a CIDR block, up to maxSize.
// Returns nil if the CIDR is invalid or exceeds maxSize.
func ExpandCIDR(cidr string, maxSize int) []string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		if len(ips) >= maxSize {
			return nil
		}
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for IPv4 /31 and larger.
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
