package sflib

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds parsed SSL certificate information.
type CertInfo struct {
	// Subject is the certificate subject common name.
	Subject string
	// Issuer is the certificate issuer.
	Issuer string
	// SANs is the list of Subject Alternative Names.
	SANs []string
	// NotBefore is the certificate validity start.
	NotBefore time.Time
	// NotAfter is the certificate validity end.
	NotAfter time.Time
	// IsExpired is true if the certificate has expired.
	IsExpired bool
	// IsExpiringSoon is true if the certificate expires within expiringDays.
	IsExpiringSoon bool
	// PEM is the PEM-encoded certificate.
	PEM string
	// SerialNumber is the certificate serial number as a hex string.
	SerialNumber string
}

// FetchSSLCert connects to host:port via TLS and returns the peer certificate.
func FetchSSLCert(ctx context.Context, host string, port int, timeout time.Duration) (*x509.Certificate, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional for OSINT scanning
		ServerName:         host,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer conn.Close()

	// Respect context cancellation.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s", addr)
	}
	return certs[0], nil
}

// ParseCert extracts useful information from an x509 certificate.
// expiringDays determines the threshold for IsExpiringSoon.
func ParseCert(cert *x509.Certificate, expiringDays int) CertInfo {
	if expiringDays <= 0 {
		expiringDays = 30
	}

	info := CertInfo{
		Subject:        cert.Subject.CommonName,
		Issuer:         cert.Issuer.CommonName,
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		IsExpired:      time.Now().After(cert.NotAfter),
		IsExpiringSoon: time.Now().Add(time.Duration(expiringDays) * 24 * time.Hour).After(cert.NotAfter),
		SerialNumber:   fmt.Sprintf("%x", cert.SerialNumber),
	}

	// Collect SANs.
	seen := make(map[string]bool)
	for _, name := range cert.DNSNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && !seen[name] {
			info.SANs = append(info.SANs, name)
			seen[name] = true
		}
	}
	for _, ip := range cert.IPAddresses {
		s := ip.String()
		if !seen[s] {
			info.SANs = append(info.SANs, s)
			seen[s] = true
		}
	}

	// PEM encode.
	info.PEM = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))

	return info
}
