package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("sslcert", func() module.Module { return &SSLCert{} })
}

// SSLCert retrieves and analyzes SSL/TLS certificates from hosts,
// extracting SANs, issuer info, and checking expiry status.
type SSLCert struct {
	seen          map[string]bool
	mu            sync.Mutex
	timeout       time.Duration
	expiringDays  int
	certExpiryDur time.Duration
}

// Meta returns module metadata for SSLCert.
func (m *SSLCert) Meta() module.Meta {
	return module.Meta{
		Name:       "sslcert",
		Summary:    "Retrieves and analyzes SSL/TLS certificates from hosts",
		Categories: []string{"Scanning"},
	}
}

// Setup initializes SSLCert configuration.
func (m *SSLCert) Setup(opts map[string]any) error {
	m.seen = make(map[string]bool)
	m.timeout = 10 * time.Second
	m.expiringDays = 30

	if v, ok := opts["timeout"].(int); ok && v > 0 {
		m.timeout = time.Duration(v) * time.Second
	}
	if v, ok := opts["certexpiringdays"].(int); ok && v > 0 {
		m.expiringDays = v
	}
	m.certExpiryDur = time.Duration(m.expiringDays) * 24 * time.Hour
	return nil
}

// WatchedEvents returns event types that SSLCert consumes.
func (m *SSLCert) WatchedEvents() []event.Type {
	return []event.Type{event.INTERNET_NAME, event.IP_ADDRESS}
}

// ProducedEvents returns event types that SSLCert may emit.
func (m *SSLCert) ProducedEvents() []event.Type {
	return []event.Type{
		event.TCP_PORT_OPEN,
		event.INTERNET_NAME,
		event.SSL_CERTIFICATE_ISSUED,
		event.SSL_CERTIFICATE_ISSUER,
		event.SSL_CERTIFICATE_MISMATCH,
		event.SSL_CERTIFICATE_EXPIRED,
		event.SSL_CERTIFICATE_EXPIRING,
		event.SSL_CERTIFICATE_RAW,
	}
}

// HandleEvent connects to the host via TLS and analyzes the certificate.
func (m *SSLCert) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	host := strings.TrimSpace(evt.Data)
	if host == "" {
		return nil, nil
	}

	if m.markSeen(host) {
		return nil, nil
	}

	addr := host + ":443"
	dialer := &net.Dialer{Timeout: m.timeout}

	tlsCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: we analyze the cert ourselves
	})
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	_ = tlsCtx // context used via dialer timeout

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil
	}

	cert := certs[0]
	var results []*event.Event

	// TCP port open.
	if e, err2 := event.New(event.TCP_PORT_OPEN, host+":443", "sslcert", evt); err2 == nil {
		results = append(results, e)
	}

	// Raw certificate info.
	raw := fmt.Sprintf("Subject: %s\nIssuer: %s\nNotBefore: %s\nNotAfter: %s",
		cert.Subject.CommonName, cert.Issuer.CommonName,
		cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	if e, err2 := event.New(event.SSL_CERTIFICATE_RAW, raw, "sslcert", evt); err2 == nil {
		results = append(results, e)
	}

	// Issued date.
	if e, err2 := event.New(event.SSL_CERTIFICATE_ISSUED, cert.NotBefore.Format(time.RFC3339), "sslcert", evt); err2 == nil {
		results = append(results, e)
	}

	// Issuer.
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.Organization[0]
	}
	if issuer != "" {
		if e, err2 := event.New(event.SSL_CERTIFICATE_ISSUER, issuer, "sslcert", evt); err2 == nil {
			results = append(results, e)
		}
	}

	// Check expiry.
	now := time.Now()
	if now.After(cert.NotAfter) {
		if e, err2 := event.New(event.SSL_CERTIFICATE_EXPIRED, cert.NotAfter.Format(time.RFC3339), "sslcert", evt); err2 == nil {
			results = append(results, e)
		}
	} else if cert.NotAfter.Before(now.Add(m.certExpiryDur)) {
		if e, err2 := event.New(event.SSL_CERTIFICATE_EXPIRING, cert.NotAfter.Format(time.RFC3339), "sslcert", evt); err2 == nil {
			results = append(results, e)
		}
	}

	// Check mismatch.
	if err := cert.VerifyHostname(host); err != nil {
		if e, err2 := event.New(event.SSL_CERTIFICATE_MISMATCH, host, "sslcert", evt); err2 == nil {
			results = append(results, e)
		}
	}

	// SANs.
	for _, san := range cert.DNSNames {
		san = strings.TrimSpace(san)
		if san == "" || san == host {
			continue
		}
		if !m.markSeen(san) {
			if e, err2 := event.New(event.INTERNET_NAME, san, "sslcert", evt); err2 == nil {
				results = append(results, e)
			}
		}
	}

	return results, nil
}

// Finish releases resources held by SSLCert.
func (m *SSLCert) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *SSLCert) markSeen(key string) bool {
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
