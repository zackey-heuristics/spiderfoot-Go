package sflib

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestParseCert(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		DNSNames:     []string{"example.com", "www.example.com"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Raw:          []byte{0x30, 0x00}, // minimal DER stub
	}
	cert.Subject.CommonName = "example.com"
	cert.Issuer.CommonName = "Test CA"

	info := ParseCert(cert, 30)
	if info.Subject != "example.com" {
		t.Fatalf("expected subject example.com, got %s", info.Subject)
	}
	if info.Issuer != "Test CA" {
		t.Fatalf("expected issuer Test CA, got %s", info.Issuer)
	}
	if len(info.SANs) != 2 {
		t.Fatalf("expected 2 SANs, got %d", len(info.SANs))
	}
	if info.IsExpired {
		t.Fatal("cert should not be expired")
	}
	if info.IsExpiringSoon {
		t.Fatal("cert should not be expiring soon")
	}
	if info.PEM == "" {
		t.Fatal("PEM should not be empty")
	}
}

func TestParseCertExpired(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		Raw:          []byte{0x30, 0x00},
	}
	info := ParseCert(cert, 30)
	if !info.IsExpired {
		t.Fatal("cert should be expired")
	}
}
