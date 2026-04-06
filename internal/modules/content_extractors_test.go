package modules

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// helper to make a TARGET_WEB_CONTENT event with given body.
func makeContentEvent(t *testing.T, body string) *event.Event {
	t.Helper()
	root, err := event.New(event.ROOT, "test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	evt, err := event.New(event.TARGET_WEB_CONTENT, body, "spider", root)
	if err != nil {
		t.Fatal(err)
	}
	return evt
}

func runExtractor(t *testing.T, name, body string) []*event.Event {
	t.Helper()
	factory, ok := module.Get(name)
	if !ok {
		t.Fatalf("module %q not registered", name)
	}
	mod := factory()
	if err := mod.Setup(nil); err != nil {
		t.Fatal(err)
	}
	results, err := mod.HandleEvent(context.Background(), makeContentEvent(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return results
}

func TestEmailExtractor(t *testing.T) {
	results := runExtractor(t, "email", "Contact admin@example.com or support@test.org")
	if len(results) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(results))
	}
	for _, r := range results {
		if r.Type != event.EMAILADDR {
			t.Fatalf("expected EMAILADDR, got %s", r.Type)
		}
	}
}

func TestBitcoinExtractor(t *testing.T) {
	body := "Send to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT please"
	results := runExtractor(t, "bitcoin", body)
	if len(results) != 1 {
		t.Fatalf("expected 1 bitcoin address, got %d", len(results))
	}
	if results[0].Type != event.BITCOIN_ADDRESS {
		t.Fatalf("expected BITCOIN_ADDRESS, got %s", results[0].Type)
	}
}

func TestEthereumExtractor(t *testing.T) {
	body := "Eth: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
	results := runExtractor(t, "ethereum", body)
	if len(results) != 1 {
		t.Fatalf("expected 1 ethereum address, got %d", len(results))
	}
	if results[0].Type != event.ETHEREUM_ADDRESS {
		t.Fatalf("expected ETHEREUM_ADDRESS, got %s", results[0].Type)
	}
}

func TestCreditCardExtractor(t *testing.T) {
	body := "VISA: 4111111111111111 expires soon"
	results := runExtractor(t, "creditcard", body)
	if len(results) != 1 {
		t.Fatalf("expected 1 credit card, got %d", len(results))
	}
}

func TestIBANExtractor(t *testing.T) {
	body := "Account: GB82WEST12345698765432 please transfer"
	results := runExtractor(t, "iban", body)
	if len(results) != 1 {
		t.Fatalf("expected 1 IBAN, got %d", len(results))
	}
}

func TestPhoneExtractor(t *testing.T) {
	body := "Call us at +1-555-123-4567 today"
	results := runExtractor(t, "phone", body)
	if len(results) == 0 {
		t.Fatal("expected at least 1 phone number")
	}
}

func TestNamesExtractor(t *testing.T) {
	body := "Author: John Smith. Reviewed by Jane Doe."
	results := runExtractor(t, "names", body)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 names, got %d", len(results))
	}
}

func TestErrorsExtractor(t *testing.T) {
	body := "Warning: mysql_query() failed at line 23. Stack trace: ..."
	results := runExtractor(t, "errors", body)
	if len(results) == 0 {
		t.Fatal("expected at least one error message")
	}
}

func TestHashesExtractor(t *testing.T) {
	body := "MD5: d41d8cd98f00b204e9800998ecf8427e and SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
	results := runExtractor(t, "hashes", body)
	if len(results) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(results))
	}
}

func TestBase64Extractor(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("This is test data with sufficient length for matching"))
	body := "Encoded data: " + encoded + " end"
	results := runExtractor(t, "base64", body)
	if len(results) == 0 {
		t.Fatal("expected at least one base64 string")
	}
}

func TestCookieExtractor(t *testing.T) {
	factory, _ := module.Get("cookie")
	mod := factory()
	_ = mod.Setup(nil)

	root, _ := event.New(event.ROOT, "test", "", nil)
	headers := "Server: nginx\nSet-Cookie: session=abc123; HttpOnly\nSet-Cookie: tracking=xyz; Path=/"
	evt, _ := event.New(event.WEBSERVER_HTTPHEADERS, headers, "spider", root)

	results, err := mod.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(results))
	}
	for _, r := range results {
		if r.Type != event.TARGET_WEB_COOKIE {
			t.Fatalf("expected TARGET_WEB_COOKIE, got %s", r.Type)
		}
	}
}

func TestBinstringExtractor(t *testing.T) {
	body := "Embedded: " + string(make([]byte, 0)) + "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AAA end"
	results := runExtractor(t, "binstring", body)
	if len(results) == 0 {
		t.Fatal("expected at least one binary string")
	}
}

// Meta and event signature tests for all registered extractors.

func TestContentExtractorsMetaAndEvents(t *testing.T) {
	names := []string{
		"email", "bitcoin", "ethereum", "creditcard", "iban", "phone",
		"names", "errors", "binstring", "hashes", "base64", "cookie",
	}
	for _, name := range names {
		factory, ok := module.Get(name)
		if !ok {
			t.Errorf("module %q not registered", name)
			continue
		}
		mod := factory()
		meta := mod.Meta()
		if meta.Name != name {
			t.Errorf("module %q has Meta name %q", name, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("module %q has empty summary", name)
		}
		if len(mod.WatchedEvents()) == 0 {
			t.Errorf("module %q has no watched events", name)
		}
		if len(mod.ProducedEvents()) == 0 {
			t.Errorf("module %q has no produced events", name)
		}
	}
}

func TestContentExtractorsHandleNil(t *testing.T) {
	names := []string{"email", "bitcoin", "ethereum", "hashes", "base64", "cookie"}
	for _, name := range names {
		factory, _ := module.Get(name)
		mod := factory()
		_ = mod.Setup(nil)
		results, err := mod.HandleEvent(context.Background(), nil)
		if err != nil {
			t.Errorf("module %q returned error on nil: %v", name, err)
		}
		if results != nil {
			t.Errorf("module %q returned non-nil results on nil event", name)
		}
	}
}

func TestContentExtractorsFinish(t *testing.T) {
	names := []string{"email", "bitcoin", "hashes", "base64", "cookie"}
	for _, name := range names {
		factory, _ := module.Get(name)
		mod := factory()
		_ = mod.Setup(nil)
		if err := mod.Finish(); err != nil {
			t.Errorf("module %q Finish error: %v", name, err)
		}
	}
}
