package sflib

import "testing"

func TestExtractEmails(t *testing.T) {
	data := "Contact us at admin@example.com or support@test.org for help."
	emails := ExtractEmails(data)
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails, got %d: %v", len(emails), emails)
	}
}

func TestExtractEmailsDedup(t *testing.T) {
	data := "admin@example.com and admin@example.com"
	emails := ExtractEmails(data)
	if len(emails) != 1 {
		t.Fatalf("expected 1 email after dedup, got %d", len(emails))
	}
}

func TestExtractURLs(t *testing.T) {
	data := `Visit https://example.com/path and http://test.org for more.`
	urls := ExtractURLs(data)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d: %v", len(urls), urls)
	}
}

func TestExtractHashes(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	data := md5 + " " + sha1 + " " + sha256
	hashes := ExtractHashes(data)
	if len(hashes) != 3 {
		t.Fatalf("expected 3 hashes, got %d", len(hashes))
	}
}

func TestExtractBitcoinAddresses(t *testing.T) {
	data := "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	addrs := ExtractBitcoinAddresses(data)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 bitcoin address, got %d", len(addrs))
	}
}

func TestExtractEthereumAddresses(t *testing.T) {
	data := "ETH: 0x32Be343B94f860124dC4fEe278FDCBD38C102D88"
	addrs := ExtractEthereumAddresses(data)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 ethereum address, got %d", len(addrs))
	}
}

func TestExtractIBANs(t *testing.T) {
	data := "IBAN: DE89370400440532013000"
	ibans := ExtractIBANs(data)
	if len(ibans) != 1 {
		t.Fatalf("expected 1 IBAN, got %d", len(ibans))
	}
}

func TestExtractCreditCards(t *testing.T) {
	data := "Card: 4111111111111111"
	cards := ExtractCreditCards(data)
	if len(cards) != 1 {
		t.Fatalf("expected 1 credit card, got %d", len(cards))
	}
}

func TestExtractEmpty(t *testing.T) {
	if ExtractEmails("") != nil {
		t.Fatal("expected nil for empty input")
	}
}
