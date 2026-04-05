package sflib

import (
	"regexp"
	"strings"
)

// Compiled regex patterns for data extraction.
var (
	emailRe      = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	urlRe        = regexp.MustCompile(`https?://[^\s<>"'\` + "`" + `\)]+`)
	md5Re        = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	sha1Re       = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	sha256Re     = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	ibanRe       = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
	creditCardRe = regexp.MustCompile(`\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b`)
	phoneRe      = regexp.MustCompile(`(?:\+\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}`)
	bitcoinRe    = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)
	ethereumRe   = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	pgpKeyIDRe   = regexp.MustCompile(`\b0x[A-Fa-f0-9]{8,16}\b`)
)

// ExtractEmails returns all email addresses found in data.
func ExtractEmails(data string) []string {
	return dedup(emailRe.FindAllString(data, -1))
}

// ExtractURLs returns all HTTP(S) URLs found in data.
func ExtractURLs(data string) []string {
	return dedup(urlRe.FindAllString(data, -1))
}

// HashMatch represents a detected hash with its type.
type HashMatch struct {
	// Type is the hash algorithm (md5, sha1, sha256).
	Type string
	// Value is the hash string.
	Value string
}

// ExtractHashes returns all MD5, SHA1, and SHA256 hashes found in data.
func ExtractHashes(data string) []HashMatch {
	var results []HashMatch
	seen := make(map[string]bool)

	for _, h := range sha256Re.FindAllString(data, -1) {
		h = strings.ToLower(h)
		if !seen[h] {
			results = append(results, HashMatch{Type: "sha256", Value: h})
			seen[h] = true
		}
	}
	for _, h := range sha1Re.FindAllString(data, -1) {
		h = strings.ToLower(h)
		if !seen[h] {
			results = append(results, HashMatch{Type: "sha1", Value: h})
			seen[h] = true
		}
	}
	for _, h := range md5Re.FindAllString(data, -1) {
		h = strings.ToLower(h)
		if !seen[h] {
			results = append(results, HashMatch{Type: "md5", Value: h})
			seen[h] = true
		}
	}
	return results
}

// ExtractIBANs returns all IBAN numbers found in data.
func ExtractIBANs(data string) []string {
	return dedup(ibanRe.FindAllString(data, -1))
}

// ExtractCreditCards returns all credit card numbers found in data.
func ExtractCreditCards(data string) []string {
	return dedup(creditCardRe.FindAllString(data, -1))
}

// ExtractPhoneNumbers returns all phone numbers found in data.
func ExtractPhoneNumbers(data string) []string {
	return dedup(phoneRe.FindAllString(data, -1))
}

// ExtractBitcoinAddresses returns all Bitcoin addresses found in data.
func ExtractBitcoinAddresses(data string) []string {
	return dedup(bitcoinRe.FindAllString(data, -1))
}

// ExtractEthereumAddresses returns all Ethereum addresses found in data.
func ExtractEthereumAddresses(data string) []string {
	return dedup(ethereumRe.FindAllString(data, -1))
}

// ExtractPGPKeyIDs returns all PGP key IDs found in data.
func ExtractPGPKeyIDs(data string) []string {
	return dedup(pgpKeyIDRe.FindAllString(data, -1))
}

func dedup(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
