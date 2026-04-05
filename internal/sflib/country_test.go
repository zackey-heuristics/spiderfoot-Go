package sflib

import "testing"

func TestCountryNameFromCode(t *testing.T) {
	if got := CountryNameFromCode("US"); got != "United States" {
		t.Fatalf("expected United States, got %s", got)
	}
	if got := CountryNameFromCode("JP"); got != "Japan" {
		t.Fatalf("expected Japan, got %s", got)
	}
	if got := CountryNameFromCode("XX"); got != "" {
		t.Fatalf("expected empty for XX, got %s", got)
	}
}

func TestCountryNameFromTLD(t *testing.T) {
	if got := CountryNameFromTLD("uk"); got != "United Kingdom" {
		t.Fatalf("expected United Kingdom, got %s", got)
	}
	if got := CountryNameFromTLD(".jp"); got != "Japan" {
		t.Fatalf("expected Japan, got %s", got)
	}
}

func TestCountryCodes(t *testing.T) {
	codes := CountryCodes()
	if len(codes) == 0 {
		t.Fatal("expected non-empty country codes")
	}
	if codes["US"] != "United States" {
		t.Fatal("expected US -> United States")
	}
}
