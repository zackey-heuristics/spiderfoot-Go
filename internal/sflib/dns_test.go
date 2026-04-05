package sflib

import "testing"

func TestReverseIP(t *testing.T) {
	rev, err := reverseIP("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if rev != "4.3.2.1" {
		t.Fatalf("expected 4.3.2.1, got %s", rev)
	}
}

func TestReverseIPInvalid(t *testing.T) {
	_, err := reverseIP("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestReverseIPv6(t *testing.T) {
	_, err := reverseIP("::1")
	if err == nil {
		t.Fatal("expected error for IPv6")
	}
}
