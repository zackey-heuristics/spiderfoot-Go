package sflib

import "testing"

func TestValidIP(t *testing.T) {
	if !ValidIP("1.2.3.4") {
		t.Fatal("expected true for 1.2.3.4")
	}
	if ValidIP("::1") {
		t.Fatal("expected false for IPv6")
	}
	if ValidIP("not-an-ip") {
		t.Fatal("expected false for invalid")
	}
}

func TestValidIP6(t *testing.T) {
	if !ValidIP6("::1") {
		t.Fatal("expected true for ::1")
	}
	if ValidIP6("1.2.3.4") {
		t.Fatal("expected false for IPv4")
	}
}

func TestValidIPNetwork(t *testing.T) {
	if !ValidIPNetwork("10.0.0.0/24") {
		t.Fatal("expected true for 10.0.0.0/24")
	}
	if ValidIPNetwork("not-a-cidr") {
		t.Fatal("expected false for invalid")
	}
}

func TestIsPublicIP(t *testing.T) {
	if !IsPublicIP("8.8.8.8") {
		t.Fatal("expected true for 8.8.8.8")
	}
	if IsPublicIP("192.168.1.1") {
		t.Fatal("expected false for private")
	}
	if IsPublicIP("127.0.0.1") {
		t.Fatal("expected false for loopback")
	}
}

func TestHostDomain(t *testing.T) {
	tests := map[string]string{
		"mail.example.com":  "example.com",
		"example.com":       "example.com",
		"a.b.example.co.uk": "co.uk", // simplified — no PSL
	}
	for input, want := range tests {
		got := HostDomain(input)
		if got != want {
			t.Errorf("HostDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsDomain(t *testing.T) {
	if !IsDomain("example.com") {
		t.Fatal("expected true")
	}
	if IsDomain("1.2.3.4") {
		t.Fatal("expected false for IP")
	}
	if IsDomain("notatld") {
		t.Fatal("expected false for no dot")
	}
}

func TestValidHost(t *testing.T) {
	if !ValidHost("example.com") {
		t.Fatal("expected true")
	}
	if ValidHost("") {
		t.Fatal("expected false for empty")
	}
}

func TestExpandCIDR(t *testing.T) {
	ips := ExpandCIDR("10.0.0.0/30", 100)
	if len(ips) != 2 {
		t.Fatalf("expected 2 hosts in /30, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Fatalf("unexpected IPs: %v", ips)
	}

	// Too large
	if ExpandCIDR("10.0.0.0/8", 10) != nil {
		t.Fatal("expected nil for oversized CIDR")
	}
}
