package modules

import (
	"context"
	"testing"
)

var threatFeeds2Names = []string{
	"talosintel", "alienvaultiprep", "greensnow",
	"vxvault", "stevenblack", "multiproxy",
}

func TestThreatFeeds2Registered(t *testing.T) {
	for _, n := range threatFeeds2Names {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestThreatFeeds2Meta(t *testing.T) {
	for _, n := range threatFeeds2Names {
		m := getModule(n)()
		meta := m.Meta()
		if meta.Name != n {
			t.Errorf("%s: wrong name %s", n, meta.Name)
		}
		if meta.Summary == "" {
			t.Errorf("%s: empty summary", n)
		}
	}
}

func TestThreatFeeds2Setup(t *testing.T) {
	for _, n := range threatFeeds2Names {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
		}
	}
}

func TestThreatFeeds2WatchedProduced(t *testing.T) {
	for _, n := range threatFeeds2Names {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

func TestThreatFeeds2HandleNilEvent(t *testing.T) {
	for _, n := range threatFeeds2Names {
		m := getModule(n)()
		_ = m.Setup(nil)
		results, err := m.HandleEvent(context.Background(), nil)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if results != nil {
			t.Errorf("%s: expected nil results for nil event", n)
		}
	}
}

func TestThreatFeeds2Finish(t *testing.T) {
	for _, n := range threatFeeds2Names {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

func TestParseAlienvaultIPRep(t *testing.T) {
	body := "# header\n1.2.3.4 #Malware Distribution\n5.6.7.8\nnot-an-ip #x\n"
	m := parseAlienvaultIPRep(body)
	if !m["1.2.3.4"] || !m["5.6.7.8"] || m["not-an-ip"] {
		t.Errorf("parseAlienvaultIPRep: %v", m)
	}
}

func TestParseVxVault(t *testing.T) {
	body := "# header\nhttp://Evil.Example.com/x.exe\nhttps://bad.example.org:8080/y\nnot a url\n"
	m := parseVxVault(body)
	if !m["evil.example.com"] || !m["bad.example.org"] {
		t.Errorf("parseVxVault: %v", m)
	}
}

func TestParseStevenBlack(t *testing.T) {
	body := "# header\n0.0.0.0 miner.example.com\n0.0.0.0 bad.example.org\n127.0.0.1 localhost\n"
	m := parseStevenBlack(body)
	if !m["miner.example.com"] || !m["bad.example.org"] {
		t.Errorf("parseStevenBlack: %v", m)
	}
	if m["localhost"] {
		t.Errorf("parseStevenBlack: should skip localhost")
	}
}

func TestParseMultiProxy(t *testing.T) {
	body := "# header\n1.2.3.4:8080\n5.6.7.8:3128\nbogus\n"
	m := parseMultiProxy(body)
	if !m["1.2.3.4"] || !m["5.6.7.8"] || m["bogus"] {
		t.Errorf("parseMultiProxy: %v", m)
	}
}
