package modules

import (
	"context"
	"testing"
)

var threatFeeds2Names = []string{
	"talosintel", "alienvaultiprep", "greensnow", "stevenblack",
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

func TestParseStevenBlack(t *testing.T) {
	body := "# header\n" +
		"0.0.0.0 miner.example.com\n" +
		"0.0.0.0 bad.example.org\n" +
		"0.0.0.0 a.example b.example c.example # inline comment\n" +
		"127.0.0.1 localhost\n"
	m := parseStevenBlack(body)
	for _, want := range []string{"miner.example.com", "bad.example.org", "a.example", "b.example", "c.example"} {
		if !m[want] {
			t.Errorf("parseStevenBlack: missing %q in %v", want, m)
		}
	}
	if m["localhost"] {
		t.Errorf("parseStevenBlack: should skip localhost")
	}
}
