package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

var searchAPINames = []string{
	"googlesearch", "bingsearch", "duckduckgo",
	"sublist3r", "stackoverflow", "searchcode",
}

func TestSearchAPIsRegistered(t *testing.T) {
	for _, n := range searchAPINames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestSearchAPIsMeta(t *testing.T) {
	for _, n := range searchAPINames {
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

func TestSearchAPIsSetup(t *testing.T) {
	for _, n := range searchAPINames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
		}
	}
}

func TestSearchAPIsWatchedProduced(t *testing.T) {
	for _, n := range searchAPINames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

func TestSearchAPIsHandleNilEvent(t *testing.T) {
	for _, n := range searchAPINames {
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

func TestSearchAPIsFinish(t *testing.T) {
	for _, n := range searchAPINames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

func TestHostMatchesTarget(t *testing.T) {
	cases := []struct {
		host, target string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"EXAMPLE.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"example.com.evil", "example.com", false},
		{"", "example.com", false},
		{"example.com", "", false},
	}
	for _, c := range cases {
		if got := hostMatchesTarget(c.host, c.target); got != c.want {
			t.Errorf("hostMatchesTarget(%q,%q)=%v want %v", c.host, c.target, got, c.want)
		}
	}
}

func TestURLInTargetScope(t *testing.T) {
	cases := []struct {
		raw, target string
		want        bool
	}{
		{"https://api.example.com/x", "example.com", true},
		{"https://example.com/", "example.com", true},
		{"https://evil.tld/?next=example.com", "example.com", false},
		{"https://notexample.com/", "example.com", false},
		{"not a url", "example.com", false},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := urlInTargetScope(c.raw, c.target); got != c.want {
			t.Errorf("urlInTargetScope(%q,%q)=%v want %v", c.raw, c.target, got, c.want)
		}
	}
}

// TestGoogleBingNoKeyNoOp ensures both engines no-op when no API key is set.
func TestGoogleBingNoKeyNoOp(t *testing.T) {
	for _, n := range []string{"googlesearch", "bingsearch"} {
		m := getModule(n)()
		_ = m.Setup(nil)
		evt, _ := event.New(event.INTERNET_NAME, "example.com", "test", nil)
		out, err := m.HandleEvent(context.Background(), evt)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", n, err)
		}
		if len(out) != 0 {
			t.Errorf("%s: expected no events without API key, got %d", n, len(out))
		}
	}
}
