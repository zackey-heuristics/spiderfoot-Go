package modules

import (
	"context"
	"testing"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

var socialNames = []string{
	"social", "accounts", "github", "twitter",
	"flickr", "keybase", "gravatar", "slideshare",
}

func TestSocialRegistered(t *testing.T) {
	for _, n := range socialNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestSocialMeta(t *testing.T) {
	for _, n := range socialNames {
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

func TestSocialSetup(t *testing.T) {
	for _, n := range socialNames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
		}
	}
}

func TestSocialWatchedProduced(t *testing.T) {
	for _, n := range socialNames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

func TestSocialHandleNilEvent(t *testing.T) {
	for _, n := range socialNames {
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

func TestSocialFinish(t *testing.T) {
	for _, n := range socialNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

// TestSocialExtractor verifies the regex-based social module emits both
// SOCIAL_MEDIA and USERNAME events for a known LinkedIn URL.
func TestSocialExtractor(t *testing.T) {
	m := getModule("social")()
	_ = m.Setup(nil)
	root, _ := event.New(event.ROOT, "example.com", "", nil)
	evt, err := event.New(event.LINKED_URL_EXTERNAL, "https://www.linkedin.com/in/janedoe/", "test", root)
	if err != nil {
		t.Fatalf("event.New: %v", err)
	}
	out, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var sawSocial, sawUser bool
	for _, e := range out {
		if e.Type == event.SOCIAL_MEDIA {
			sawSocial = true
		}
		if e.Type == event.USERNAME && e.Data == "janedoe" {
			sawUser = true
		}
	}
	if !sawSocial || !sawUser {
		t.Errorf("expected SOCIAL_MEDIA + USERNAME events, got %d", len(out))
	}
}

func TestExtractGithubUsername(t *testing.T) {
	cases := map[string]string{
		"GitHub: https://github.com/octocat":  "octocat",
		"GitHub: https://github.com/octocat/": "octocat",
		"octocat":                             "octocat",
	}
	for in, want := range cases {
		if got := extractGithubUsername(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}
