package sflib

import "testing"

func TestExtractLinksFromHTML(t *testing.T) {
	body := `<html><body>
		<a href="/about">About</a>
		<a href="https://external.com/page">External</a>
		<a href="relative.html">Relative</a>
		<a href="#anchor">Anchor</a>
		<a href="javascript:void(0)">JS</a>
	</body></html>`

	links := ExtractLinksFromHTML("https://example.com/index.html", body)
	if len(links) != 3 {
		t.Fatalf("expected 3 links, got %d: %v", len(links), links)
	}

	// Check absolute resolution.
	found := false
	for _, l := range links {
		if l.URL == "https://example.com/about" {
			found = true
			if l.Text != "About" {
				t.Fatalf("expected text 'About', got %q", l.Text)
			}
		}
	}
	if !found {
		t.Fatal("expected /about to resolve to https://example.com/about")
	}
}

func TestExtractLinksDedup(t *testing.T) {
	body := `<a href="/page">A</a><a href="/page">B</a>`
	links := ExtractLinksFromHTML("https://example.com", body)
	if len(links) != 1 {
		t.Fatalf("expected 1 link after dedup, got %d", len(links))
	}
}

func TestExtractURLsFromRobotsTxt(t *testing.T) {
	robots := `User-agent: *
Disallow: /admin
Disallow: /private/
Allow: /public`

	urls := ExtractURLsFromRobotsTxt("https://example.com", robots)
	if len(urls) != 3 {
		t.Fatalf("expected 3 paths, got %d: %v", len(urls), urls)
	}
}
