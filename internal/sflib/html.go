package sflib

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// ExtractedLink represents a link found in HTML content.
type ExtractedLink struct {
	// URL is the resolved absolute URL.
	URL string
	// Text is the anchor text, if any.
	Text string
}

// ExtractLinksFromHTML parses HTML and returns all href links as absolute URLs.
func ExtractLinksFromHTML(baseURL, body string) []ExtractedLink {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	var links []ExtractedLink
	seen := make(map[string]bool)

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		t := tokenizer.Token()
		if t.Data != "a" && t.Data != "link" && t.Data != "script" && t.Data != "img" {
			continue
		}

		for _, attr := range t.Attr {
			if attr.Key != "href" && attr.Key != "src" {
				continue
			}
			resolved := resolveURL(base, attr.Val)
			if resolved == "" || seen[resolved] {
				continue
			}
			seen[resolved] = true

			text := ""
			if t.Data == "a" {
				text = extractAnchorText(tokenizer)
			}
			links = append(links, ExtractedLink{URL: resolved, Text: text})
		}
	}
	return links
}

// ExtractURLsFromRobotsTxt parses a robots.txt body and returns all
// Disallow and Allow paths as absolute URLs.
func ExtractURLsFromRobotsTxt(baseURL, data string) []string {
	var paths []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") || strings.HasPrefix(lower, "allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if path != "" && path != "/" {
					u := strings.TrimSuffix(baseURL, "/") + path
					paths = append(paths, u)
				}
			}
		}
	}
	return paths
}

func resolveURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func extractAnchorText(z *html.Tokenizer) string {
	for {
		tt := z.Next()
		switch tt {
		case html.TextToken:
			return strings.TrimSpace(z.Token().Data)
		case html.EndTagToken, html.ErrorToken:
			return ""
		}
	}
}
