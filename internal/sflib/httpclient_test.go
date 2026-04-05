package sflib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientFetchURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "hello")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientOpts{})
	resp, err := c.FetchURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Body != "OK" {
		t.Fatalf("expected OK, got %q", resp.Body)
	}
	if resp.Headers.Get("X-Test") != "hello" {
		t.Fatal("expected X-Test header")
	}
}

func TestHTTPClientUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientOpts{UserAgent: "SpiderFoot-Test/1.0"})
	_, _ = c.FetchURL(context.Background(), srv.URL)
	if gotUA != "SpiderFoot-Test/1.0" {
		t.Fatalf("expected custom UA, got %q", gotUA)
	}
}

func TestHTTPClientMaxBodySize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < 1000; i++ {
			_, _ = w.Write([]byte("A"))
		}
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientOpts{MaxBodySize: 100})
	resp, err := c.FetchURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) > 100 {
		t.Fatalf("body exceeded max size: %d", len(resp.Body))
	}
}
