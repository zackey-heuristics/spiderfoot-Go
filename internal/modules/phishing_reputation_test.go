package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

var phishingNames = []string{
	"phishtank", "openphish", "emergingthreats", "threatcrowd", "phishstats",
}

func TestPhishingRegistered(t *testing.T) {
	for _, n := range phishingNames {
		if getModule(n) == nil {
			t.Errorf("%s not registered", n)
		}
	}
}

func TestPhishingMeta(t *testing.T) {
	for _, n := range phishingNames {
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

func TestPhishingSetup(t *testing.T) {
	for _, n := range phishingNames {
		m := getModule(n)()
		if err := m.Setup(nil); err != nil {
			t.Errorf("%s: setup error: %v", n, err)
		}
	}
}

func TestPhishingWatchedProduced(t *testing.T) {
	for _, n := range phishingNames {
		m := getModule(n)()
		if len(m.WatchedEvents()) == 0 {
			t.Errorf("%s: no watched events", n)
		}
		if len(m.ProducedEvents()) == 0 {
			t.Errorf("%s: no produced events", n)
		}
	}
}

func TestPhishingHandleNilEvent(t *testing.T) {
	for _, n := range phishingNames {
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

func TestPhishingFinish(t *testing.T) {
	for _, n := range phishingNames {
		m := getModule(n)()
		_ = m.Setup(nil)
		if err := m.Finish(); err != nil {
			t.Errorf("%s: finish error: %v", n, err)
		}
	}
}

func TestParsePhishtank(t *testing.T) {
	csv := "phish_id,url,phish_detail_url\n1,http://evil.example.com/login,http://x\n2,https://Bad.Example.Org/a,http://y\n"
	m := parsePhishtank(csv)
	if !m["evil.example.com"] || !m["bad.example.org"] {
		t.Errorf("parsePhishtank missed entries: %v", m)
	}
}

func TestParseOpenphish(t *testing.T) {
	body := "http://a.example.com/x\nhttps://B.Example.org/y\n\n"
	m := parseOpenphish(body)
	if !m["a.example.com"] || !m["b.example.org"] {
		t.Errorf("parseOpenphish missed entries: %v", m)
	}
}

func TestFetchOnceRetriesOnFailure(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var f fetchOnce
	if _, err := f.get(context.Background(), srv.URL); err == nil {
		t.Fatal("first call: expected error, got nil")
	}
	body, err := f.get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("second call: unexpected error %v", err)
	}
	if body != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 server calls, got %d", got)
	}
}

// TestHostFeedConcurrentDedup verifies that two concurrent goroutines
// handling the same indicator only result in ONE feed fetch and ONE
// emitted blacklist event — i.e. dedup is atomic at HandleEvent entry.
func TestHostFeedConcurrentDedup(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		// Slow response to widen the race window.
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("phish_id,url,phish_detail_url\n1,http://evil.example.com/a,x\n"))
	}))
	defer srv.Close()

	m := &hostFeed{
		name:    "phishtank",
		summary: "test",
		url:     srv.URL,
		parser:  parsePhishtank,
	}
	root, _ := event.New(event.ROOT, "example.com", "", nil)
	evt, _ := event.New(event.INTERNET_NAME, "evil.example.com", "test", root)

	const N = 10
	type result struct {
		out []*event.Event
		err error
	}
	results := make(chan result, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := m.HandleEvent(context.Background(), evt)
			results <- result{out, err}
		}()
	}
	wg.Wait()
	close(results)

	emitted := 0
	for r := range results {
		if r.err != nil {
			t.Errorf("unexpected error: %v", r.err)
		}
		for _, e := range r.out {
			if e.Type == event.BLACKLISTED_INTERNET_NAME {
				emitted++
			}
		}
	}
	if emitted != 1 {
		t.Errorf("expected exactly 1 BLACKLISTED_INTERNET_NAME emission, got %d", emitted)
	}
	// Note: feed itself is cached by fetchOnce so a single fetch is
	// sufficient. The point is that the work is not duplicated under
	// concurrency.
	if got := atomic.LoadInt32(&calls); got > 1 {
		t.Errorf("expected at most 1 server call, got %d", got)
	}
}

// TestHostFeedRetryAfterTransientFailure ensures that a transient feed
// load failure on the first event does NOT permanently suppress the
// module for later events with the same indicator.
func TestHostFeedRetryAfterTransientFailure(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("phish_id,url,phish_detail_url\n1,http://evil.example.com/a,x\n"))
	}))
	defer srv.Close()

	m := &hostFeed{
		name:    "phishtank",
		summary: "test",
		url:     srv.URL,
		parser:  parsePhishtank,
	}
	root, _ := event.New(event.ROOT, "example.com", "", nil)
	evt, _ := event.New(event.INTERNET_NAME, "evil.example.com", "test", root)

	// First call: feed fetch fails transiently → no results, no mark-done.
	out, err := m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("first call: expected no events, got %d", len(out))
	}

	// Second call: feed fetch succeeds → indicator must still be checked
	// and match.
	out, err = m.HandleEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	var sawBlacklisted bool
	for _, e := range out {
		if e.Type == event.BLACKLISTED_INTERNET_NAME {
			sawBlacklisted = true
		}
	}
	if !sawBlacklisted {
		t.Errorf("second call: expected BLACKLISTED_INTERNET_NAME event, got %d events", len(out))
	}
}

func TestFetchOnceCachesSuccess(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte("hi"))
	}))
	defer srv.Close()

	var f fetchOnce
	for i := 0; i < 3; i++ {
		body, err := f.get(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("call %d: unexpected error %v", i, err)
		}
		if body != "hi" {
			t.Errorf("call %d: body=%q want %q", i, body, "hi")
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 server call, got %d", got)
	}
}

func TestParseIPList(t *testing.T) {
	body := "# header\n1.2.3.4\n5.6.7.8\nnot-an-ip\n"
	m := parseIPList(body)
	if !m["1.2.3.4"] || !m["5.6.7.8"] || m["not-an-ip"] {
		t.Errorf("parseIPList: %v", m)
	}
}
