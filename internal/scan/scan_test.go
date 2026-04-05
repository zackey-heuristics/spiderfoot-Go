package scan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// dummyModule watches ROOT and produces nothing.
type dummyModule struct {
	handled []*event.Event
	mu      sync.Mutex
}

func (d *dummyModule) Meta() module.Meta {
	return module.Meta{Name: "dummy", Summary: "test module"}
}
func (d *dummyModule) Setup(_ map[string]any) error { return nil }
func (d *dummyModule) WatchedEvents() []event.Type  { return []event.Type{event.ROOT} }
func (d *dummyModule) ProducedEvents() []event.Type  { return nil }
func (d *dummyModule) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	d.mu.Lock()
	d.handled = append(d.handled, evt)
	d.mu.Unlock()
	return nil, nil
}
func (d *dummyModule) Finish() error { return nil }

// Note: These tests call module.Reset() to isolate the global registry.
// They must NOT use t.Parallel() as they mutate shared global state.

func TestStatusConstants(t *testing.T) {
	if StatusCreated != "CREATED" {
		t.Fatal("unexpected CREATED value")
	}
	if StatusRunning != "RUNNING" {
		t.Fatal("unexpected RUNNING value")
	}
	if StatusFinished != "FINISHED" {
		t.Fatal("unexpected FINISHED value")
	}
}

func TestScannerNew(t *testing.T) {
	s := New(nil, nil, config.Defaults(), "id1", "example.com", []string{"mod1"})
	if s.scanID != "id1" {
		t.Fatal("scanID mismatch")
	}
	if s.GetStatus() != StatusCreated {
		t.Fatal("initial status should be CREATED")
	}
}

func TestScannerStartFinish(t *testing.T) {
	module.Reset()
	module.Register("dummy", func() module.Module { return &dummyModule{} })

	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	scanID := "scan-test-1"
	if err := database.ScanCreate(scanID, "test", "example.com"); err != nil {
		t.Fatal(err)
	}

	bus := event.NewBus()
	cfg := config.Defaults()
	s := New(database, bus, cfg, scanID, "example.com", []string{"dummy"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	if s.GetStatus() != StatusFinished {
		t.Fatalf("expected FINISHED, got %s", s.GetStatus())
	}

	scan, err := database.ScanGet(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Status != string(StatusFinished) {
		t.Fatalf("DB status expected FINISHED, got %s", scan.Status)
	}
}

func TestScannerAbort(t *testing.T) {
	module.Reset()

	// blockingModule blocks in HandleEvent until context is done.
	module.Register("blocker", func() module.Module { return &blockingModule{} })

	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	scanID := "scan-abort-1"
	if err := database.ScanCreate(scanID, "test", "example.com"); err != nil {
		t.Fatal(err)
	}

	bus := event.NewBus()
	cfg := config.Defaults()
	s := New(database, bus, cfg, scanID, "example.com", []string{"blocker"})

	done := make(chan error, 1)
	go func() {
		done <- s.Start(context.Background())
	}()

	// Give the scan time to start.
	time.Sleep(200 * time.Millisecond)
	s.Abort()

	select {
	case err := <-done:
		if !errors.Is(err, ErrScanAborted) {
			t.Fatalf("expected ErrScanAborted, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not finish after abort")
	}

	st := s.GetStatus()
	if st != StatusAborted {
		t.Fatalf("expected ABORTED, got %s", st)
	}
}

// blockingModule blocks in HandleEvent until context is cancelled (via bus close).
type blockingModule struct {
	ch chan struct{}
}

func (b *blockingModule) Meta() module.Meta {
	return module.Meta{Name: "blocker", Summary: "blocks in HandleEvent"}
}
func (b *blockingModule) Setup(_ map[string]any) error {
	b.ch = make(chan struct{})
	return nil
}
func (b *blockingModule) WatchedEvents() []event.Type  { return []event.Type{event.ROOT} }
func (b *blockingModule) ProducedEvents() []event.Type  { return nil }
func (b *blockingModule) HandleEvent(ctx context.Context, _ *event.Event) ([]*event.Event, error) {
	<-ctx.Done() // block until context is cancelled
	return nil, ctx.Err()
}
func (b *blockingModule) Finish() error { return nil }
