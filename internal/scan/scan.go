package scan

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/config"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/db"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

// Scanner orchestrates a single SpiderFoot scan.
type Scanner struct {
	db          *db.DB
	bus         *event.Bus
	cfg         *config.Config
	scanID      string
	target      string
	moduleNames []string

	status        Status
	mu            sync.Mutex
	inFlight      atomic.Int64
	droppedEvents atomic.Int64
	scanErr       error // first fatal module error
	done          chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
}

// New creates a Scanner for the given scan parameters.
func New(database *db.DB, bus *event.Bus, cfg *config.Config, scanID, target string, moduleNames []string) *Scanner {
	return &Scanner{
		db:          database,
		bus:         bus,
		cfg:         cfg,
		scanID:      scanID,
		target:      target,
		moduleNames: moduleNames,
		status:      StatusCreated,
		done:        make(chan struct{}, 1),
	}
}

// decrInFlight decrements the in-flight counter and signals done when it reaches zero.
func (s *Scanner) decrInFlight() {
	if s.inFlight.Add(-1) <= 0 {
		select {
		case s.done <- struct{}{}:
		default:
		}
	}
}

// Start runs the scan. It blocks until all events are processed or the context is cancelled.
func (s *Scanner) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.ctx, s.cancel = ctx, cancel
	s.mu.Unlock()

	now := time.Now().UTC().UnixMilli()

	// Mark RUNNING in DB. If anything fails after this point, a deferred
	// cleanup ensures the scan does not remain stuck in RUNNING.
	s.setStatus(StatusRunning)
	if err := s.db.ScanUpdateStatus(s.scanID, string(StatusRunning)); err != nil {
		return fmt.Errorf("update scan status: %w", err)
	}
	if err := s.db.ScanUpdateTimes(s.scanID, now, 0); err != nil {
		return fmt.Errorf("update scan times: %w", err)
	}

	setupFailed := true
	defer func() {
		if setupFailed {
			s.setStatus(StatusErrorFailed)
			ended := time.Now().UTC().UnixMilli()
			_ = s.db.ScanUpdateStatus(s.scanID, string(StatusErrorFailed))
			_ = s.db.ScanUpdateTimes(s.scanID, now, ended)
		}
	}()

	rootEvt, err := event.New(event.ROOT, s.target, "SpiderFoot", nil)
	if err != nil {
		return fmt.Errorf("create root event: %w", err)
	}

	// Instantiate and set up modules.
	type runningModule struct {
		mod module.Module
		chs []<-chan *event.Event
	}
	var modules []runningModule

	for _, name := range s.moduleNames {
		factory, ok := module.Get(name)
		if !ok {
			slog.Warn("module not found, skipping", "module", name)
			continue
		}
		mod := factory()
		opts := s.cfg.ModuleOpts(name)
		if opts == nil {
			opts = make(map[string]any)
		}
		opts["__db"] = s.db
		opts["__scanid"] = s.scanID
		if err := mod.Setup(opts); err != nil {
			return fmt.Errorf("setup module %s: %w", name, err)
		}

		rm := runningModule{mod: mod}
		for _, typ := range mod.WatchedEvents() {
			ch, _ := s.bus.Subscribe(typ, 1000)
			rm.chs = append(rm.chs, ch)
		}
		modules = append(modules, rm)
	}

	// All modules initialized successfully; disable the setup-failure cleanup.
	setupFailed = false

	// Launch a goroutine per module subscription.
	var wg sync.WaitGroup
	for i := range modules {
		rm := &modules[i]
		for _, ch := range rm.chs {
			wg.Add(1)
			go func(mod module.Module, ch <-chan *event.Event) {
				defer wg.Done()
				for {
					select {
					case <-s.ctx.Done():
						// Drain remaining in-flight for events we won't process.
						for range ch {
							s.decrInFlight()
						}
						return
					case evt, ok := <-ch:
						if !ok {
							return
						}
						results, handleErr := mod.HandleEvent(s.ctx, evt)
						if handleErr != nil {
							// Context cancellation errors are expected during abort;
							// only treat non-cancellation errors as module failures.
							if s.ctx.Err() == nil {
								slog.Error("module handle event error", "module", mod.Meta().Name, "error", handleErr)
								s.mu.Lock()
								if s.scanErr == nil {
									s.scanErr = fmt.Errorf("module %s: %w", mod.Meta().Name, handleErr)
								}
								s.mu.Unlock()
								s.cancel()
							}
							s.decrInFlight()
							return
						}
						for _, r := range results {
							s.publishEvent(r)
						}
						s.decrInFlight()
					}
				}
			}(rm.mod, ch)
		}
	}

	// Publish the root event.
	s.publishEvent(rootEvt)

	// Publish a typed seed event so modules that watch specific types
	// (e.g. dns_resolve watching INTERNET_NAME/DOMAIN_NAME/IP_ADDRESS)
	// receive the initial target.
	seedType := classifyTarget(s.target)
	if seedType != event.ROOT {
		seedEvt, err := event.New(seedType, s.target, "SpiderFoot", rootEvt)
		if err == nil {
			s.publishEvent(seedEvt)
		}
	}

	// If nothing is in-flight, signal done immediately.
	if s.inFlight.Load() <= 0 {
		select {
		case s.done <- struct{}{}:
		default:
		}
	}

	// Wait for all in-flight events to be processed or context cancellation.
	select {
	case <-s.done:
	case <-s.ctx.Done():
	}

	// Determine final status. Module errors take priority over ctx cancellation
	// because we cancel the context ourselves on module failure.
	s.mu.Lock()
	hasErr := s.scanErr != nil
	s.mu.Unlock()

	var finalStatus Status
	switch {
	case hasErr:
		finalStatus = StatusErrorFailed
	case s.droppedEvents.Load() > 0:
		finalStatus = StatusErrorFailed
		s.mu.Lock()
		if s.scanErr == nil {
			s.scanErr = fmt.Errorf("scan incomplete: %d event deliveries dropped due to full buffers", s.droppedEvents.Load())
		}
		s.mu.Unlock()
	default:
		select {
		case <-s.ctx.Done():
			// Only treat as abort if no internal error caused the cancellation.
			finalStatus = StatusAborted
		default:
			finalStatus = StatusFinished
		}
	}

	// Close bus so module goroutines drain and exit.
	s.bus.Close()

	// Wait for module goroutines to exit. With context cancellation propagated
	// to HandleEvent, modules should exit promptly. Use a safety timeout to
	// avoid blocking forever if a module ignores cancellation.
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		slog.Warn("some module goroutines did not exit within timeout")
	}

	// Finish all modules.
	for i := range modules {
		if err := modules[i].mod.Finish(); err != nil {
			slog.Error("module finish error", "module", modules[i].mod.Meta().Name, "error", err)
		}
	}

	s.setStatus(finalStatus)
	ended := time.Now().UTC().UnixMilli()
	_ = s.db.ScanUpdateStatus(s.scanID, string(finalStatus))
	_ = s.db.ScanUpdateTimes(s.scanID, now, ended)

	s.mu.Lock()
	scanErr := s.scanErr
	s.mu.Unlock()

	if scanErr != nil {
		return scanErr
	}
	if finalStatus == StatusAborted {
		return ErrScanAborted
	}
	return nil
}

// Abort requests scan cancellation.
func (s *Scanner) Abort() {
	s.setStatus(StatusAbortRequested)
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// GetStatus returns the current scan status.
func (s *Scanner) GetStatus() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Scanner) setStatus(st Status) {
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
}

// publishEvent publishes an event to the bus with correct inFlight accounting.
// If any subscriber drops the event, the drop is recorded for scan failure.
func (s *Scanner) publishEvent(evt *event.Event) {
	s.inFlight.Add(1)
	r := s.bus.Publish(evt)
	if r.Sent > 1 {
		s.inFlight.Add(int64(r.Sent - 1))
	} else if r.Sent == 0 {
		s.decrInFlight()
	}
	if r.Dropped > 0 {
		s.droppedEvents.Add(int64(r.Dropped))
	}
}

// classifyTarget determines the event type for the scan target string.
func classifyTarget(target string) event.Type {
	// Check for IP address.
	if net.ParseIP(target) != nil {
		return event.IP_ADDRESS
	}
	// Otherwise treat as a domain/hostname.
	return event.INTERNET_NAME
}
