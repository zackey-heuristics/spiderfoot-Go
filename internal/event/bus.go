package event

import (
	"log/slog"
	"sync"
)

// Bus delivers events to subscribers by event type.
type Bus struct {
	mu     sync.RWMutex
	closed bool
	nextID uint64
	subs   map[Type]map[uint64]chan *Event
}

// NewBus constructs an empty event bus.
func NewBus() *Bus {
	return &Bus{
		subs: make(map[Type]map[uint64]chan *Event),
	}
}

// Subscribe registers a buffered subscription for a specific type or Wildcard.
// The minimum buffer size is 1 to prevent unbuffered channels.
func (b *Bus) Subscribe(typ Type, buffer int) (<-chan *Event, func()) {
	if buffer < 1 {
		buffer = 1
	}

	ch := make(chan *Event, buffer)

	b.mu.Lock()
	if b.closed {
		close(ch)
		b.mu.Unlock()
		return ch, func() {}
	}

	b.nextID++
	id := b.nextID
	if b.subs[typ] == nil {
		b.subs[typ] = make(map[uint64]chan *Event)
	}
	b.subs[typ][id] = ch
	b.mu.Unlock()

	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			b.mu.Lock()
			if subs, ok := b.subs[typ]; ok {
				if _, exists := subs[id]; exists {
					delete(subs, id)
					if len(subs) == 0 {
						delete(b.subs, typ)
					}
					close(ch)
				}
			}
			b.mu.Unlock()
		})
	}

	return ch, unsubscribe
}

// PublishResult holds the outcome of a Publish call.
type PublishResult struct {
	// Sent is the number of subscribers that received the event.
	Sent int
	// Dropped is the number of subscribers whose buffer was full.
	Dropped int
}

// Publish sends an event to exact-type and Wildcard subscribers using
// non-blocking sends. Events are dropped (with a warning) if a subscriber
// buffer is full, preventing deadlocks.
func (b *Bus) Publish(evt *Event) PublishResult {
	if evt == nil {
		return PublishResult{}
	}

	// Snapshot subscribers under lock, then release before sending.
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return PublishResult{}
	}

	var targets []chan *Event
	for _, ch := range b.subs[evt.Type] {
		targets = append(targets, ch)
	}
	for _, ch := range b.subs[Wildcard] {
		targets = append(targets, ch)
	}
	b.mu.RUnlock()

	var r PublishResult
	for _, ch := range targets {
		// Recover from send-on-closed-channel if Close/unsubscribe races
		// with this snapshot-based iteration.
		func() {
			defer func() { recover() }()
			select {
			case ch <- evt:
				r.Sent++
			default:
				r.Dropped++
				slog.Warn("event dropped: subscriber buffer full", "type", string(evt.Type))
			}
		}()
	}
	return r
}

// Close closes the bus and all active subscriptions.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true
	for typ, subs := range b.subs {
		for id, ch := range subs {
			close(ch)
			delete(subs, id)
		}
		delete(b.subs, typ)
	}
}
