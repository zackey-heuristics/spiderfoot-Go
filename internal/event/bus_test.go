package event

import (
	"testing"
	"time"
)

func TestBusPublishesToTypeSubscriber(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch, unsubscribe := bus.Subscribe(DOMAIN_NAME, 1)
	defer unsubscribe()

	root, err := New(ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("New root returned error: %v", err)
	}

	evt, err := New(DOMAIN_NAME, "api.example.com", "sfp_dnsresolve", root)
	if err != nil {
		t.Fatalf("New child returned error: %v", err)
	}

	bus.Publish(evt)

	select {
	case got := <-ch:
		if got != evt {
			t.Fatal("received unexpected event pointer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBusPublishesToWildcardSubscriber(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch, unsubscribe := bus.Subscribe(Wildcard, 1)
	defer unsubscribe()

	root, err := New(ROOT, "example.com", "", nil)
	if err != nil {
		t.Fatalf("New root returned error: %v", err)
	}

	bus.Publish(root)

	select {
	case got := <-ch:
		if got != root {
			t.Fatal("received unexpected event pointer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for wildcard event")
	}
}

func TestBusUnsubscribeClosesChannel(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch, unsubscribe := bus.Subscribe(DOMAIN_NAME, 1)
	unsubscribe()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after unsubscribe")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for closed subscription")
	}
}

func TestBusPublishReturnsSubscriberCount(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	_, unsub1 := bus.Subscribe(DOMAIN_NAME, 10)
	defer unsub1()
	_, unsub2 := bus.Subscribe(Wildcard, 10)
	defer unsub2()

	root, _ := New(ROOT, "example.com", "", nil)
	evt, _ := New(DOMAIN_NAME, "test.com", "test", root)

	// DOMAIN_NAME subscriber + Wildcard subscriber = 2
	r := bus.Publish(evt)
	if r.Sent != 2 {
		t.Fatalf("expected 2 subscribers, got %d", r.Sent)
	}
}

func TestBusPublishNonBlocking(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch, unsub := bus.Subscribe(DOMAIN_NAME, 1)
	defer unsub()

	root, _ := New(ROOT, "example.com", "", nil)
	evt1, _ := New(DOMAIN_NAME, "a.com", "test", root)
	evt2, _ := New(DOMAIN_NAME, "b.com", "test", root)

	// Fill the buffer.
	r1 := bus.Publish(evt1)
	if r1.Sent != 1 {
		t.Fatalf("first publish: expected sent=1, got %d", r1.Sent)
	}

	// Buffer full — should drop, not deadlock.
	r2 := bus.Publish(evt2)
	if r2.Sent != 0 {
		t.Fatalf("second publish to full buffer: expected sent=0, got %d", r2.Sent)
	}
	if r2.Dropped != 1 {
		t.Fatalf("second publish: expected dropped=1, got %d", r2.Dropped)
	}

	// Drain and verify first event arrived.
	got := <-ch
	if got != evt1 {
		t.Fatal("expected evt1")
	}
}

func TestBusSubscribeMinimumBuffer(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch, unsub := bus.Subscribe(DOMAIN_NAME, 0)
	defer unsub()

	// Even with buffer=0 requested, the channel should have cap >= 1.
	if cap(ch) < 1 {
		t.Fatalf("expected cap >= 1, got %d", cap(ch))
	}
}

func TestBusCloseClosesSubscribers(t *testing.T) {
	t.Parallel()

	bus := NewBus()
	ch1, _ := bus.Subscribe(DOMAIN_NAME, 1)
	ch2, _ := bus.Subscribe(Wildcard, 1)

	bus.Close()

	for _, ch := range []<-chan *Event{ch1, ch2} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatal("channel should be closed after bus close")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for closed channel")
		}
	}
}
