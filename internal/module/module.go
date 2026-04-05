// Package module defines the SpiderFoot-Go module interface and registry.
package module

import (
	"context"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
)

// Module defines the interface that all OSINT modules must implement.
type Module interface {
	// Meta returns static metadata describing the module.
	Meta() Meta
	// Setup applies runtime options before the module handles events.
	Setup(opts map[string]any) error
	// WatchedEvents returns the event types the module subscribes to.
	WatchedEvents() []event.Type
	// ProducedEvents returns the event types the module may emit.
	ProducedEvents() []event.Type
	// HandleEvent processes one event and returns any emitted events.
	// Implementations should respect ctx cancellation for timely abort.
	HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error)
	// Finish releases module resources after scanning completes.
	Finish() error
}
