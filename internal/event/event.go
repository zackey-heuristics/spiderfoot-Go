package event

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Event represents a SpiderFoot event and its related metadata.
type Event struct {
	// Generated is the event creation timestamp.
	Generated time.Time
	// Type is the event type identifier.
	Type Type
	// Data is the event payload.
	Data string
	// Module is the module that emitted the event.
	Module string
	// Confidence is the confidence score from 0 to 100.
	Confidence int
	// Visibility is the visibility score from 0 to 100.
	Visibility int
	// Risk is the risk score from 0 to 100.
	Risk int
	// SourceEvent is the parent event that triggered this event.
	SourceEvent *Event
	// ModuleDataSource records the upstream data source used by the module.
	ModuleDataSource string
	// ActualSource records the original source material for the event.
	ActualSource string

	id string
}

// New constructs an Event using SpiderFoot-compatible validation rules.
func New(typ Type, data, module string, source *Event) (*Event, error) {
	if typ == "" {
		return nil, errors.New("event type is empty")
	}

	if data == "" {
		return nil, errors.New("event data is empty")
	}

	if typ != ROOT && module == "" {
		return nil, errors.New("module is empty")
	}

	if typ != ROOT && source == nil {
		return nil, errors.New("source event is required for non-root events")
	}

	now := time.Now().UTC()
	sourceHash := string(ROOT)
	if source != nil {
		sourceHash = source.Hash()
	}
	evt := &Event{
		Generated:  now,
		Type:       typ,
		Data:       data,
		Module:     module,
		Confidence: 100,
		Visibility: 100,
		Risk:       0,
		// Deterministic ID from semantic fields enables deduplication.
		id: fmt.Sprintf("%s:%s:%s:%s", typ, data, module, sourceHash),
	}

	if typ != ROOT {
		evt.SourceEvent = source
	}

	return evt, nil
}

// Hash returns a deterministic, content-stable event hash.
// The hash is derived from the event's semantic fields (type, data, module,
// and source event hash), enabling deduplication of logically identical events.
// ROOT events always return "ROOT".
func (e *Event) Hash() string {
	if e == nil {
		return ""
	}

	if e.Type == ROOT {
		return string(ROOT)
	}

	sum := sha256.Sum256([]byte(e.id))
	return hex.EncodeToString(sum[:])
}

// SourceEventHash returns the parent event hash, or ROOT when no parent exists.
func (e *Event) SourceEventHash() string {
	if e == nil || e.Type == ROOT || e.SourceEvent == nil {
		return string(ROOT)
	}

	return e.SourceEvent.Hash()
}

// AsMap renders the event using the Python SpiderFoot event dictionary shape.
func (e *Event) AsMap() map[string]any {
	source := ""
	if e != nil && e.SourceEvent != nil {
		source = e.SourceEvent.Data
	}

	if e == nil {
		return map[string]any{
			"generated": int64(0),
			"type":      "",
			"data":      "",
			"module":    "",
			"source":    "",
		}
	}

	return map[string]any{
		"generated": e.Generated.Unix(),
		"type":      string(e.Type),
		"data":      e.Data,
		"module":    e.Module,
		"source":    source,
	}
}
