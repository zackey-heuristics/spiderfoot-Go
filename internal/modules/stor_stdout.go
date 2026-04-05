package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("stor_stdout", func() module.Module { return &StorStdout{} })
}

// StorStdout outputs scan events to stdout in a configurable format
// (tab-separated, CSV, or JSON).
type StorStdout struct {
	format       string
	delimiter    string
	stripNewline bool
	showSource   bool
	maxLength    int
	mu           sync.Mutex
}

// Meta returns module metadata for StorStdout.
func (m *StorStdout) Meta() module.Meta {
	return module.Meta{
		Name:       "stor_stdout",
		Summary:    "Outputs scan events to stdout in tab, CSV, or JSON format",
		Categories: []string{"Output"},
	}
}

// Setup initializes StorStdout configuration.
func (m *StorStdout) Setup(opts map[string]any) error {
	m.format = "tab"
	m.delimiter = ","
	m.stripNewline = false
	m.showSource = false
	m.maxLength = 0

	if v, ok := opts["format"].(string); ok {
		switch strings.ToLower(v) {
		case "csv", "json", "tab":
			m.format = strings.ToLower(v)
		}
	}
	if v, ok := opts["delimiter"].(string); ok && v != "" {
		m.delimiter = v
	}
	if v, ok := opts["stripnewline"].(bool); ok {
		m.stripNewline = v
	}
	if v, ok := opts["showsource"].(bool); ok {
		m.showSource = v
	}
	if v, ok := opts["maxlength"].(int); ok && v > 0 {
		m.maxLength = v
	}
	return nil
}

// WatchedEvents returns all event types (wildcard).
func (m *StorStdout) WatchedEvents() []event.Type {
	return []event.Type{event.Wildcard}
}

// ProducedEvents returns nothing since this is a terminal output module.
func (m *StorStdout) ProducedEvents() []event.Type {
	return nil
}

// HandleEvent formats and prints the event to stdout.
func (m *StorStdout) HandleEvent(_ context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	if evt.Type == event.ROOT {
		return nil, nil
	}

	data := evt.Data
	if m.stripNewline {
		data = strings.ReplaceAll(data, "\n", " ")
		data = strings.ReplaceAll(data, "\r", "")
	}
	if m.maxLength > 0 && len(data) > m.maxLength {
		data = data[:m.maxLength]
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.format {
	case "json":
		m.outputJSON(evt, data)
	case "csv":
		m.outputCSV(evt, data)
	default:
		m.outputTab(evt, data)
	}

	return nil, nil
}

// Finish is a no-op for StorStdout.
func (m *StorStdout) Finish() error {
	return nil
}

func (m *StorStdout) outputTab(evt *event.Event, data string) {
	mod := fmt.Sprintf("%-30s", evt.Module)
	typ := fmt.Sprintf("%-45s", string(evt.Type))
	if m.showSource && evt.SourceEvent != nil {
		src := evt.SourceEvent.Data
		if m.stripNewline {
			src = strings.ReplaceAll(src, "\n", " ")
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", mod, typ, src, data)
	} else {
		fmt.Printf("%s\t%s\t%s\n", mod, typ, data)
	}
}

func (m *StorStdout) outputCSV(evt *event.Event, data string) {
	d := m.delimiter
	if m.showSource && evt.SourceEvent != nil {
		src := evt.SourceEvent.Data
		fmt.Printf("%s%s%s%s%s%s%s\n", evt.Module, d, string(evt.Type), d, src, d, data)
	} else {
		fmt.Printf("%s%s%s%s%s\n", evt.Module, d, string(evt.Type), d, data)
	}
}

func (m *StorStdout) outputJSON(evt *event.Event, data string) {
	obj := map[string]string{
		"module": evt.Module,
		"type":   string(evt.Type),
		"data":   data,
	}
	if m.showSource && evt.SourceEvent != nil {
		obj["source"] = evt.SourceEvent.Data
	}
	b, err := json.Marshal(obj)
	if err == nil {
		fmt.Println(string(b))
	}
}
