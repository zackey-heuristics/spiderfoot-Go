package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zackey-heuristics/spiderfoot-Go/internal/event"
	"github.com/zackey-heuristics/spiderfoot-Go/internal/module"
)

func init() {
	module.Register("portscan_tcp", func() module.Module { return &PortscanTCP{} })
}

// PortscanTCP performs TCP port scanning against discovered IP addresses,
// identifying open ports and collecting service banners.
type PortscanTCP struct {
	seen       map[string]bool
	mu         sync.Mutex
	ports      []int
	timeout    time.Duration
	maxWorkers int
}

// defaultPorts lists the TCP ports scanned by default.
var defaultPorts = []int{
	21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 113, 119, 123,
	137, 138, 139, 143, 161, 179, 389, 443, 445, 465, 512, 513,
	514, 515, 631, 636, 990, 992, 993, 995, 1080, 1433, 1521,
	2638, 3306, 3389, 5432, 5631, 5900, 5901, 5902, 5903, 8080, 8888, 9000,
}

// Meta returns module metadata for PortscanTCP.
func (m *PortscanTCP) Meta() module.Meta {
	return module.Meta{
		Name:       "portscan_tcp",
		Summary:    "Scans for common open TCP ports on IP addresses",
		Categories: []string{"Scanning"},
	}
}

// Setup initializes PortscanTCP configuration.
func (m *PortscanTCP) Setup(opts map[string]any) error {
	m.seen = make(map[string]bool)
	m.ports = defaultPorts
	m.timeout = 15 * time.Second
	m.maxWorkers = 10

	if v, ok := opts["timeout"].(int); ok && v > 0 {
		m.timeout = time.Duration(v) * time.Second
	}
	if v, ok := opts["maxworkers"].(int); ok && v > 0 {
		m.maxWorkers = v
	}
	if v, ok := opts["ports"].([]int); ok && len(v) > 0 {
		m.ports = v
	}
	return nil
}

// WatchedEvents returns event types that PortscanTCP consumes.
func (m *PortscanTCP) WatchedEvents() []event.Type {
	return []event.Type{event.IP_ADDRESS}
}

// ProducedEvents returns event types that PortscanTCP may emit.
func (m *PortscanTCP) ProducedEvents() []event.Type {
	return []event.Type{event.TCP_PORT_OPEN, event.TCP_PORT_OPEN_BANNER}
}

// HandleEvent scans TCP ports on the given IP address.
func (m *PortscanTCP) HandleEvent(ctx context.Context, evt *event.Event) ([]*event.Event, error) {
	if evt == nil {
		return nil, nil
	}

	ip := strings.TrimSpace(evt.Data)
	if net.ParseIP(ip) == nil {
		return nil, nil
	}

	if m.markSeen(ip) {
		return nil, nil
	}

	var (
		results []*event.Event
		resMu   sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, m.maxWorkers)
	)

	for _, port := range m.ports {
		if ctx.Err() != nil {
			break
		}
		port := port
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", addr, m.timeout)
			if err != nil {
				return
			}

			portStr := fmt.Sprintf("%s:%d", ip, port)
			resMu.Lock()
			if e, err2 := event.New(event.TCP_PORT_OPEN, portStr, "portscan_tcp", evt); err2 == nil {
				results = append(results, e)
			}
			resMu.Unlock()

			// Try to read a banner.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			conn.Close()
			if err == nil && n > 0 {
				banner := strings.TrimSpace(string(buf[:n]))
				if banner != "" {
					resMu.Lock()
					if e, err2 := event.New(event.TCP_PORT_OPEN_BANNER, portStr+" ["+banner+"]", "portscan_tcp", evt); err2 == nil {
						results = append(results, e)
					}
					resMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// Finish releases resources held by PortscanTCP.
func (m *PortscanTCP) Finish() error {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
	return nil
}

func (m *PortscanTCP) markSeen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		return false
	}
	if m.seen[key] {
		return true
	}
	m.seen[key] = true
	return false
}
