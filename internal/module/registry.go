package module

import (
	"slices"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]func() Module)
)

// Register adds a module factory to the package registry.
//
// It panics if the name is empty, the factory is nil, or the name is already
// registered.
func Register(name string, factory func() Module) {
	if name == "" {
		panic("module: register empty name")
	}

	if factory == nil {
		panic("module: register nil factory")
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[name]; exists {
		panic("module: register duplicate name: " + name)
	}

	registry[name] = factory
}

// Get returns the registered factory for name.
func Get(name string) (func() Module, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	factory, ok := registry[name]
	return factory, ok
}

// All returns all registered module names in sorted order.
func All() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}

	slices.Sort(names)
	return names
}

// Reset clears the package registry.
//
// This helper exists for tests.
func Reset() {
	registryMu.Lock()
	defer registryMu.Unlock()

	clear(registry)
}
