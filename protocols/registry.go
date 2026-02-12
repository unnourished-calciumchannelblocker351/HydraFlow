// Package protocols provides the protocol registry and all built-in
// protocol implementations for HydraFlow. Each protocol implements
// the core.Protocol interface and is automatically registered at init time.
package protocols

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/Evr1kys/HydraFlow/core"
)

// registry is the global protocol registry. Protocols register themselves
// via init() functions, and the engine queries the registry to discover
// all available implementations.
var registry = &Registry{
	factories: make(map[string]Factory),
}

// Factory creates a new Protocol instance from a generic configuration map.
// Each protocol package registers a Factory at init time.
type Factory func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error)

// Registry holds all known protocol factories and can instantiate
// protocol implementations on demand.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// Register adds a protocol factory to the global registry.
// It is safe for concurrent use and is typically called from init().
// Panics if a factory with the same name is already registered,
// preventing silent overwrites.
func Register(name string, factory Factory) {
	registry.mu.Lock()
	defer registry.mu.Unlock()

	if _, exists := registry.factories[name]; exists {
		panic(fmt.Sprintf("protocols: duplicate registration for %q", name))
	}
	registry.factories[name] = factory
}

// Get retrieves a protocol factory by name from the global registry.
// Returns nil if no factory with that name exists.
func Get(name string) Factory {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.factories[name]
}

// Names returns a sorted list of all registered protocol names.
func Names() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	names := make([]string, 0, len(registry.factories))
	for name := range registry.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Count returns the number of registered protocols.
func Count() int {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return len(registry.factories)
}

// Has reports whether a protocol with the given name is registered.
func Has(name string) bool {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	_, ok := registry.factories[name]
	return ok
}

// CreateAll instantiates all registered protocols using their factories
// and the provided configuration map. The top-level keys in configs
// should be protocol names, and their values are passed to each factory.
// Protocols that fail to instantiate are logged and skipped.
func CreateAll(configs map[string]map[string]interface{}, logger *slog.Logger) []core.Protocol {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	var protocols []core.Protocol
	for name, factory := range registry.factories {
		cfg := configs[name]
		if cfg == nil {
			cfg = make(map[string]interface{})
		}

		p, err := factory(cfg, logger)
		if err != nil {
			logger.Warn("failed to create protocol",
				"protocol", name,
				"error", err,
			)
			continue
		}
		protocols = append(protocols, p)
	}

	// Sort by priority for deterministic ordering.
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].Priority() < protocols[j].Priority()
	})

	return protocols
}

// CreateByName instantiates a single protocol by name. Returns an error
// if the protocol is not registered or if the factory fails.
func CreateByName(name string, cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
	factory := Get(name)
	if factory == nil {
		return nil, fmt.Errorf("protocols: unknown protocol %q (registered: %v)", name, Names())
	}

	p, err := factory(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("protocols: create %q: %w", name, err)
	}
	return p, nil
}

// RegisterAll registers all created protocols with the given engine.
// This is a convenience function that calls CreateAll and then registers
// each protocol with the engine.
func RegisterAll(engine *core.Engine, configs map[string]map[string]interface{}, logger *slog.Logger) error {
	protocols := CreateAll(configs, logger)
	if len(protocols) == 0 {
		return fmt.Errorf("protocols: no protocols could be created")
	}

	for _, p := range protocols {
		engine.RegisterProtocol(p)
	}

	logger.Info("protocols registered",
		"count", len(protocols),
		"names", protocolNames(protocols),
	)
	return nil
}

// protocolNames extracts names from a protocol slice for logging.
func protocolNames(protocols []core.Protocol) []string {
	names := make([]string, len(protocols))
	for i, p := range protocols {
		names[i] = p.Name()
	}
	return names
}

// BuiltinProtocols lists all protocol names that ship with HydraFlow.
// This is a constant list used for documentation and validation; it
// does not depend on whether the protocols have been registered yet.
var BuiltinProtocols = []string{
	"hydra",
	"vless-reality",
	"vless-xhttp",
	"hysteria2",
	"chain",
	"shadowtls-v3",
}

// ValidateBuiltins checks that all expected built-in protocols are
// registered. Returns a list of any missing protocols. This is called
// during startup to surface configuration issues early.
func ValidateBuiltins() []string {
	var missing []string
	for _, name := range BuiltinProtocols {
		if !Has(name) {
			missing = append(missing, name)
		}
	}
	return missing
}
