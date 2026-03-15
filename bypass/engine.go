// Package bypass provides the core DPI bypass engine for HydraFlow.
// It combines every known DPI bypass technique (fragmentation, padding,
// TCP desync, SNI manipulation, multi-hop chains, DNS bypass, and more)
// into a single configurable engine. On startup it probes the network,
// detects what is blocked, and automatically enables the right
// combination of techniques.
package bypass

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Technique is a single bypass method that can wrap connections.
type Technique interface {
	// Name returns a human-readable identifier.
	Name() string

	// Wrap applies this technique to an existing connection.
	// It returns a wrapped connection or the original if the technique
	// is not applicable.
	Wrap(conn net.Conn) net.Conn

	// WrapDial returns a Dialer that applies this technique during
	// the initial handshake phase.
	WrapDial(dialer DialFunc) DialFunc

	// Available reports whether this technique is usable in the
	// current environment.
	Available() bool

	// Effective reports whether probing determined this technique
	// actually helps bypass DPI in the current network.
	Effective() bool
}

// DialFunc is a function signature matching net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ProtocolConfig describes one available proxy protocol with priority.
type ProtocolConfig struct {
	// Name identifies the protocol (e.g. "reality", "ws-cdn", "hysteria2").
	Name string `yaml:"name" json:"name"`

	// Priority controls selection order (lower = tried first).
	Priority int `yaml:"priority" json:"priority"`

	// Enabled controls whether this protocol is active.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ChainNode describes one hop in a multi-hop chain.
type ChainNode struct {
	// Host is the server address.
	Host string `yaml:"host" json:"host"`

	// Port is the server port.
	Port int `yaml:"port" json:"port"`

	// Protocol is the transport protocol for this hop.
	Protocol string `yaml:"protocol" json:"protocol"`

	// SNI is the TLS server name for this hop.
	SNI string `yaml:"sni" json:"sni"`

	// UUID is the authentication credential.
	UUID string `yaml:"uuid" json:"uuid"`

	// PublicKey is the Reality public key (if applicable).
	PublicKey string `yaml:"public_key" json:"public_key"`

	// ShortID is the Reality short ID (if applicable).
	ShortID string `yaml:"short_id" json:"short_id"`
}

// BypassConfig holds all tunable parameters for the bypass engine.
type BypassConfig struct {
	// ---- Fragment settings ----

	// FragmentEnabled turns on TLS ClientHello fragmentation.
	FragmentEnabled bool `yaml:"fragment_enabled" json:"fragment_enabled"`
	// FragmentSize is a range like "1-5" (bytes per fragment).
	FragmentSize string `yaml:"fragment_size" json:"fragment_size"`
	// FragmentInterval is the delay between fragments in ms, e.g. "1-5".
	FragmentInterval string `yaml:"fragment_interval" json:"fragment_interval"`
	// FragmentPackets controls what to fragment: "tlshello" or "1-3" (first N packets).
	FragmentPackets string `yaml:"fragment_packets" json:"fragment_packets"`

	// ---- Padding ----

	// PaddingEnabled turns on traffic padding and shaping.
	PaddingEnabled bool `yaml:"padding_enabled" json:"padding_enabled"`
	// PaddingSize is a range like "100-200" (target padded size in bytes).
	PaddingSize string `yaml:"padding_size" json:"padding_size"`
	// TimingJitterMs is the max jitter in ms added to each write (0 = off).
	TimingJitterMs int `yaml:"timing_jitter_ms" json:"timing_jitter_ms"`
	// FakePacketInterval sends a random packet every N real packets (0 = off).
	FakePacketInterval int `yaml:"fake_packet_interval" json:"fake_packet_interval"`

	// ---- Multi-hop chain ----

	// ChainEnabled turns on multi-hop proxy chaining.
	ChainEnabled bool `yaml:"chain_enabled" json:"chain_enabled"`
	// ChainServers lists the hops in order.
	ChainServers []ChainNode `yaml:"chain_servers" json:"chain_servers"`
	// ChainFallback is an alternative chain tried when the primary fails.
	ChainFallback []ChainNode `yaml:"chain_fallback" json:"chain_fallback"`
	// ChainHealthInterval is how often to health-check each hop (seconds).
	ChainHealthInterval int `yaml:"chain_health_interval" json:"chain_health_interval"`

	// ---- SNI tricks ----

	// SNIDomain is the primary SNI value.
	SNIDomain string `yaml:"sni_domain" json:"sni_domain"`
	// SNIFallbacks are backup SNI domains tried in order.
	SNIFallbacks []string `yaml:"sni_fallbacks" json:"sni_fallbacks"`
	// FakeSNI sends a decoy SNI in the first packet when true.
	FakeSNI bool `yaml:"fake_sni" json:"fake_sni"`
	// SNIRotation changes the SNI every N connections (0 = off).
	SNIRotation int `yaml:"sni_rotation" json:"sni_rotation"`
	// DomainFronting uses CDN domain fronting when true.
	DomainFronting bool `yaml:"domain_fronting" json:"domain_fronting"`
	// DomainFrontHost is the Host header domain when domain fronting.
	DomainFrontHost string `yaml:"domain_front_host" json:"domain_front_host"`

	// ---- Timing ----

	// TimingEnabled turns on inter-packet timing randomisation.
	TimingEnabled bool `yaml:"timing_enabled" json:"timing_enabled"`
	// TimingInterval is a range like "5-50" ms between packets.
	TimingInterval string `yaml:"timing_interval" json:"timing_interval"`

	// ---- TCP desync ----

	// DesyncEnabled turns on TCP desync techniques.
	DesyncEnabled bool `yaml:"desync_enabled" json:"desync_enabled"`
	// DesyncFakeTTL is the TTL for fake packets (0 = auto-detect).
	DesyncFakeTTL int `yaml:"desync_fake_ttl" json:"desync_fake_ttl"`
	// DesyncSplitPos is the byte offset at which to split TCP segments.
	DesyncSplitPos int `yaml:"desync_split_pos" json:"desync_split_pos"`
	// DesyncOOO sends packets out of order when true.
	DesyncOOO bool `yaml:"desync_ooo" json:"desync_ooo"`
	// DesyncWindowSize forces a small TCP window (0 = disabled).
	DesyncWindowSize int `yaml:"desync_window_size" json:"desync_window_size"`

	// ---- DNS ----

	// DOHEnabled turns on DNS-over-HTTPS for all resolution.
	DOHEnabled bool `yaml:"doh_enabled" json:"doh_enabled"`
	// DOHServer is the DoH endpoint, e.g. "https://dns.google/dns-query".
	DOHServer string `yaml:"doh_server" json:"doh_server"`
	// DOTEnabled turns on DNS-over-TLS as a fallback.
	DOTEnabled bool `yaml:"dot_enabled" json:"dot_enabled"`
	// DOTServer is the DoT server, e.g. "dns.google:853".
	DOTServer string `yaml:"dot_server" json:"dot_server"`
	// SplitDNS routes Russian domains to a Russian DNS server.
	SplitDNS bool `yaml:"split_dns" json:"split_dns"`
	// RussianDNS is the DNS server for .ru zones when SplitDNS is on.
	RussianDNS string `yaml:"russian_dns" json:"russian_dns"`

	// ---- Protocol mix ----

	// Protocols lists all available protocols with priority.
	Protocols []ProtocolConfig `yaml:"protocols" json:"protocols"`

	// ---- Auto-probe ----

	// AutoProbe runs network probing on startup to auto-configure.
	AutoProbe bool `yaml:"auto_probe" json:"auto_probe"`
	// ProbeTarget is the host:port to probe against.
	ProbeTarget string `yaml:"probe_target" json:"probe_target"`
	// ProbeTimeout is the maximum time for the probe phase.
	ProbeTimeout time.Duration `yaml:"probe_timeout" json:"probe_timeout"`

	// ---- Preset ----

	// Preset selects a pre-built configuration by name (e.g. "russia-megafon").
	// When set, it overrides individual settings unless they are explicitly provided.
	Preset string `yaml:"preset" json:"preset"`
}

// DefaultBypassConfig returns a config with safe defaults that work
// in most environments without any network probing.
func DefaultBypassConfig() BypassConfig {
	return BypassConfig{
		FragmentEnabled:  false,
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   false,
		PaddingSize:      "100-200",
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		AutoProbe:        true,
		ProbeTimeout:     15 * time.Second,
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "ss2022", Priority: 3, Enabled: true},
		},
	}
}

// BypassEngine combines all DPI bypass techniques and orchestrates
// which ones to enable based on configuration and network probing.
type BypassEngine struct {
	mu         sync.RWMutex
	config     BypassConfig
	techniques []Technique
	profile    *NetworkProfile
	logger     *slog.Logger

	// sniCounter tracks connections for SNI rotation.
	sniCounter int

	// dnsResolver is the configured DNS resolver.
	dnsResolver *DNSResolver
}

// NewBypassEngine creates an engine with the given config. If the
// config specifies a preset, the preset values are applied first.
func NewBypassEngine(cfg BypassConfig, logger *slog.Logger) (*BypassEngine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Apply preset if specified.
	if cfg.Preset != "" {
		if preset, ok := Presets[cfg.Preset]; ok {
			cfg = mergeConfigs(preset, cfg)
			logger.Info("preset applied", "preset", cfg.Preset)
		} else {
			logger.Warn("unknown preset, using as-is", "preset", cfg.Preset)
		}
	}

	e := &BypassEngine{
		config: cfg,
		logger: logger,
	}

	// Initialize DNS resolver.
	if cfg.DOHEnabled || cfg.DOTEnabled || cfg.SplitDNS {
		e.dnsResolver = NewDNSResolver(DNSConfig{
			DOHEnabled: cfg.DOHEnabled,
			DOHServer:  cfg.DOHServer,
			DOTEnabled: cfg.DOTEnabled,
			DOTServer:  cfg.DOTServer,
			SplitDNS:   cfg.SplitDNS,
			RussianDNS: cfg.RussianDNS,
		}, logger)
	}

	// Register techniques based on config.
	e.registerTechniques()

	logger.Info("bypass engine initialised",
		"techniques", e.techniqueNames(),
		"protocols", len(cfg.Protocols),
	)

	return e, nil
}

// registerTechniques instantiates and adds all enabled techniques.
func (e *BypassEngine) registerTechniques() {
	if e.config.FragmentEnabled {
		e.techniques = append(e.techniques, NewFragmentTechnique(
			e.config.FragmentSize,
			e.config.FragmentInterval,
			e.config.FragmentPackets,
		))
	}

	if e.config.PaddingEnabled {
		e.techniques = append(e.techniques, NewPaddingTechnique(
			e.config.PaddingSize,
			e.config.TimingJitterMs,
			e.config.FakePacketInterval,
		))
	}

	if e.config.DesyncEnabled {
		e.techniques = append(e.techniques, NewDesyncTechnique(DesyncConfig{
			FakeTTL:    e.config.DesyncFakeTTL,
			SplitPos:   e.config.DesyncSplitPos,
			OOO:        e.config.DesyncOOO,
			WindowSize: e.config.DesyncWindowSize,
		}))
	}

	if e.config.SNIDomain != "" || e.config.FakeSNI || len(e.config.SNIFallbacks) > 0 {
		e.techniques = append(e.techniques, NewSNITechnique(SNIConfig{
			Domain:          e.config.SNIDomain,
			Fallbacks:       e.config.SNIFallbacks,
			FakeSNI:         e.config.FakeSNI,
			Rotation:        e.config.SNIRotation,
			DomainFronting:  e.config.DomainFronting,
			DomainFrontHost: e.config.DomainFrontHost,
		}))
	}

	if e.config.ChainEnabled && len(e.config.ChainServers) > 0 {
		e.techniques = append(e.techniques, NewChainTechnique(ChainConfig{
			Servers:        e.config.ChainServers,
			Fallback:       e.config.ChainFallback,
			HealthInterval: e.config.ChainHealthInterval,
		}, e.logger))
	}
}

// techniqueNames returns the names of all registered techniques.
func (e *BypassEngine) techniqueNames() []string {
	names := make([]string, len(e.techniques))
	for i, t := range e.techniques {
		names[i] = t.Name()
	}
	return names
}

// AutoConfigure probes the network and adjusts the config automatically.
// It should be called once on startup when AutoProbe is enabled.
func (e *BypassEngine) AutoConfigure(ctx context.Context) (*NetworkProfile, error) {
	if e.config.ProbeTarget == "" {
		return nil, fmt.Errorf("bypass: probe_target is required for auto-configure")
	}

	timeout := e.config.ProbeTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	e.logger.Info("starting network probe", "target", e.config.ProbeTarget)

	prober := NewNetworkProber(e.config.ProbeTarget, e.logger)
	profile, err := prober.Probe(probeCtx)
	if err != nil {
		return nil, fmt.Errorf("bypass: probe failed: %w", err)
	}

	e.mu.Lock()
	e.profile = profile
	e.mu.Unlock()

	// Apply probe results to config.
	e.applyProfile(profile)

	e.logger.Info("auto-configure complete",
		"fragment_effective", profile.FragmentEffective,
		"quic_available", profile.QUICAvailable,
		"optimal_fragment_size", profile.OptimalFragmentSize,
		"blocked_snis", profile.BlockedSNIs,
	)

	return profile, nil
}

// applyProfile adjusts the engine configuration based on probe results.
func (e *BypassEngine) applyProfile(p *NetworkProfile) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Enable fragmentation if probing showed it works.
	if p.FragmentEffective && !e.config.FragmentEnabled {
		e.config.FragmentEnabled = true
		if p.OptimalFragmentSize > 0 {
			e.config.FragmentSize = fmt.Sprintf("%d-%d",
				p.OptimalFragmentSize, p.OptimalFragmentSize+5)
		}
		e.config.FragmentPackets = "tlshello"
		e.techniques = append(e.techniques, NewFragmentTechnique(
			e.config.FragmentSize,
			e.config.FragmentInterval,
			e.config.FragmentPackets,
		))
		e.logger.Info("auto-enabled fragmentation",
			"size", e.config.FragmentSize)
	}

	// If QUIC is blocked, remove hysteria2 from protocol list.
	if !p.QUICAvailable {
		var filtered []ProtocolConfig
		for _, proto := range e.config.Protocols {
			if proto.Name != "hysteria2" {
				filtered = append(filtered, proto)
			}
		}
		e.config.Protocols = filtered
		e.logger.Info("QUIC blocked, removed hysteria2 from protocols")
	}

	// If certain protocols are blocked, disable them.
	for _, blocked := range p.BlockedProtocols {
		var filtered []ProtocolConfig
		for _, proto := range e.config.Protocols {
			if proto.Name != blocked {
				filtered = append(filtered, proto)
			}
		}
		e.config.Protocols = filtered
	}

	// If SNI domains are blocked, set fallback SNIs.
	if len(p.WorkingSNIs) > 0 && e.config.SNIDomain == "" {
		e.config.SNIDomain = p.WorkingSNIs[0]
		if len(p.WorkingSNIs) > 1 {
			e.config.SNIFallbacks = p.WorkingSNIs[1:]
		}
		e.logger.Info("auto-set SNI from probe",
			"primary", e.config.SNIDomain,
			"fallbacks", e.config.SNIFallbacks)
	}
}

// Dial creates a connection with all enabled bypass techniques applied.
// Techniques are layered in order: DNS resolution -> Chain -> Fragment ->
// Desync -> Padding -> SNI manipulation.
func (e *BypassEngine) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	e.mu.RLock()
	techniques := make([]Technique, len(e.techniques))
	copy(techniques, e.techniques)
	e.mu.RUnlock()

	// Base dialer — optionally uses our DNS resolver.
	var dialFn DialFunc
	if e.dnsResolver != nil {
		dialFn = e.dnsResolver.DialContext
	} else {
		d := &net.Dialer{Timeout: 30 * time.Second}
		dialFn = d.DialContext
	}

	// Layer each technique's dial wrapper.
	for _, t := range techniques {
		if t.Available() {
			dialFn = t.WrapDial(dialFn)
		}
	}

	conn, err := dialFn(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("bypass dial: %w", err)
	}

	// Apply connection wrappers (post-connect techniques like padding).
	for _, t := range techniques {
		if t.Available() {
			conn = t.Wrap(conn)
		}
	}

	return conn, nil
}

// Dialer returns a DialFunc that uses this bypass engine.
func (e *BypassEngine) Dialer() DialFunc {
	return e.Dial
}

// Config returns a copy of the current configuration.
func (e *BypassEngine) Config() BypassConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cfg := e.config
	return cfg
}

// Profile returns the detected network profile, or nil if probing
// has not been run.
func (e *BypassEngine) Profile() *NetworkProfile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.profile
}

// CurrentSNI returns the SNI domain to use for the current connection,
// accounting for rotation. It is safe for concurrent use.
func (e *BypassEngine) CurrentSNI() string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.config.SNIDomain == "" {
		return ""
	}

	if e.config.SNIRotation <= 0 || len(e.config.SNIFallbacks) == 0 {
		return e.config.SNIDomain
	}

	pool := append([]string{e.config.SNIDomain}, e.config.SNIFallbacks...)
	idx := (e.sniCounter / e.config.SNIRotation) % len(pool)
	e.sniCounter++
	return pool[idx]
}

// Techniques returns all registered techniques (for inspection/testing).
func (e *BypassEngine) Techniques() []Technique {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Technique, len(e.techniques))
	copy(out, e.techniques)
	return out
}

// mergeConfigs applies preset values as defaults, then overrides with
// any explicitly-set values from the user config. The rule is: if the
// user config field is the zero value, use the preset value.
func mergeConfigs(preset, user BypassConfig) BypassConfig {
	out := preset

	// Overrides — only apply non-zero user values.
	if user.FragmentEnabled {
		out.FragmentEnabled = true
	}
	if user.FragmentSize != "" {
		out.FragmentSize = user.FragmentSize
	}
	if user.FragmentInterval != "" {
		out.FragmentInterval = user.FragmentInterval
	}
	if user.FragmentPackets != "" {
		out.FragmentPackets = user.FragmentPackets
	}
	if user.PaddingEnabled {
		out.PaddingEnabled = true
	}
	if user.PaddingSize != "" {
		out.PaddingSize = user.PaddingSize
	}
	if user.TimingJitterMs > 0 {
		out.TimingJitterMs = user.TimingJitterMs
	}
	if user.FakePacketInterval > 0 {
		out.FakePacketInterval = user.FakePacketInterval
	}
	if user.ChainEnabled {
		out.ChainEnabled = true
	}
	if len(user.ChainServers) > 0 {
		out.ChainServers = user.ChainServers
	}
	if len(user.ChainFallback) > 0 {
		out.ChainFallback = user.ChainFallback
	}
	if user.ChainHealthInterval > 0 {
		out.ChainHealthInterval = user.ChainHealthInterval
	}
	if user.SNIDomain != "" {
		out.SNIDomain = user.SNIDomain
	}
	if len(user.SNIFallbacks) > 0 {
		out.SNIFallbacks = user.SNIFallbacks
	}
	if user.FakeSNI {
		out.FakeSNI = true
	}
	if user.SNIRotation > 0 {
		out.SNIRotation = user.SNIRotation
	}
	if user.DomainFronting {
		out.DomainFronting = true
	}
	if user.DomainFrontHost != "" {
		out.DomainFrontHost = user.DomainFrontHost
	}
	if user.TimingEnabled {
		out.TimingEnabled = true
	}
	if user.TimingInterval != "" {
		out.TimingInterval = user.TimingInterval
	}
	if user.DesyncEnabled {
		out.DesyncEnabled = true
	}
	if user.DesyncFakeTTL > 0 {
		out.DesyncFakeTTL = user.DesyncFakeTTL
	}
	if user.DesyncSplitPos > 0 {
		out.DesyncSplitPos = user.DesyncSplitPos
	}
	if user.DesyncOOO {
		out.DesyncOOO = true
	}
	if user.DesyncWindowSize > 0 {
		out.DesyncWindowSize = user.DesyncWindowSize
	}
	if user.DOHEnabled {
		out.DOHEnabled = true
	}
	if user.DOHServer != "" {
		out.DOHServer = user.DOHServer
	}
	if user.DOTEnabled {
		out.DOTEnabled = true
	}
	if user.DOTServer != "" {
		out.DOTServer = user.DOTServer
	}
	if user.SplitDNS {
		out.SplitDNS = true
	}
	if user.RussianDNS != "" {
		out.RussianDNS = user.RussianDNS
	}
	if len(user.Protocols) > 0 {
		out.Protocols = user.Protocols
	}
	if user.ProbeTarget != "" {
		out.ProbeTarget = user.ProbeTarget
	}
	if user.ProbeTimeout > 0 {
		out.ProbeTimeout = user.ProbeTimeout
	}

	// Always keep the preset name.
	out.Preset = user.Preset

	return out
}
