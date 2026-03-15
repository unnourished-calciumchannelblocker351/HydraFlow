package bypass

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ChainConfig holds configuration for multi-hop proxy chaining.
type ChainConfig struct {
	// Servers lists the hops in order for the primary chain.
	Servers []ChainNode

	// Fallback is an alternative chain tried when the primary fails.
	Fallback []ChainNode

	// HealthInterval is how often to health-check each hop (seconds).
	HealthInterval int
}

// ChainTechnique implements multi-hop proxy chaining:
//   - Client -> RU VPS -> Foreign VPS (TSPU sees traffic to Russian IP)
//   - Client -> CDN -> Foreign VPS (TSPU sees traffic to Cloudflare)
//   - Client -> Yandex Cloud -> Foreign VPS (TSPU sees traffic to Yandex)
//
// If the primary chain fails, it automatically falls back to the
// alternative chain.
type ChainTechnique struct {
	config     ChainConfig
	logger     *slog.Logger
	mu         sync.RWMutex
	healthy    map[string]bool // host:port -> healthy
	usePrimary bool
}

// NewChainTechnique creates a multi-hop chain technique.
func NewChainTechnique(cfg ChainConfig, logger *slog.Logger) *ChainTechnique {
	if logger == nil {
		logger = slog.Default()
	}
	ct := &ChainTechnique{
		config:     cfg,
		logger:     logger.With("technique", "chain"),
		healthy:    make(map[string]bool),
		usePrimary: true,
	}

	// Start health-checking if configured.
	if cfg.HealthInterval > 0 && len(cfg.Servers) > 0 {
		go ct.healthCheckLoop()
	}

	return ct
}

func (c *ChainTechnique) Name() string    { return "chain" }
func (c *ChainTechnique) Available() bool { return len(c.config.Servers) > 0 }
func (c *ChainTechnique) Effective() bool { return true }

// Wrap returns the connection unchanged; chaining is at dial time.
func (c *ChainTechnique) Wrap(conn net.Conn) net.Conn {
	return conn
}

// WrapDial returns a dialer that connects through the chain.
func (c *ChainTechnique) WrapDial(next DialFunc) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.dialChain(ctx, network, address, next)
	}
}

// dialChain connects through the chain of servers. If the primary
// chain fails, it tries the fallback chain.
func (c *ChainTechnique) dialChain(ctx context.Context, network, address string, baseDial DialFunc) (net.Conn, error) {
	c.mu.RLock()
	primary := c.usePrimary
	c.mu.RUnlock()

	servers := c.config.Servers
	if !primary && len(c.config.Fallback) > 0 {
		servers = c.config.Fallback
	}

	if len(servers) == 0 {
		return baseDial(ctx, network, address)
	}

	conn, err := c.connectChain(ctx, servers, baseDial)
	if err != nil {
		// Try fallback chain.
		if primary && len(c.config.Fallback) > 0 {
			c.logger.Warn("primary chain failed, trying fallback",
				"error", err,
			)
			c.mu.Lock()
			c.usePrimary = false
			c.mu.Unlock()

			conn, err = c.connectChain(ctx, c.config.Fallback, baseDial)
			if err != nil {
				return nil, fmt.Errorf("both chains failed: %w", err)
			}
			return conn, nil
		}
		return nil, fmt.Errorf("chain dial: %w", err)
	}

	return conn, nil
}

// connectChain establishes a connection through the given chain of
// servers sequentially. Each hop is connected via the previous hop.
func (c *ChainTechnique) connectChain(ctx context.Context, servers []ChainNode, baseDial DialFunc) (net.Conn, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("chain: no servers configured")
	}

	// Connect to the first hop directly.
	first := servers[0]
	addr := net.JoinHostPort(first.Host, fmt.Sprintf("%d", first.Port))

	c.logger.Debug("connecting to first hop", "addr", addr)

	conn, err := baseDial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("first hop %s: %w", addr, err)
	}

	// Apply TLS/Reality to the first hop.
	conn, err = c.applyHopSecurity(ctx, conn, first)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("first hop security %s: %w", addr, err)
	}

	// Connect through subsequent hops.
	for i := 1; i < len(servers); i++ {
		hop := servers[i]
		c.logger.Debug("connecting through hop",
			"index", i,
			"host", hop.Host,
			"port", hop.Port,
		)

		conn, err = c.dialThroughHop(ctx, conn, hop)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("hop %d (%s:%d): %w", i, hop.Host, hop.Port, err)
		}
	}

	c.logger.Info("chain established",
		"hops", len(servers),
		"exit", fmt.Sprintf("%s:%d", servers[len(servers)-1].Host, servers[len(servers)-1].Port),
	)

	return conn, nil
}

// applyHopSecurity wraps a connection with TLS appropriate for the hop.
func (c *ChainTechnique) applyHopSecurity(ctx context.Context, conn net.Conn, hop ChainNode) (net.Conn, error) {
	sni := hop.SNI
	if sni == "" {
		sni = "www.microsoft.com"
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake (sni=%s): %w", sni, err)
	}

	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// dialThroughHop tunnels through the current connection to reach the
// next hop using a CONNECT-like request.
func (c *ChainTechnique) dialThroughHop(ctx context.Context, conn net.Conn, hop ChainNode) (net.Conn, error) {
	// Send a minimal tunnel request. The actual format depends on the
	// protocol (VLESS, SOCKS5, HTTP CONNECT). Here we implement a
	// VLESS-style tunnel since that's what HydraFlow servers speak.

	// Build VLESS request targeting the next hop.
	target := fmt.Sprintf("%s:%d", hop.Host, hop.Port)
	tunnelReq := buildChainTunnelRequest(target, hop.UUID)

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(tunnelReq); err != nil {
		return nil, fmt.Errorf("tunnel request: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read tunnel response (VLESS: version byte + addon length).
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp [2]byte
	if _, err := readFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("tunnel response: %w", err)
	}

	// Skip addon data if present.
	if resp[1] > 0 {
		addon := make([]byte, resp[1])
		if _, err := readFull(conn, addon); err != nil {
			return nil, fmt.Errorf("tunnel addon: %w", err)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Apply TLS for the new hop over the tunnel.
	return c.applyHopSecurity(ctx, conn, hop)
}

// buildChainTunnelRequest creates a minimal VLESS-format tunnel request.
func buildChainTunnelRequest(target, uuid string) []byte {
	var req []byte

	// VLESS version.
	req = append(req, 0x00)

	// UUID (16 bytes) — parse from string.
	uuidBytes := parseUUIDSimple(uuid)
	req = append(req, uuidBytes[:]...)

	// No addon.
	req = append(req, 0x00)

	// Command: TCP connect.
	req = append(req, 0x01)

	// Parse target host:port.
	host, portStr, _ := net.SplitHostPort(target)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	// Port (big-endian).
	req = append(req, byte(port>>8), byte(port&0xFF))

	// Address type and value.
	ip := net.ParseIP(host)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = append(req, 0x01)
			req = append(req, ipv4...)
		} else {
			req = append(req, 0x03)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x02)
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	return req
}

// parseUUIDSimple parses a UUID string (with or without dashes) into
// 16 bytes. Returns zeroes on parse failure.
func parseUUIDSimple(s string) [16]byte {
	var uuid [16]byte
	clean := make([]byte, 0, 32)
	for _, c := range s {
		if c != '-' {
			clean = append(clean, byte(c))
		}
	}
	if len(clean) != 32 {
		return uuid
	}
	for i := 0; i < 16; i++ {
		hi := hexVal(clean[i*2])
		lo := hexVal(clean[i*2+1])
		uuid[i] = (hi << 4) | lo
	}
	return uuid
}

func hexVal(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		return 0
	}
}

// healthCheckLoop periodically checks reachability of all hops.
func (c *ChainTechnique) healthCheckLoop() {
	interval := time.Duration(c.config.HealthInterval) * time.Second
	if interval < 10*time.Second {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.runHealthChecks()
	}
}

// runHealthChecks tests TCP reachability of every hop in both chains.
func (c *ChainTechnique) runHealthChecks() {
	allServers := make([]ChainNode, 0, len(c.config.Servers)+len(c.config.Fallback))
	allServers = append(allServers, c.config.Servers...)
	allServers = append(allServers, c.config.Fallback...)

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]bool)

	for _, srv := range allServers {
		wg.Add(1)
		go func(s ChainNode) {
			defer wg.Done()
			addr := net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			healthy := err == nil
			if conn != nil {
				conn.Close()
			}

			mu.Lock()
			results[addr] = healthy
			mu.Unlock()
		}(srv)
	}

	wg.Wait()

	c.mu.Lock()
	c.healthy = results

	// If primary chain has unhealthy hops, switch to fallback.
	primaryHealthy := true
	for _, srv := range c.config.Servers {
		addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
		if !results[addr] {
			primaryHealthy = false
			break
		}
	}
	if !primaryHealthy && len(c.config.Fallback) > 0 {
		c.usePrimary = false
		c.logger.Warn("primary chain unhealthy, switching to fallback")
	} else if primaryHealthy {
		c.usePrimary = true
	}
	c.mu.Unlock()
}

// IsHealthy reports whether a specific hop is currently healthy.
func (c *ChainTechnique) IsHealthy(host string, port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	healthy, ok := c.healthy[addr]
	return ok && healthy
}

// ChainDialer is a convenience wrapper that creates a chain dialer
// from a list of ChainNodes.
func ChainDialer(servers []ChainNode, fallback []ChainNode, logger *slog.Logger) DialFunc {
	technique := NewChainTechnique(ChainConfig{
		Servers:        servers,
		Fallback:       fallback,
		HealthInterval: 30,
	}, logger)

	d := &net.Dialer{Timeout: 30 * time.Second}
	baseDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, network, address)
	}

	return technique.WrapDial(baseDial)
}
