// Package xhttp implements the VLESS + XHTTP transport protocol for HydraFlow.
// XHTTP carries VLESS traffic over HTTP/2 or HTTP/3 through CDN providers
// (primarily Cloudflare), making the traffic appear as regular web requests.
// This is particularly effective when direct server IP access is blocked,
// as the CDN provides a domain-fronting-like bypass mechanism.
package xhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Evr1kys/HydraFlow/core"
	"github.com/Evr1kys/HydraFlow/protocols"
)

const (
	protocolName = "vless-xhttp"

	// defaultPriority is medium; XHTTP works when direct is blocked
	// but adds CDN latency overhead.
	defaultPriority = 20

	// vlessVersion is the VLESS protocol version byte.
	vlessVersion = 0

	// dialTimeout is the default timeout for establishing connections.
	dialTimeout = 20 * time.Second

	// defaultPath is the default HTTP path prefix.
	defaultPath = "/xhttp"

	// defaultCDNProvider is the default CDN backend.
	defaultCDNProvider = "cloudflare"
)

func init() {
	protocols.Register(protocolName, func(cfg map[string]interface{}, logger *slog.Logger) (core.Protocol, error) {
		xc := DefaultConfig()
		if v, ok := cfg["host"].(string); ok {
			xc.Host = v
		}
		if v, ok := cfg["port"].(int); ok {
			xc.Port = v
		}
		if v, ok := cfg["uuid"].(string); ok {
			xc.UUID = v
		}
		if v, ok := cfg["cdn_host"].(string); ok {
			xc.CDNHost = v
		}
		if v, ok := cfg["cdn_provider"].(string); ok {
			xc.CDNProvider = v
		}
		if v, ok := cfg["path"].(string); ok {
			xc.Path = v
		}
		if v, ok := cfg["sni"].(string); ok {
			xc.SNI = v
		}
		if v, ok := cfg["priority"].(int); ok {
			xc.Priority = v
		}
		if v, ok := cfg["extra_headers"].(map[string]interface{}); ok {
			for k, val := range v {
				if s, ok2 := val.(string); ok2 {
					xc.ExtraHeaders[k] = s
				}
			}
		}
		if v, ok := cfg["max_early_data"].(int); ok {
			xc.MaxEarlyData = v
		}
		if v, ok := cfg["early_data_header"].(string); ok {
			xc.EarlyDataHeader = v
		}

		return New(xc, logger)
	})
}

// XHTTPConfig contains all settings for a VLESS XHTTP connection.
type XHTTPConfig struct {
	// Host is the origin server address (behind the CDN).
	Host string `yaml:"host" json:"host"`

	// Port is the origin server port.
	Port int `yaml:"port" json:"port"`

	// UUID is the VLESS user ID.
	UUID string `yaml:"uuid" json:"uuid"`

	// CDNHost is the CDN hostname to connect through. This is the
	// domain pointed to Cloudflare (or another CDN) that routes
	// to the origin server.
	CDNHost string `yaml:"cdn_host" json:"cdn_host"`

	// CDNProvider identifies the CDN backend for provider-specific
	// optimizations. Supported: "cloudflare", "gcore", "custom".
	CDNProvider string `yaml:"cdn_provider" json:"cdn_provider"`

	// SNI is the TLS Server Name Indication. When using CDN, this
	// should match the CDN domain.
	SNI string `yaml:"sni" json:"sni"`

	// Path is the HTTP request path prefix for XHTTP streams.
	Path string `yaml:"path" json:"path"`

	// ExtraHeaders contains additional HTTP headers to include
	// in requests. Useful for passing through CDN-specific headers
	// or mimicking real traffic patterns.
	ExtraHeaders map[string]string `yaml:"extra_headers" json:"extra_headers"`

	// MaxEarlyData sets the maximum bytes of early data (0-RTT)
	// to include in the initial request. Set to 0 to disable.
	MaxEarlyData int `yaml:"max_early_data" json:"max_early_data"`

	// EarlyDataHeader is the HTTP header name used to carry early
	// data when MaxEarlyData > 0.
	EarlyDataHeader string `yaml:"early_data_header" json:"early_data_header"`

	// Priority controls protocol selection order (lower = higher priority).
	Priority int `yaml:"priority" json:"priority"`

	// DialTimeout overrides the default connection timeout.
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// EnableH3 enables HTTP/3 (QUIC) transport to the CDN when available.
	EnableH3 bool `yaml:"enable_h3" json:"enable_h3"`
}

// DefaultConfig returns an XHTTPConfig with sensible defaults.
func DefaultConfig() *XHTTPConfig {
	return &XHTTPConfig{
		Port:            443,
		CDNProvider:     defaultCDNProvider,
		Path:            defaultPath,
		ExtraHeaders:    make(map[string]string),
		MaxEarlyData:    0,
		EarlyDataHeader: "Sec-WebSocket-Protocol",
		Priority:        defaultPriority,
		DialTimeout:     dialTimeout,
		EnableH3:        false,
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *XHTTPConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("xhttp: host is required")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("xhttp: invalid port %d", c.Port)
	}
	if c.UUID == "" {
		return fmt.Errorf("xhttp: uuid is required")
	}
	if c.CDNHost == "" {
		return fmt.Errorf("xhttp: cdn_host is required")
	}
	if c.Path == "" {
		return fmt.Errorf("xhttp: path is required")
	}
	return nil
}

// XHTTP implements the core.Protocol interface for VLESS + XHTTP.
type XHTTP struct {
	config *XHTTPConfig
	logger *slog.Logger

	mu        sync.RWMutex
	available bool
	lastCheck time.Time

	// httpClient is reused across connections for keep-alive.
	httpClient *http.Client
}

// New creates a new XHTTP protocol instance with the given configuration.
func New(cfg *XHTTPConfig, logger *slog.Logger) (*XHTTP, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	x := &XHTTP{
		config:    cfg,
		logger:    logger.With("protocol", protocolName),
		available: true,
	}

	x.httpClient = x.buildHTTPClient()

	return x, nil
}

// Name returns the protocol identifier.
func (x *XHTTP) Name() string {
	return protocolName
}

// Priority returns the protocol's selection priority.
func (x *XHTTP) Priority() int {
	return x.config.Priority
}

// Available reports whether XHTTP is likely to work on the current network.
func (x *XHTTP) Available() bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.available
}

// Dial establishes a VLESS XHTTP connection through the CDN.
// The connection process:
//  1. Resolve CDN host to get CDN edge server
//  2. TLS handshake with CDN edge (using CDN host as SNI)
//  3. HTTP/2 request to establish XHTTP stream
//  4. VLESS protocol header over the XHTTP stream
//  5. Bidirectional data transfer over the HTTP stream
func (x *XHTTP) Dial(ctx context.Context) (net.Conn, error) {
	timeout := x.config.DialTimeout
	if timeout == 0 {
		timeout = dialTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cdnHost := x.config.CDNHost
	sni := x.config.SNI
	if sni == "" {
		sni = cdnHost
	}

	x.logger.Debug("dialing xhttp through cdn",
		"cdn_host", cdnHost,
		"sni", sni,
		"path", x.config.Path,
		"provider", x.config.CDNProvider,
	)

	// Step 1: Establish TLS connection to CDN edge.
	addr := net.JoinHostPort(cdnHost, fmt.Sprintf("%d", x.config.Port))
	tlsCfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: timeout,
		},
		Config: tlsCfg,
	}

	tlsConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		x.markUnavailable()
		return nil, fmt.Errorf("xhttp: cdn tls dial %s: %w", addr, err)
	}

	// Step 2: Build the XHTTP upgrade request.
	reqPath := x.config.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s%s", cdnHost, reqPath), nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: build request: %w", err)
	}

	// Set headers to look like legitimate web traffic.
	req.Header.Set("Host", cdnHost)
	req.Header.Set("User-Agent", chromeUserAgent())
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("X-Forwarded-For", "")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// Apply CDN-specific headers.
	x.applyCDNHeaders(req)

	// Apply user-defined extra headers.
	for k, v := range x.config.ExtraHeaders {
		req.Header.Set(k, v)
	}

	// Step 3: Send the HTTP request to establish the stream.
	if err := req.Write(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: write request: %w", err)
	}

	// Step 4: Read the HTTP response.
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: unexpected status %d from CDN", resp.StatusCode)
	}

	// Step 5: Send VLESS header over the established stream.
	uuid, err := parseUUID(x.config.UUID)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: parse uuid: %w", err)
	}

	vlessHeader := buildVLESSHeader(uuid, x.config.Host, x.config.Port)
	if _, err := tlsConn.Write(vlessHeader); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: write vless header: %w", err)
	}

	// Step 6: Read VLESS response.
	vlessResp := make([]byte, 2)
	if _, err := io.ReadFull(br, vlessResp); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: read vless response: %w", err)
	}
	if vlessResp[0] != vlessVersion {
		tlsConn.Close()
		return nil, fmt.Errorf("xhttp: unexpected vless version %d", vlessResp[0])
	}
	// Skip addon if present.
	if addonLen := vlessResp[1]; addonLen > 0 {
		addon := make([]byte, addonLen)
		if _, err := io.ReadFull(br, addon); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("xhttp: read vless addon: %w", err)
		}
	}

	x.markAvailable()

	x.logger.Info("xhttp connection established",
		"cdn", cdnHost,
		"path", reqPath,
	)

	return &xhttpConn{
		Conn:     tlsConn,
		reader:   br,
		config:   x.config,
		logger:   x.logger,
		response: resp,
	}, nil
}

// Listen starts an XHTTP server listener. For XHTTP, the server side
// is typically an xray-core instance behind a CDN-proxied domain.
func (x *XHTTP) Listen(ctx context.Context, addr string) (net.Listener, error) {
	return nil, fmt.Errorf("xhttp: server-side listening not implemented (use xray-core behind CDN)")
}

// ProbeTests returns censorship detection tests relevant to XHTTP.
func (x *XHTTP) ProbeTests() []core.ProbeTest {
	return []core.ProbeTest{
		&xhttpCDNProbe{
			cdnHost:  x.config.CDNHost,
			port:     x.config.Port,
			sni:      x.config.SNI,
			provider: x.config.CDNProvider,
		},
		&xhttpHTTPProbe{
			cdnHost: x.config.CDNHost,
			port:    x.config.Port,
			path:    x.config.Path,
		},
	}
}

// applyCDNHeaders sets provider-specific HTTP headers.
func (x *XHTTP) applyCDNHeaders(req *http.Request) {
	switch x.config.CDNProvider {
	case "cloudflare":
		// Cloudflare-specific headers to prevent caching and
		// ensure the request reaches the origin.
		req.Header.Set("CF-Connecting-IP", "")
		req.Header.Set("Cache-Control", "no-store")
	case "gcore":
		req.Header.Set("Cache-Control", "no-cache, no-store")
	default:
		req.Header.Set("Cache-Control", "no-store")
	}
}

// buildHTTPClient creates an HTTP client configured for CDN transport.
func (x *XHTTP) buildHTTPClient() *http.Client {
	sni := x.config.SNI
	if sni == "" {
		sni = x.config.CDNHost
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   x.config.DialTimeout,
	}
}

// markAvailable marks the protocol as available.
func (x *XHTTP) markAvailable() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.available = true
	x.lastCheck = time.Now()
}

// markUnavailable marks the protocol as unavailable.
func (x *XHTTP) markUnavailable() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.available = false
	x.lastCheck = time.Now()
}

// xhttpConn wraps a connection established through XHTTP CDN transport.
type xhttpConn struct {
	net.Conn
	reader   *bufio.Reader
	config   *XHTTPConfig
	logger   *slog.Logger
	response *http.Response
	closed   bool
	mu       sync.Mutex
}

// Read reads data from the XHTTP connection, using the buffered reader
// to handle any data already read during the HTTP response parsing.
func (c *xhttpConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// Close closes the XHTTP connection and cleans up HTTP resources.
func (c *xhttpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.logger.Debug("closing xhttp connection",
		"cdn", c.config.CDNHost,
	)

	if c.response != nil && c.response.Body != nil {
		c.response.Body.Close()
	}

	return c.Conn.Close()
}

// xhttpCDNProbe tests if the CDN host is reachable and responds correctly.
type xhttpCDNProbe struct {
	cdnHost  string
	port     int
	sni      string
	provider string
}

func (p *xhttpCDNProbe) Name() string    { return "xhttp_cdn_reachability" }
func (p *xhttpCDNProbe) Weight() float64 { return 0.9 }

func (p *xhttpCDNProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()

	sni := p.sni
	if sni == "" {
		sni = p.cdnHost
	}
	addr := net.JoinHostPort(p.cdnHost, fmt.Sprintf("%d", p.port))

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error":    err.Error(),
				"cdn_host": p.cdnHost,
				"provider": p.provider,
			},
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	negotiated := state.NegotiatedProtocol

	return &core.ProbeResult{
		TestName: p.Name(),
		Success:  true,
		Latency:  time.Since(start),
		Details: map[string]string{
			"cdn_host":   p.cdnHost,
			"provider":   p.provider,
			"tls":        fmt.Sprintf("0x%04x", state.Version),
			"negotiated": negotiated,
		},
		Timestamp: time.Now(),
	}, nil
}

// xhttpHTTPProbe tests if the XHTTP endpoint responds to HTTP requests.
type xhttpHTTPProbe struct {
	cdnHost string
	port    int
	path    string
}

func (p *xhttpHTTPProbe) Name() string    { return "xhttp_http_probe" }
func (p *xhttpHTTPProbe) Weight() float64 { return 0.7 }

func (p *xhttpHTTPProbe) Run(ctx context.Context, _ string) (*core.ProbeResult, error) {
	start := time.Now()

	url := fmt.Sprintf("https://%s:%d%s", p.cdnHost, p.port, p.path)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: p.cdnHost,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build probe request: %w", err)
	}
	req.Header.Set("User-Agent", chromeUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return &core.ProbeResult{
			TestName: p.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error": err.Error(),
				"url":   url,
			},
			Timestamp: time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	// Any response (even 400/404) means the CDN path is reachable.
	return &core.ProbeResult{
		TestName: p.Name(),
		Success:  resp.StatusCode < 500,
		Latency:  time.Since(start),
		Details: map[string]string{
			"status": fmt.Sprintf("%d", resp.StatusCode),
			"server": resp.Header.Get("Server"),
			"url":    url,
		},
		Timestamp: time.Now(),
	}, nil
}

// chromeUserAgent returns a current Chrome user agent string for
// blending in with real browser traffic.
func chromeUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
}

// buildVLESSHeader constructs a VLESS protocol header for the given
// UUID and destination.
func buildVLESSHeader(uuid [16]byte, host string, port int) []byte {
	var header []byte

	// Version byte.
	header = append(header, vlessVersion)

	// UUID (16 bytes).
	header = append(header, uuid[:]...)

	// No addon.
	header = append(header, 0)

	// Command: TCP (0x01).
	header = append(header, 0x01)

	// Destination port (big-endian).
	header = append(header, byte(port>>8), byte(port&0xFF))

	// Address type and address.
	hostIP := net.ParseIP(host)
	if hostIP != nil {
		if ipv4 := hostIP.To4(); ipv4 != nil {
			header = append(header, 0x01)
			header = append(header, ipv4...)
		} else {
			header = append(header, 0x03)
			header = append(header, hostIP.To16()...)
		}
	} else {
		header = append(header, 0x02)
		header = append(header, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	return header
}

// parseUUID parses a UUID string (with or without hyphens) into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte

	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}
	if len(clean) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(clean))
	}

	b, err := hex.DecodeString(clean)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}
	copy(uuid[:], b)
	return uuid, nil
}
