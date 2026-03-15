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

// NetworkProfile contains the detected network characteristics.
// The bypass engine uses this to auto-configure the optimal set
// of techniques.
type NetworkProfile struct {
	// FragmentEffective is true when TLS fragmentation bypasses DPI.
	FragmentEffective bool `json:"fragment_effective"`

	// OptimalFragmentSize is the smallest fragment size that worked.
	OptimalFragmentSize int `json:"optimal_fragment_size"`

	// WorkingFragmentSizes lists all fragment sizes that bypassed DPI.
	WorkingFragmentSizes []int `json:"working_fragment_sizes"`

	// QUICAvailable is true when UDP/QUIC traffic reaches the target.
	QUICAvailable bool `json:"quic_available"`

	// BlockedProtocols lists protocol names detected as blocked.
	BlockedProtocols []string `json:"blocked_protocols"`

	// BlockedSNIs lists SNI domains that triggered blocking.
	BlockedSNIs []string `json:"blocked_snis"`

	// WorkingSNIs lists SNI domains that passed through.
	WorkingSNIs []string `json:"working_snis"`

	// TLS13Available is true when TLS 1.3 connections succeed.
	TLS13Available bool `json:"tls13_available"`

	// ResetOnBlock is true when the DPI sends TCP RST on block.
	ResetOnBlock bool `json:"reset_on_block"`

	// EstimatedDPILatency is the additional latency introduced by DPI.
	EstimatedDPILatency time.Duration `json:"estimated_dpi_latency"`

	// TCPDirectWorks is true when plain TCP without TLS works.
	TCPDirectWorks bool `json:"tcp_direct_works"`

	// CDNReachable is true when CDN endpoints (Cloudflare, etc.) work.
	CDNReachable bool `json:"cdn_reachable"`

	// ProbeTimestamp records when the probe was run.
	ProbeTimestamp time.Time `json:"probe_timestamp"`

	// ConfidenceScore is 0.0–1.0 indicating probe reliability.
	ConfidenceScore float64 `json:"confidence_score"`
}

// NetworkProber runs comprehensive network censorship detection.
type NetworkProber struct {
	target string
	logger *slog.Logger
}

// NewNetworkProber creates a prober targeting the given host:port.
func NewNetworkProber(target string, logger *slog.Logger) *NetworkProber {
	if logger == nil {
		logger = slog.Default()
	}
	return &NetworkProber{
		target: target,
		logger: logger.With("component", "probe"),
	}
}

// Probe runs all detection tests and returns a network profile.
func (p *NetworkProber) Probe(ctx context.Context) (*NetworkProfile, error) {
	profile := &NetworkProfile{
		ProbeTimestamp: time.Now(),
	}

	type probeResult struct {
		name string
		fn   func(ctx context.Context) error
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	testsRun := 0
	testsPassed := 0

	// Define all probes.
	probes := []probeResult{
		{"tcp_direct", func(ctx context.Context) error {
			ok := p.probeTCPDirect(ctx)
			mu.Lock()
			profile.TCPDirectWorks = ok
			testsRun++
			if ok {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"tls13", func(ctx context.Context) error {
			ok := p.probeTLS13(ctx)
			mu.Lock()
			profile.TLS13Available = ok
			testsRun++
			if ok {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"quic", func(ctx context.Context) error {
			ok := p.probeQUIC(ctx)
			mu.Lock()
			profile.QUICAvailable = ok
			testsRun++
			if ok {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"fragment", func(ctx context.Context) error {
			effective, optimal, working := p.probeFragment(ctx)
			mu.Lock()
			profile.FragmentEffective = effective
			profile.OptimalFragmentSize = optimal
			profile.WorkingFragmentSizes = working
			testsRun++
			if effective {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"sni", func(ctx context.Context) error {
			blocked, working := p.probeSNI(ctx)
			mu.Lock()
			profile.BlockedSNIs = blocked
			profile.WorkingSNIs = working
			testsRun++
			if len(working) > 0 {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"cdn", func(ctx context.Context) error {
			ok := p.probeCDN(ctx)
			mu.Lock()
			profile.CDNReachable = ok
			testsRun++
			if ok {
				testsPassed++
			}
			mu.Unlock()
			return nil
		}},
		{"rst_detection", func(ctx context.Context) error {
			rst := p.probeRST(ctx)
			mu.Lock()
			profile.ResetOnBlock = rst
			testsRun++
			testsPassed++ // detection itself always succeeds
			mu.Unlock()
			return nil
		}},
		{"dpi_latency", func(ctx context.Context) error {
			latency := p.probeDPILatency(ctx)
			mu.Lock()
			profile.EstimatedDPILatency = latency
			testsRun++
			testsPassed++
			mu.Unlock()
			return nil
		}},
	}

	// Run all probes in parallel.
	for _, probe := range probes {
		wg.Add(1)
		go func(pr probeResult) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			p.logger.Debug("running probe", "name", pr.name)
			if err := pr.fn(probeCtx); err != nil {
				p.logger.Warn("probe error", "name", pr.name, "error", err)
			}
		}(probe)
	}

	wg.Wait()

	// Calculate confidence.
	if testsRun > 0 {
		profile.ConfidenceScore = float64(testsPassed) / float64(testsRun)
	}

	return profile, nil
}

// probeTCPDirect checks if plain TCP connections work.
func (p *NetworkProber) probeTCPDirect(ctx context.Context) bool {
	conn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		p.logger.Debug("TCP direct failed", "error", err)
		return false
	}
	conn.Close()
	return true
}

// probeTLS13 checks if TLS 1.3 connections succeed.
func (p *NetworkProber) probeTLS13(ctx context.Context) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", p.target, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		p.logger.Debug("TLS 1.3 failed", "error", err)
		return false
	}
	conn.Close()
	return true
}

// probeQUIC checks if UDP/QUIC traffic reaches the target.
func (p *NetworkProber) probeQUIC(ctx context.Context) bool {
	addr, err := net.ResolveUDPAddr("udp", p.target)
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send a QUIC-like Initial packet.
	probe := make([]byte, 64)
	probe[0] = 0xC0 // Long header
	probe[1] = 0x00
	probe[2] = 0x00
	probe[3] = 0x00
	probe[4] = 0x01 // Version 1
	probe[5] = 0x08 // DCID length

	_, err = conn.Write(probe)
	if err != nil {
		return false
	}

	// Any response (even ICMP unreachable) indicates reachability.
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return n > 0
}

// probeFragment tests different fragment sizes and reports which work.
func (p *NetworkProber) probeFragment(ctx context.Context) (effective bool, optimal int, working []int) {
	sizes := []int{1, 2, 3, 5, 10, 50, 100, 200, 500, 1000}

	type result struct {
		size int
		ok   bool
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []result

	for _, size := range sizes {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			ok := p.testFragmentSize(s)
			mu.Lock()
			results = append(results, result{s, ok})
			mu.Unlock()
		}(size)
	}

	wg.Wait()

	for _, r := range results {
		if r.ok {
			working = append(working, r.size)
			if optimal == 0 || r.size < optimal {
				optimal = r.size
			}
		}
	}

	effective = len(working) > 0
	return
}

// testFragmentSize tests if a specific fragment size bypasses DPI.
func (p *NetworkProber) testFragmentSize(size int) bool {
	conn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Build a minimal TLS ClientHello.
	hello := buildMinimalClientHelloForProbe()
	if size <= 0 || size >= len(hello) {
		_, err = conn.Write(hello)
		return err == nil
	}

	// Write in fragments.
	for i := 0; i < len(hello); i += size {
		end := i + size
		if end > len(hello) {
			end = len(hello)
		}
		if _, err := conn.Write(hello[i:end]); err != nil {
			return false
		}
		time.Sleep(1 * time.Millisecond)
	}

	// Check for a response.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return n > 0
}

// probeSNI tests various SNI domains to determine which are blocked.
func (p *NetworkProber) probeSNI(ctx context.Context) (blocked, working []string) {
	// Test a mix of critical Russian domains and global CDN domains.
	testDomains := []string{
		"gosuslugi.ru",
		"ya.ru",
		"sberbank.ru",
		"vk.com",
		"www.google.com",
		"www.microsoft.com",
		"cloudflare.com",
		"www.apple.com",
		"icloud.com",
	}

	host, port, err := net.SplitHostPort(p.target)
	if err != nil {
		host = p.target
		port = "443"
	}

	type result struct {
		domain string
		ok     bool
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []result

	for _, domain := range testDomains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			addr := net.JoinHostPort(host, port)
			ok := p.testSNIDomain(addr, d)
			mu.Lock()
			results = append(results, result{d, ok})
			mu.Unlock()
		}(domain)
	}

	wg.Wait()

	for _, r := range results {
		if r.ok {
			working = append(working, r.domain)
		} else {
			blocked = append(blocked, r.domain)
		}
	}

	return
}

// testSNIDomain tests if a TLS handshake with a specific SNI succeeds.
func (p *NetworkProber) testSNIDomain(addr, sni string) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeCDN checks if CDN endpoints are reachable.
func (p *NetworkProber) probeCDN(ctx context.Context) bool {
	cdnHosts := []string{
		"cloudflare.com:443",
		"cdn.cloudflare.com:443",
	}

	for _, host := range cdnHosts {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// probeRST checks if the DPI sends TCP RST packets on block.
func (p *NetworkProber) probeRST(ctx context.Context) bool {
	conn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		if isRSTError(err) {
			return true
		}
		return false
	}
	defer conn.Close()

	// Send a suspicious-looking payload to trigger DPI.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"))
	if err != nil && isRSTError(err) {
		return true
	}

	buf := make([]byte, 256)
	_, err = conn.Read(buf)
	return err != nil && isRSTError(err)
}

// probeDPILatency measures the latency overhead introduced by DPI.
func (p *NetworkProber) probeDPILatency(ctx context.Context) time.Duration {
	const trials = 5
	var latencies []time.Duration

	for i := 0; i < trials; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", p.target, 5*time.Second)
		if err != nil {
			continue
		}
		latencies = append(latencies, time.Since(start))
		conn.Close()
	}

	if len(latencies) == 0 {
		return 0
	}

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	return sum / time.Duration(len(latencies))
}

// buildMinimalClientHelloForProbe constructs a TLS ClientHello for
// fragment probing.
func buildMinimalClientHelloForProbe() []byte {
	return []byte{
		0x16, 0x03, 0x01, 0x00, 0x2f, // record: handshake, TLS 1.0, length=47
		0x01, 0x00, 0x00, 0x2b, // handshake: client_hello, length=43
		0x03, 0x03, // version: TLS 1.2
		// 32 bytes random
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x00,       // session id length: 0
		0x00, 0x02, // cipher suites length: 2
		0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0x01, 0x00, // compression methods: null
	}
}

// ProbeSummary returns a human-readable summary of the network profile.
func ProbeSummary(p *NetworkProfile) string {
	if p == nil {
		return "no probe results available"
	}

	summary := fmt.Sprintf(
		"Network Profile (confidence=%.0f%%):\n"+
			"  TCP Direct: %v\n"+
			"  TLS 1.3: %v\n"+
			"  QUIC/UDP: %v\n"+
			"  CDN Reachable: %v\n"+
			"  Fragment Bypass: %v (optimal=%d)\n"+
			"  RST on Block: %v\n"+
			"  DPI Latency: %s\n"+
			"  Blocked SNIs: %v\n"+
			"  Working SNIs: %v\n"+
			"  Probed: %s",
		p.ConfidenceScore*100,
		p.TCPDirectWorks,
		p.TLS13Available,
		p.QUICAvailable,
		p.CDNReachable,
		p.FragmentEffective, p.OptimalFragmentSize,
		p.ResetOnBlock,
		p.EstimatedDPILatency,
		p.BlockedSNIs,
		p.WorkingSNIs,
		p.ProbeTimestamp.Format(time.RFC3339),
	)
	return summary
}
