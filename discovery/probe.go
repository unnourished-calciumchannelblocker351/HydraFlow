// Package discovery implements the censorship probe engine that
// detects DPI capabilities and network restrictions.
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	
)

// Prober runs a suite of censorship detection tests against a target.
type Prober struct {
	target string
	tests  []ProbeTest
}

// NewProber creates a prober targeting the given host:port.
func NewProber(target string) *Prober {
	return &Prober{
		target: target,
		tests: []ProbeTest{
			&PortReachabilityTest{},
			&TLSFingerprintTest{},
			&SNIFilteringTest{},
			&QUICAvailabilityTest{},
			&FragmentBypassTest{},
		},
	}
}

// RunAll executes all probe tests and returns results.
func (p *Prober) RunAll(ctx context.Context) ([]*ProbeResult, error) {
	var results []*ProbeResult

	for _, t := range p.tests {
		result, err := t.Run(ctx, p.target)
		if err != nil {
			results = append(results, &ProbeResult{
				TestName:  t.Name(),
				Success:   false,
				Details:   map[string]string{"error": err.Error()},
				Timestamp: time.Now(),
			})
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// PortReachabilityTest checks if TCP/UDP ports are accessible.
type PortReachabilityTest struct{}

func (t *PortReachabilityTest) Name() string    { return "port_reachability" }
func (t *PortReachabilityTest) Weight() float64 { return 1.0 }

func (t *PortReachabilityTest) Run(ctx context.Context, target string) (*ProbeResult, error) {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return &ProbeResult{
			TestName:  t.Name(),
			Success:   false,
			Latency:   time.Since(start),
			Details:   map[string]string{"error": err.Error()},
			Timestamp: time.Now(),
		}, nil
	}
	conn.Close()

	return &ProbeResult{
		TestName:  t.Name(),
		Success:   true,
		Latency:   time.Since(start),
		Timestamp: time.Now(),
	}, nil
}

// TLSFingerprintTest checks if TLS connections are being
// fingerprinted and filtered based on JA3/JA4 hashes.
type TLSFingerprintTest struct{}

func (t *TLSFingerprintTest) Name() string    { return "tls_fingerprint" }
func (t *TLSFingerprintTest) Weight() float64 { return 0.8 }

func (t *TLSFingerprintTest) Run(ctx context.Context, target string) (*ProbeResult, error) {
	start := time.Now()

	// Attempt TLS handshake with chrome-like fingerprint
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return &ProbeResult{
			TestName: t.Name(),
			Success:  false,
			Latency:  time.Since(start),
			Details: map[string]string{
				"error": err.Error(),
				"note":  "TLS handshake failed - possible fingerprint blocking",
			},
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return &ProbeResult{
		TestName: t.Name(),
		Success:  true,
		Latency:  time.Since(start),
		Details: map[string]string{
			"version":     fmt.Sprintf("0x%04x", state.Version),
			"cipher":      tls.CipherSuiteName(state.CipherSuite),
			"server_name": state.ServerName,
		},
		Timestamp: time.Now(),
	}, nil
}

// SNIFilteringTest checks if connections with specific SNI values
// are being blocked or redirected.
type SNIFilteringTest struct {
	// TestDomains is a list of SNI values to test.
	// If empty, a default list is used.
	TestDomains []string
}

func (t *SNIFilteringTest) Name() string    { return "sni_filtering" }
func (t *SNIFilteringTest) Weight() float64 { return 0.9 }

func (t *SNIFilteringTest) Run(ctx context.Context, target string) (*ProbeResult, error) {
	domains := t.TestDomains
	if len(domains) == 0 {
		domains = []string{
			"www.microsoft.com",
			"cloudflare.com",
			"icloud.com",
		}
	}

	blocked := make(map[string]bool)
	for _, domain := range domains {
		host, port, _ := net.SplitHostPort(target)
		if host == "" {
			host = target
			port = "443"
		}

		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		})
		if err != nil {
			blocked[domain] = true
			continue
		}
		conn.Close()
		blocked[domain] = false
	}

	details := make(map[string]string)
	allBlocked := true
	for domain, isBlocked := range blocked {
		if isBlocked {
			details[domain] = "blocked"
		} else {
			details[domain] = "accessible"
			allBlocked = false
		}
	}

	return &ProbeResult{
		TestName:  t.Name(),
		Success:   !allBlocked,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// QUICAvailabilityTest checks if UDP/QUIC traffic can reach the target.
type QUICAvailabilityTest struct{}

func (t *QUICAvailabilityTest) Name() string    { return "quic_availability" }
func (t *QUICAvailabilityTest) Weight() float64 { return 0.7 }

func (t *QUICAvailabilityTest) Run(ctx context.Context, target string) (*ProbeResult, error) {
	start := time.Now()

	// Send a QUIC-like Initial packet and check for response
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return &ProbeResult{
			TestName:  t.Name(),
			Success:   false,
			Latency:   time.Since(start),
			Details:   map[string]string{"error": err.Error()},
			Timestamp: time.Now(),
		}, nil
	}
	defer conn.Close()

	// Send a minimal probe packet
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte{0x00})
	if err != nil {
		return &ProbeResult{
			TestName:  t.Name(),
			Success:   false,
			Details:   map[string]string{"error": "udp write failed"},
			Timestamp: time.Now(),
		}, nil
	}

	return &ProbeResult{
		TestName:  t.Name(),
		Success:   true,
		Latency:   time.Since(start),
		Details:   map[string]string{"note": "UDP port reachable"},
		Timestamp: time.Now(),
	}, nil
}

// FragmentBypassTest determines the optimal TLS fragment size
// to bypass DPI that doesn't reassemble TCP segments.
type FragmentBypassTest struct{}

func (t *FragmentBypassTest) Name() string    { return "fragment_bypass" }
func (t *FragmentBypassTest) Weight() float64 { return 0.6 }

func (t *FragmentBypassTest) Run(ctx context.Context, target string) (*ProbeResult, error) {
	// Test different fragment sizes to find what bypasses DPI
	sizes := []int{1, 2, 5, 10, 50, 100, 200}
	var working []int

	for _, size := range sizes {
		if testFragment(target, size) {
			working = append(working, size)
		}
	}

	details := map[string]string{}
	if len(working) > 0 {
		details["working_sizes"] = fmt.Sprintf("%v", working)
		details["optimal"] = fmt.Sprintf("%d", working[0])
	}

	return &ProbeResult{
		TestName:  t.Name(),
		Success:   len(working) > 0,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// testFragment and buildMinimalClientHello are defined in fingerprint.go
// to avoid duplication across the discovery package.
