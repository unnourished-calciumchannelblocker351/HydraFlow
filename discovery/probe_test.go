package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// startTCPServer creates a local TCP server for testing.
// Returns the address and a cleanup function.
func startTCPServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start TCP server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				c.Read(buf)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// startTLSServer creates a local TLS server for testing.
func startTLSServer(t *testing.T) (string, func()) {
	t.Helper()

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				c.Read(buf)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

// startUDPServer creates a local UDP server for testing.
func startUDPServer(t *testing.T) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to start UDP server: %v", err)
	}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], remoteAddr)
		}
	}()

	return conn.LocalAddr().String(), func() { conn.Close() }
}

func TestPortReachabilityTestReachable(t *testing.T) {
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	test := &PortReachabilityTest{}

	if name := test.Name(); name != "port_reachability" {
		t.Errorf("Name() = %q, want %q", name, "port_reachability")
	}
	if w := test.Weight(); w != 1.0 {
		t.Errorf("Weight() = %f, want 1.0", w)
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !result.Success {
		t.Error("expected success for reachable port")
	}
	if result.Latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestPortReachabilityTestUnreachable(t *testing.T) {
	// Use a port that is very unlikely to be open.
	test := &PortReachabilityTest{}
	result, err := test.Run(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for unreachable port")
	}
	if result.Details["error"] == "" {
		t.Error("expected error details")
	}
}

func TestTLSFingerprintTestSuccess(t *testing.T) {
	addr, cleanup := startTLSServer(t)
	defer cleanup()

	test := &TLSFingerprintTest{}

	if name := test.Name(); name != "tls_fingerprint" {
		t.Errorf("Name() = %q, want %q", name, "tls_fingerprint")
	}
	if w := test.Weight(); w != 0.8 {
		t.Errorf("Weight() = %f, want 0.8", w)
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got failure: %v", result.Details)
	}
	if result.Details["version"] == "" {
		t.Error("expected TLS version in details")
	}
	if result.Details["cipher"] == "" {
		t.Error("expected cipher suite in details")
	}
}

func TestTLSFingerprintTestFailure(t *testing.T) {
	// Plain TCP server, no TLS.
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	test := &TLSFingerprintTest{}
	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for non-TLS server")
	}
	if result.Details["note"] == "" {
		t.Error("expected blocking note in details")
	}
}

func TestSNIFilteringTestAllAccessible(t *testing.T) {
	addr, cleanup := startTLSServer(t)
	defer cleanup()

	test := &SNIFilteringTest{}

	if name := test.Name(); name != "sni_filtering" {
		t.Errorf("Name() = %q, want %q", name, "sni_filtering")
	}
	if w := test.Weight(); w != 0.9 {
		t.Errorf("Weight() = %f, want 0.9", w)
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success when all domains are accessible, got details: %v", result.Details)
	}
}

func TestSNIFilteringTestCustomDomains(t *testing.T) {
	addr, cleanup := startTLSServer(t)
	defer cleanup()

	test := &SNIFilteringTest{
		TestDomains: []string{"example.com", "test.org"},
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// Both should be accessible on a local TLS server.
	if result.Details["example.com"] != "accessible" {
		t.Errorf("example.com should be accessible, got %s", result.Details["example.com"])
	}
	if result.Details["test.org"] != "accessible" {
		t.Errorf("test.org should be accessible, got %s", result.Details["test.org"])
	}
}

func TestSNIFilteringTestNoServer(t *testing.T) {
	test := &SNIFilteringTest{
		TestDomains: []string{"example.com"},
	}

	result, err := test.Run(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	// All should be blocked (unreachable).
	if result.Success {
		t.Error("expected failure for unreachable target")
	}
}

func TestQUICAvailabilityTestReachable(t *testing.T) {
	addr, cleanup := startUDPServer(t)
	defer cleanup()

	test := &QUICAvailabilityTest{}

	if name := test.Name(); name != "quic_availability" {
		t.Errorf("Name() = %q, want %q", name, "quic_availability")
	}
	if w := test.Weight(); w != 0.7 {
		t.Errorf("Weight() = %f, want 0.7", w)
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success for reachable UDP port, got: %v", result.Details)
	}
}

func TestQUICAvailabilityTestInvalidTarget(t *testing.T) {
	test := &QUICAvailabilityTest{}
	_, err := test.Run(context.Background(), "not-a-valid-address")
	if err == nil {
		t.Error("expected error for invalid target address")
	}
}

func TestFragmentBypassTestLocalServer(t *testing.T) {
	test := &FragmentBypassTest{}

	if name := test.Name(); name != "fragment_bypass" {
		t.Errorf("Name() = %q, want %q", name, "fragment_bypass")
	}
	if w := test.Weight(); w != 0.6 {
		t.Errorf("Weight() = %f, want 0.6", w)
	}

	// Test against a non-existent server — fragments won't work.
	result, err := test.Run(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if result.Success {
		t.Error("expected failure for unreachable target")
	}
}

func TestProberRunAll(t *testing.T) {
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	prober := NewProber(addr)

	results, err := prober.RunAll(context.Background())
	if err != nil {
		t.Fatalf("RunAll() error: %v", err)
	}

	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	}

	// Port reachability should succeed.
	found := false
	for _, r := range results {
		if r.TestName == "port_reachability" {
			found = true
			if !r.Success {
				t.Error("port_reachability should succeed for local TCP server")
			}
		}
	}
	if !found {
		t.Error("port_reachability test not found in results")
	}
}

func TestProberRunAllContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	prober := NewProber("127.0.0.1:1")
	results, err := prober.RunAll(ctx)
	if err != nil {
		t.Fatalf("RunAll() error: %v", err)
	}

	// Most tests should fail with cancelled context.
	// UDP-based tests (QUIC) may still succeed since UDP dial is connectionless.
	for _, r := range results {
		if r.Success && r.TestName != "quic_availability" {
			t.Errorf("test %s should not succeed with cancelled context", r.TestName)
		}
	}
}

func TestProberTestNames(t *testing.T) {
	prober := NewProber("127.0.0.1:443")

	expectedNames := map[string]bool{
		"port_reachability": true,
		"tls_fingerprint":   true,
		"sni_filtering":     true,
		"quic_availability": true,
		"fragment_bypass":   true,
	}

	for _, test := range prober.tests {
		if !expectedNames[test.Name()] {
			t.Errorf("unexpected test name: %s", test.Name())
		}
		delete(expectedNames, test.Name())
	}

	for name := range expectedNames {
		t.Errorf("missing test: %s", name)
	}
}

func TestProberTestWeights(t *testing.T) {
	prober := NewProber("127.0.0.1:443")

	for _, test := range prober.tests {
		w := test.Weight()
		if w < 0 || w > 1.0 {
			t.Errorf("test %s has invalid weight %f (must be 0.0-1.0)", test.Name(), w)
		}
	}
}

func TestPortReachabilityTestTimestamp(t *testing.T) {
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	before := time.Now()
	test := &PortReachabilityTest{}
	result, err := test.Run(context.Background(), addr)
	after := time.Now()

	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if result.Timestamp.Before(before) || result.Timestamp.After(after) {
		t.Errorf("timestamp %v not between %v and %v", result.Timestamp, before, after)
	}
}

func TestBuildMinimalClientHello(t *testing.T) {
	hello := buildMinimalClientHello()

	if len(hello) < 10 {
		t.Errorf("ClientHello too short: %d bytes", len(hello))
	}

	// First byte should be TLS record type (0x16 = handshake).
	if hello[0] != 0x16 {
		t.Errorf("expected TLS handshake record type 0x16, got 0x%02x", hello[0])
	}

	// Bytes 1-2 should be TLS version (0x03, 0x01 = TLS 1.0 record layer).
	if hello[1] != 0x03 || hello[2] != 0x01 {
		t.Errorf("unexpected record version: 0x%02x 0x%02x", hello[1], hello[2])
	}
}

func TestSNIFilteringTestResultFormat(t *testing.T) {
	addr, cleanup := startTLSServer(t)
	defer cleanup()

	test := &SNIFilteringTest{
		TestDomains: []string{"test1.com", "test2.com", "test3.com"},
	}

	result, err := test.Run(context.Background(), addr)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Verify all domains are in the details.
	for _, domain := range test.TestDomains {
		status, ok := result.Details[domain]
		if !ok {
			t.Errorf("domain %s missing from details", domain)
			continue
		}
		if status != "accessible" && status != "blocked" {
			t.Errorf("domain %s has unexpected status: %s", domain, status)
		}
	}
}

func TestMultipleProbers(t *testing.T) {
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	// Run multiple probers concurrently.
	const n = 5
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(id int) {
			prober := NewProber(addr)
			results, err := prober.RunAll(context.Background())
			if err != nil {
				errs <- fmt.Errorf("prober %d: %w", id, err)
				return
			}
			if len(results) == 0 {
				errs <- fmt.Errorf("prober %d: no results", id)
				return
			}
			errs <- nil
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

var localhostCert []byte
var localhostKey []byte

func init() {
	// Generate a valid self-signed cert for testing at startup.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate test key: " + err.Error())
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic("failed to create test cert: " + err.Error())
	}

	localhostCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("failed to marshal test key: " + err.Error())
	}
	localhostKey = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
