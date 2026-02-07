package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DPICapability represents a specific DPI feature.
type DPICapability int

const (
	// CapSNIFiltering means the DPI inspects TLS SNI fields.
	CapSNIFiltering DPICapability = 1 << iota
	// CapTLSFingerprinting means the DPI fingerprints TLS ClientHello.
	CapTLSFingerprinting
	// CapQUICBlocking means the DPI blocks QUIC/UDP traffic.
	CapQUICBlocking
	// CapFragmentReassembly means the DPI reassembles TCP fragments.
	CapFragmentReassembly
	// CapActiveProbing means the DPI actively probes suspected proxies.
	CapActiveProbing
	// CapHTTPFiltering means the DPI inspects HTTP content.
	CapHTTPFiltering
	// CapTimingAnalysis means the DPI uses timing-based detection.
	CapTimingAnalysis
	// CapCipherFiltering means the DPI filters based on cipher suites.
	CapCipherFiltering
)

// DPIVendor identifies a known DPI system.
type DPIVendor string

const (
	VendorUnknown    DPIVendor = "unknown"
	VendorTPDPI      DPIVendor = "tpdpi"      // generic TP-based DPI
	VendorTSPU       DPIVendor = "tspu"       // Roskomnadzor TSPU (Russia)
	VendorGFW        DPIVendor = "gfw"        // Great Firewall (China)
	VendorSandvine   DPIVendor = "sandvine"   // Sandvine PacketLogic (Iran, Turkey, Egypt)
	VendorFortinet   DPIVendor = "fortinet"   // Fortinet FortiGuard (UAE, Saudi Arabia)
	VendorPaloAlto   DPIVendor = "paloalto"   // Palo Alto Networks (enterprise, UAE)
	VendorAllot      DPIVendor = "allot"      // Allot Communications (ISP-level, multiple countries)
	VendorNetsweeper DPIVendor = "netsweeper" // Netsweeper (Pakistan, Qatar, Yemen)
	VendorHuawei     DPIVendor = "huawei"     // Huawei eSight/iManager (Central Asia, Africa)
)

// DPIProfile describes the detected DPI system and its capabilities.
type DPIProfile struct {
	// Vendor is the identified DPI vendor, if known.
	Vendor DPIVendor `json:"vendor"`

	// Capabilities is a bitmask of detected DPI features.
	Capabilities DPICapability `json:"capabilities"`

	// TLSVersions lists which TLS versions are allowed through.
	TLSVersions []uint16 `json:"tls_versions,omitempty"`

	// BlockedCiphers lists cipher suites that are filtered.
	BlockedCiphers []uint16 `json:"blocked_ciphers,omitempty"`

	// AllowedCiphers lists cipher suites that pass through.
	AllowedCiphers []uint16 `json:"allowed_ciphers,omitempty"`

	// SNIBehavior describes how SNI filtering works.
	SNIBehavior string `json:"sni_behavior,omitempty"`

	// FragmentThreshold is the minimum fragment size the DPI handles.
	// Fragments smaller than this bypass the DPI.
	FragmentThreshold int `json:"fragment_threshold,omitempty"`

	// QUICBlocked indicates whether QUIC traffic is blocked.
	QUICBlocked bool `json:"quic_blocked"`

	// ResetOnBlock indicates whether the DPI sends TCP RST on block.
	ResetOnBlock bool `json:"reset_on_block"`

	// TypicalLatency is the DPI-induced latency overhead.
	TypicalLatency time.Duration `json:"typical_latency,omitempty"`

	// Confidence is the overall confidence in the profile (0.0 to 1.0).
	Confidence float64 `json:"confidence"`

	// RawResults holds the individual test results.
	RawResults []FingerprintResult `json:"raw_results,omitempty"`
}

// HasCapability checks if the profile includes a specific DPI capability.
func (p *DPIProfile) HasCapability(cap DPICapability) bool {
	return p.Capabilities&cap != 0
}

// FingerprintResult is the outcome of a single fingerprinting test.
type FingerprintResult struct {
	TestName string            `json:"test_name"`
	Detected bool              `json:"detected"`
	Details  map[string]string `json:"details,omitempty"`
	Duration time.Duration     `json:"duration"`
}

// Fingerprinter detects which DPI system is in use based on
// behavioral patterns. It runs a suite of tests that probe
// different DPI detection methods.
type Fingerprinter struct {
	target  string
	timeout time.Duration
}

// NewFingerprinter creates a DPI fingerprinter targeting the given host:port.
func NewFingerprinter(target string) *Fingerprinter {
	return &Fingerprinter{
		target:  target,
		timeout: 10 * time.Second,
	}
}

// SetTimeout changes the per-test timeout.
func (f *Fingerprinter) SetTimeout(d time.Duration) {
	f.timeout = d
}

// Fingerprint runs all DPI detection tests and returns a profile.
func (f *Fingerprinter) Fingerprint(ctx context.Context) (*DPIProfile, error) {
	profile := &DPIProfile{
		Vendor: VendorUnknown,
	}

	type testFunc struct {
		name string
		fn   func(ctx context.Context) FingerprintResult
	}

	tests := []testFunc{
		{"tls_version_support", f.testTLSVersions},
		{"cipher_suite_filtering", f.testCipherFiltering},
		{"sni_blocking", f.testSNIBlocking},
		{"fragment_handling", f.testFragmentHandling},
		{"quic_blocking", f.testQUICBlocking},
		{"timing_analysis", f.testTimingAnalysis},
		{"reset_behavior", f.testResetBehavior},
		{"active_probing", f.testActiveProbing},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, test := range tests {
		wg.Add(1)
		go func(t testFunc) {
			defer wg.Done()
			testCtx, cancel := context.WithTimeout(ctx, f.timeout)
			defer cancel()

			result := t.fn(testCtx)
			result.TestName = t.name

			mu.Lock()
			profile.RawResults = append(profile.RawResults, result)
			mu.Unlock()
		}(test)
	}

	wg.Wait()

	// Analyze results to build the profile.
	f.analyzeResults(profile)

	return profile, nil
}

// testTLSVersions checks which TLS versions are allowed through.
func (f *Fingerprinter) testTLSVersions(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	versions := []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"tls10", tls.VersionTLS10, tls.VersionTLS10},
		{"tls11", tls.VersionTLS11, tls.VersionTLS11},
		{"tls12", tls.VersionTLS12, tls.VersionTLS12},
		{"tls13", tls.VersionTLS13, tls.VersionTLS13},
	}

	var allowed []uint16
	for _, v := range versions {
		if f.tryTLSVersion(ctx, v.min, v.max) {
			details[v.name] = "allowed"
			allowed = append(allowed, v.min)
		} else {
			details[v.name] = "blocked"
		}
	}

	// If some versions are blocked, DPI is likely filtering.
	detected := len(allowed) > 0 && len(allowed) < len(versions)

	return FingerprintResult{
		Detected: detected,
		Details:  details,
		Duration: time.Since(start),
	}
}

// tryTLSVersion attempts a TLS handshake with a specific version.
func (f *Fingerprinter) tryTLSVersion(ctx context.Context, minVer, maxVer uint16) bool {
	deadline, ok := ctx.Deadline()
	timeout := 5 * time.Second
	if ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", f.target, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// testCipherFiltering checks if specific cipher suites are being blocked.
func (f *Fingerprinter) testCipherFiltering(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	// Test a selection of cipher suites.
	testCiphers := []struct {
		name string
		id   uint16
	}{
		{"TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256},
		{"TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384},
		{"TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	var blocked []uint16
	var allowed []uint16

	for _, c := range testCiphers {
		if f.tryCipherSuite(ctx, c.id) {
			details[c.name] = "allowed"
			allowed = append(allowed, c.id)
		} else {
			details[c.name] = "blocked"
			blocked = append(blocked, c.id)
		}
	}

	detected := len(blocked) > 0 && len(allowed) > 0

	return FingerprintResult{
		Detected: detected,
		Details:  details,
		Duration: time.Since(start),
	}
}

// tryCipherSuite attempts a TLS 1.2 handshake with a specific cipher.
func (f *Fingerprinter) tryCipherSuite(ctx context.Context, cipherID uint16) bool {
	deadline, ok := ctx.Deadline()
	timeout := 5 * time.Second
	if ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", f.target, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{cipherID},
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// testSNIBlocking checks if specific SNI values trigger blocking.
func (f *Fingerprinter) testSNIBlocking(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	// Test with various SNI values: known-benign, known-blocked, empty, random.
	sniTests := []struct {
		name string
		sni  string
	}{
		{"benign_microsoft", "www.microsoft.com"},
		{"benign_cloudflare", "cloudflare.com"},
		{"benign_apple", "www.apple.com"},
		{"empty_sni", ""},
		{"random_sni", "xn--random-test-" + randomHex(4) + ".example.com"},
	}

	host, port, err := net.SplitHostPort(f.target)
	if err != nil {
		host = f.target
		port = "443"
	}

	blockedCount := 0
	for _, test := range sniTests {
		if f.trySNI(ctx, host, port, test.sni) {
			details[test.name] = "accessible"
		} else {
			details[test.name] = "blocked"
			blockedCount++
		}
	}

	detected := blockedCount > 0 && blockedCount < len(sniTests)

	// Determine SNI behavior.
	if detected {
		if details["empty_sni"] == "accessible" {
			details["behavior"] = "sni_value_based"
		} else {
			details["behavior"] = "sni_required"
		}
	}

	return FingerprintResult{
		Detected: detected,
		Details:  details,
		Duration: time.Since(start),
	}
}

// trySNI attempts a TLS handshake with a specific SNI value.
func (f *Fingerprinter) trySNI(ctx context.Context, host, port, sni string) bool {
	deadline, ok := ctx.Deadline()
	timeout := 5 * time.Second
	if ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// testFragmentHandling checks if the DPI reassembles TCP fragments.
func (f *Fingerprinter) testFragmentHandling(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	sizes := []int{1, 2, 5, 10, 50, 100, 200, 500}
	var working []int
	var blocked []int

	for _, size := range sizes {
		if testFragment(f.target, size) {
			working = append(working, size)
		} else {
			blocked = append(blocked, size)
		}
	}

	details["working_sizes"] = fmt.Sprintf("%v", working)
	details["blocked_sizes"] = fmt.Sprintf("%v", blocked)

	threshold := 0
	if len(working) > 0 && len(blocked) > 0 {
		// Find the boundary between working and blocked sizes.
		threshold = working[0]
		details["threshold"] = fmt.Sprintf("%d", threshold)
	}

	// DPI fragment reassembly detected if small fragments bypass but large don't.
	detected := len(working) > 0 && len(blocked) > 0

	return FingerprintResult{
		Detected: detected,
		Details:  details,
		Duration: time.Since(start),
	}
}

// testQUICBlocking checks if UDP/QUIC traffic is blocked.
func (f *Fingerprinter) testQUICBlocking(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	addr, err := net.ResolveUDPAddr("udp", f.target)
	if err != nil {
		return FingerprintResult{
			Detected: false,
			Details:  map[string]string{"error": err.Error()},
			Duration: time.Since(start),
		}
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return FingerprintResult{
			Detected: true,
			Details:  map[string]string{"error": err.Error(), "note": "UDP blocked"},
			Duration: time.Since(start),
		}
	}
	defer conn.Close()

	// Send a probe packet.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Try sending a minimal QUIC Initial-like packet.
	quicProbe := buildQUICProbe()
	_, err = conn.Write(quicProbe)
	if err != nil {
		details["write"] = "failed"
		return FingerprintResult{
			Detected: true,
			Details:  details,
			Duration: time.Since(start),
		}
	}
	details["write"] = "ok"

	// Try to read a response (even an ICMP error would indicate reachability).
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		details["read"] = "timeout"
		// Timeout could mean blocked or just no QUIC server.
		// We mark as potentially blocked.
		return FingerprintResult{
			Detected: false,
			Details:  details,
			Duration: time.Since(start),
		}
	}

	details["read"] = fmt.Sprintf("%d bytes", n)
	return FingerprintResult{
		Detected: false, // Got a response, not blocked.
		Details:  details,
		Duration: time.Since(start),
	}
}

// testTimingAnalysis detects DPI by measuring connection timing patterns.
// Many DPI systems introduce consistent latency overhead.
func (f *Fingerprinter) testTimingAnalysis(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	// Measure multiple connection times.
	const trials = 5
	var latencies []time.Duration

	for i := 0; i < trials; i++ {
		connStart := time.Now()
		conn, err := net.DialTimeout("tcp", f.target, 5*time.Second)
		if err != nil {
			continue
		}
		latencies = append(latencies, time.Since(connStart))
		conn.Close()
	}

	if len(latencies) == 0 {
		return FingerprintResult{
			Detected: false,
			Details:  map[string]string{"error": "no successful connections"},
			Duration: time.Since(start),
		}
	}

	// Compute statistics.
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	avg := sum / time.Duration(len(latencies))

	// Compute variance.
	var variance float64
	for _, l := range latencies {
		diff := float64(l - avg)
		variance += diff * diff
	}
	variance /= float64(len(latencies))

	details["avg_latency_ms"] = fmt.Sprintf("%d", avg.Milliseconds())
	details["trials"] = fmt.Sprintf("%d", len(latencies))
	details["variance"] = fmt.Sprintf("%.0f", variance/1e12) // convert ns^2 to ms^2

	// Unusually consistent high latency suggests DPI.
	// This is a heuristic: avg > 100ms with low variance is suspicious.
	detected := avg > 100*time.Millisecond && variance/(float64(avg)*float64(avg)) < 0.1

	return FingerprintResult{
		Detected: detected,
		Details:  details,
		Duration: time.Since(start),
	}
}

// testResetBehavior checks if blocked connections get TCP RST.
func (f *Fingerprinter) testResetBehavior(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	// Try to connect with a known-blocked pattern and see if we get RST.
	conn, err := net.DialTimeout("tcp", f.target, 5*time.Second)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "reset") || strings.Contains(errStr, "RST") {
			details["reset"] = "true"
			return FingerprintResult{
				Detected: true,
				Details:  details,
				Duration: time.Since(start),
			}
		}
		details["error"] = errStr
		return FingerprintResult{
			Detected: false,
			Details:  details,
			Duration: time.Since(start),
		}
	}
	defer conn.Close()

	// Send a suspicious-looking payload.
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"))
	if err != nil {
		if strings.Contains(err.Error(), "reset") {
			details["reset"] = "true"
			return FingerprintResult{
				Detected: true,
				Details:  details,
				Duration: time.Since(start),
			}
		}
	}

	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil && strings.Contains(err.Error(), "reset") {
		details["reset"] = "true"
		return FingerprintResult{
			Detected: true,
			Details:  details,
			Duration: time.Since(start),
		}
	}

	details["reset"] = "false"
	return FingerprintResult{
		Detected: false,
		Details:  details,
		Duration: time.Since(start),
	}
}

// testActiveProbing detects if the DPI actively probes back.
func (f *Fingerprinter) testActiveProbing(ctx context.Context) FingerprintResult {
	start := time.Now()
	details := make(map[string]string)

	// Listen on a random port and see if we get unsolicited connections
	// after initiating a suspicious-looking connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return FingerprintResult{
			Detected: false,
			Details:  map[string]string{"error": err.Error()},
			Duration: time.Since(start),
		}
	}
	defer ln.Close()

	details["listen_addr"] = ln.Addr().String()

	// Set a short accept deadline.
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		_ = tcpLn.SetDeadline(time.Now().Add(3 * time.Second))
	}

	// Check for unsolicited connections.
	conn, err := ln.Accept()
	if err != nil {
		// Timeout = no active probing detected (expected).
		details["probed"] = "false"
		return FingerprintResult{
			Detected: false,
			Details:  details,
			Duration: time.Since(start),
		}
	}
	conn.Close()

	details["probed"] = "true"
	return FingerprintResult{
		Detected: true,
		Details:  details,
		Duration: time.Since(start),
	}
}

// analyzeResults examines all test results to identify the DPI vendor
// and build the profile capabilities.
func (f *Fingerprinter) analyzeResults(profile *DPIProfile) {
	detectedCount := 0
	totalTests := len(profile.RawResults)

	for _, r := range profile.RawResults {
		if !r.Detected {
			continue
		}
		detectedCount++

		switch r.TestName {
		case "sni_blocking":
			profile.Capabilities |= CapSNIFiltering
			profile.SNIBehavior = r.Details["behavior"]
		case "tls_version_support":
			profile.Capabilities |= CapTLSFingerprinting
			// Parse allowed TLS versions from details.
			for key, val := range r.Details {
				if val == "allowed" {
					switch key {
					case "tls10":
						profile.TLSVersions = append(profile.TLSVersions, tls.VersionTLS10)
					case "tls11":
						profile.TLSVersions = append(profile.TLSVersions, tls.VersionTLS11)
					case "tls12":
						profile.TLSVersions = append(profile.TLSVersions, tls.VersionTLS12)
					case "tls13":
						profile.TLSVersions = append(profile.TLSVersions, tls.VersionTLS13)
					}
				}
			}
		case "cipher_suite_filtering":
			profile.Capabilities |= CapCipherFiltering
		case "fragment_handling":
			profile.Capabilities |= CapFragmentReassembly
			if threshold, ok := r.Details["threshold"]; ok {
				profile.FragmentThreshold = stringToInt(threshold)
			}
		case "quic_blocking":
			profile.Capabilities |= CapQUICBlocking
			profile.QUICBlocked = true
		case "timing_analysis":
			profile.Capabilities |= CapTimingAnalysis
		case "reset_behavior":
			profile.ResetOnBlock = true
		case "active_probing":
			profile.Capabilities |= CapActiveProbing
		}
	}

	if totalTests > 0 {
		profile.Confidence = float64(detectedCount) / float64(totalTests)
	}

	// Vendor identification based on capability patterns.
	profile.Vendor = identifyVendor(profile)
}

// identifyVendor attempts to match the DPI profile to a known vendor
// based on capability fingerprints observed across different countries.
func identifyVendor(profile *DPIProfile) DPIVendor {
	caps := profile.Capabilities

	// TSPU pattern (Russia): SNI filtering + active probing + fragment reassembly.
	// TSPU reassembles fragments but doesn't usually do timing analysis.
	if caps&CapSNIFiltering != 0 && caps&CapActiveProbing != 0 && caps&CapFragmentReassembly != 0 {
		return VendorTSPU
	}

	// GFW pattern (China): SNI filtering + active probing + QUIC blocking + TCP RST.
	// GFW is the most aggressive: blocks QUIC entirely, sends RST packets.
	if caps&CapSNIFiltering != 0 && caps&CapActiveProbing != 0 && caps&CapQUICBlocking != 0 && profile.ResetOnBlock {
		return VendorGFW
	}

	// Sandvine pattern (Iran, Turkey, Egypt): timing + TLS fingerprint + cipher filtering.
	// Sandvine PacketLogic focuses on traffic analysis rather than active probing.
	if caps&CapTimingAnalysis != 0 && caps&CapTLSFingerprinting != 0 && caps&CapCipherFiltering != 0 {
		return VendorSandvine
	}

	// Fortinet pattern (UAE, Saudi Arabia): HTTP filtering + TLS fingerprinting + SNI.
	// Fortinet does deep HTTP inspection and TLS interception but no active probing.
	if caps&CapHTTPFiltering != 0 && caps&CapTLSFingerprinting != 0 && caps&CapSNIFiltering != 0 && caps&CapActiveProbing == 0 {
		return VendorFortinet
	}

	// Palo Alto pattern (enterprise/gov): all filtering + no fragment reassembly issues.
	// Full-stack DPI but typically doesn't reassemble fragments aggressively.
	if caps&CapHTTPFiltering != 0 && caps&CapCipherFiltering != 0 && caps&CapSNIFiltering != 0 && caps&CapFragmentReassembly == 0 {
		return VendorPaloAlto
	}

	// Allot pattern (Pakistan, Qatar): SNI + HTTP filtering + QUIC blocking, no active probe.
	if caps&CapSNIFiltering != 0 && caps&CapHTTPFiltering != 0 && caps&CapQUICBlocking != 0 && caps&CapActiveProbing == 0 {
		return VendorAllot
	}

	// Netsweeper pattern (Pakistan, Yemen): SNI + HTTP filtering only, basic.
	if caps&CapSNIFiltering != 0 && caps&CapHTTPFiltering != 0 && caps&CapTLSFingerprinting == 0 {
		return VendorNetsweeper
	}

	// Huawei pattern (Central Asia, Africa): SNI filtering + cipher filtering, no active probe.
	if caps&CapSNIFiltering != 0 && caps&CapCipherFiltering != 0 && caps&CapActiveProbing == 0 && caps&CapTimingAnalysis == 0 {
		return VendorHuawei
	}

	// Generic TP-based: SNI filtering without active probing.
	if caps&CapSNIFiltering != 0 && caps&CapActiveProbing == 0 {
		return VendorTPDPI
	}

	return VendorUnknown
}

// RecommendedStrategy returns the best bypass strategy for the detected DPI vendor.
// This is the core intelligence that makes Hydra universal.
func RecommendedStrategy(profile *DPIProfile) []string {
	switch profile.Vendor {
	case VendorTSPU:
		// Russia: CDN transport is king, fragment bypass works, QUIC unreliable
		return []string{"xhttp-cdn", "ws-cdn", "grpc-cdn", "reality-fragment", "shadowtls"}
	case VendorGFW:
		// China: Reality works (no CDN needed usually), naiveproxy, meek
		return []string{"reality-direct", "naiveproxy", "ws-cdn", "meek", "shadowtls"}
	case VendorSandvine:
		// Iran/Turkey: TLS fingerprint randomization critical, fragment bypass
		return []string{"reality-random-fp", "ws-cdn", "fragment-bypass", "shadowtls", "hysteria2"}
	case VendorFortinet:
		// UAE/Saudi: CDN works, QUIC sometimes works, HTTP/2 good
		return []string{"ws-cdn", "grpc-cdn", "h2-transport", "hysteria2", "reality-direct"}
	case VendorPaloAlto:
		// Enterprise/Gov: fragment bypass effective, CDN reliable
		return []string{"fragment-bypass", "ws-cdn", "reality-direct", "shadowtls"}
	case VendorAllot:
		// Pakistan/Qatar: CDN works, fragments work, no QUIC
		return []string{"ws-cdn", "fragment-bypass", "reality-direct", "shadowtls"}
	case VendorNetsweeper:
		// Basic DPI: almost anything works
		return []string{"reality-direct", "ws-cdn", "hysteria2", "shadowtls"}
	case VendorHuawei:
		// Central Asia: similar to Netsweeper but slightly more capable
		return []string{"reality-direct", "ws-cdn", "fragment-bypass", "hysteria2"}
	default:
		// Unknown or no DPI: use fastest option
		return []string{"reality-direct", "hysteria2", "ws-cdn", "shadowtls"}
	}
}

// testFragment checks if a TCP connection through the target succeeds
// when using the given fragment size for the initial TLS ClientHello.
func testFragment(target string, size int) bool {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Build a minimal TLS ClientHello and split it into fragments.
	hello := buildMinimalClientHello()
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

	// Try to read a response (any response means the connection went through).
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return n > 0
}

// buildMinimalClientHello constructs a minimal TLS 1.2 ClientHello record.
func buildMinimalClientHello() []byte {
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

// buildQUICProbe creates a minimal QUIC Initial-like packet for probing.
func buildQUICProbe() []byte {
	// Minimal QUIC-like packet: long header form, version 1.
	// This isn't a valid QUIC packet but is enough to trigger DPI rules.
	probe := make([]byte, 64)
	probe[0] = 0xC0 // Long header form
	// Version field (QUIC v1).
	probe[1] = 0x00
	probe[2] = 0x00
	probe[3] = 0x00
	probe[4] = 0x01
	// DCID length.
	probe[5] = 0x08
	// Random DCID.
	for i := 6; i < 14; i++ {
		probe[i] = byte(i * 37 % 256) // deterministic "random"
	}
	return probe
}

// randomHex returns n random hex characters for test domain generation.
func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[time.Now().UnixNano()%16]
	}
	return string(b)
}

// stringToInt is a simple string-to-int converter without importing strconv.
func stringToInt(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
