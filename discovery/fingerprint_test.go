package discovery

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

func TestFingerprinterNew(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"standard target", "example.com:443"},
		{"IP target", "1.2.3.4:443"},
		{"localhost", "127.0.0.1:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFingerprinter(tt.target)
			if f == nil {
				t.Fatal("NewFingerprinter returned nil")
			}
			if f.target != tt.target {
				t.Errorf("target = %q, want %q", f.target, tt.target)
			}
			if f.timeout != 10*time.Second {
				t.Errorf("timeout = %v, want 10s", f.timeout)
			}
		})
	}
}

func TestFingerprinterSetTimeout(t *testing.T) {
	f := NewFingerprinter("example.com:443")
	f.SetTimeout(5 * time.Second)
	if f.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", f.timeout)
	}
}

func TestDPIProfileHasCapability(t *testing.T) {
	tests := []struct {
		name         string
		capabilities DPICapability
		check        DPICapability
		want         bool
	}{
		{"has SNI filtering", CapSNIFiltering, CapSNIFiltering, true},
		{"no SNI filtering", CapQUICBlocking, CapSNIFiltering, false},
		{"has multiple", CapSNIFiltering | CapQUICBlocking | CapActiveProbing, CapQUICBlocking, true},
		{"empty capabilities", 0, CapSNIFiltering, false},
		{"check TLS fingerprinting in combined", CapTLSFingerprinting | CapCipherFiltering, CapTLSFingerprinting, true},
		{"check missing in combined", CapTLSFingerprinting | CapCipherFiltering, CapQUICBlocking, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &DPIProfile{Capabilities: tt.capabilities}
			if got := profile.HasCapability(tt.check); got != tt.want {
				t.Errorf("HasCapability(%v) = %v, want %v", tt.check, got, tt.want)
			}
		})
	}
}

func TestIdentifyVendor(t *testing.T) {
	tests := []struct {
		name         string
		capabilities DPICapability
		resetOnBlock bool
		wantVendor   DPIVendor
	}{
		{
			name:       "no capabilities = unknown",
			wantVendor: VendorUnknown,
		},
		{
			name:         "TSPU pattern: SNI + active probing + fragment reassembly",
			capabilities: CapSNIFiltering | CapActiveProbing | CapFragmentReassembly,
			wantVendor:   VendorTSPU,
		},
		{
			name:         "GFW pattern: SNI + active probing + QUIC blocking + RST",
			capabilities: CapSNIFiltering | CapActiveProbing | CapQUICBlocking,
			resetOnBlock: true,
			wantVendor:   VendorGFW,
		},
		{
			name:         "Sandvine pattern: timing + TLS fingerprinting + cipher",
			capabilities: CapTimingAnalysis | CapTLSFingerprinting | CapCipherFiltering,
			wantVendor:   VendorSandvine,
		},
		{
			name:         "TP-DPI pattern: SNI filtering without active probing",
			capabilities: CapSNIFiltering,
			wantVendor:   VendorTPDPI,
		},
		{
			name:         "SNI + QUIC without active probing = TPDPI",
			capabilities: CapSNIFiltering | CapQUICBlocking,
			wantVendor:   VendorTPDPI,
		},
		{
			name:         "only QUIC blocking = unknown",
			capabilities: CapQUICBlocking,
			wantVendor:   VendorUnknown,
		},
		{
			name:         "only timing analysis = unknown",
			capabilities: CapTimingAnalysis,
			wantVendor:   VendorUnknown,
		},
		{
			name:         "only active probing = unknown",
			capabilities: CapActiveProbing,
			wantVendor:   VendorUnknown,
		},
		{
			name:         "HTTP filtering only = unknown",
			capabilities: CapHTTPFiltering,
			wantVendor:   VendorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &DPIProfile{
				Capabilities: tt.capabilities,
				ResetOnBlock: tt.resetOnBlock,
			}
			got := identifyVendor(profile)
			if got != tt.wantVendor {
				t.Errorf("identifyVendor() = %q, want %q", got, tt.wantVendor)
			}
		})
	}
}

func TestAnalyzeResults(t *testing.T) {
	tests := []struct {
		name       string
		results    []FingerprintResult
		wantCap    DPICapability
		wantVendor DPIVendor
	}{
		{
			name:       "no results",
			results:    nil,
			wantCap:    0,
			wantVendor: VendorUnknown,
		},
		{
			name: "SNI blocking detected",
			results: []FingerprintResult{
				{TestName: "sni_blocking", Detected: true, Details: map[string]string{"behavior": "sni_value_based"}},
			},
			wantCap:    CapSNIFiltering,
			wantVendor: VendorTPDPI,
		},
		{
			name: "TLS version filtering detected",
			results: []FingerprintResult{
				{TestName: "tls_version_support", Detected: true, Details: map[string]string{"tls12": "allowed", "tls13": "allowed"}},
			},
			wantCap:    CapTLSFingerprinting,
			wantVendor: VendorUnknown,
		},
		{
			name: "cipher filtering detected",
			results: []FingerprintResult{
				{TestName: "cipher_suite_filtering", Detected: true, Details: map[string]string{}},
			},
			wantCap:    CapCipherFiltering,
			wantVendor: VendorUnknown,
		},
		{
			name: "fragment reassembly detected",
			results: []FingerprintResult{
				{TestName: "fragment_handling", Detected: true, Details: map[string]string{"threshold": "5"}},
			},
			wantCap:    CapFragmentReassembly,
			wantVendor: VendorUnknown,
		},
		{
			name: "QUIC blocking detected",
			results: []FingerprintResult{
				{TestName: "quic_blocking", Detected: true, Details: map[string]string{}},
			},
			wantCap:    CapQUICBlocking,
			wantVendor: VendorUnknown,
		},
		{
			name: "timing analysis detected",
			results: []FingerprintResult{
				{TestName: "timing_analysis", Detected: true, Details: map[string]string{}},
			},
			wantCap:    CapTimingAnalysis,
			wantVendor: VendorUnknown,
		},
		{
			name: "active probing detected",
			results: []FingerprintResult{
				{TestName: "active_probing", Detected: true, Details: map[string]string{}},
			},
			wantCap:    CapActiveProbing,
			wantVendor: VendorUnknown,
		},
		{
			name: "multiple capabilities",
			results: []FingerprintResult{
				{TestName: "sni_blocking", Detected: true, Details: map[string]string{}},
				{TestName: "quic_blocking", Detected: true, Details: map[string]string{}},
				{TestName: "tls_version_support", Detected: false, Details: map[string]string{}},
			},
			wantCap:    CapSNIFiltering | CapQUICBlocking,
			wantVendor: VendorTPDPI,
		},
		{
			name: "nothing detected",
			results: []FingerprintResult{
				{TestName: "sni_blocking", Detected: false},
				{TestName: "quic_blocking", Detected: false},
				{TestName: "timing_analysis", Detected: false},
			},
			wantCap:    0,
			wantVendor: VendorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFingerprinter("127.0.0.1:443")
			profile := &DPIProfile{
				Vendor:     VendorUnknown,
				RawResults: tt.results,
			}
			f.analyzeResults(profile)

			if profile.Capabilities != tt.wantCap {
				t.Errorf("capabilities = %v, want %v", profile.Capabilities, tt.wantCap)
			}
			if profile.Vendor != tt.wantVendor {
				t.Errorf("vendor = %q, want %q", profile.Vendor, tt.wantVendor)
			}
		})
	}
}

func TestAnalyzeResultsConfidence(t *testing.T) {
	tests := []struct {
		name           string
		results        []FingerprintResult
		wantConfidence float64
	}{
		{
			name:           "all detected",
			results:        []FingerprintResult{{Detected: true}, {Detected: true}, {Detected: true}},
			wantConfidence: 1.0,
		},
		{
			name:           "none detected",
			results:        []FingerprintResult{{Detected: false}, {Detected: false}, {Detected: false}},
			wantConfidence: 0.0,
		},
		{
			name:           "half detected",
			results:        []FingerprintResult{{Detected: true}, {Detected: false}},
			wantConfidence: 0.5,
		},
		{
			name:           "no results",
			results:        nil,
			wantConfidence: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFingerprinter("127.0.0.1:443")
			profile := &DPIProfile{RawResults: tt.results}
			f.analyzeResults(profile)

			if profile.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %f, want %f", profile.Confidence, tt.wantConfidence)
			}
		})
	}
}

func TestAnalyzeResultsTLSVersions(t *testing.T) {
	f := NewFingerprinter("127.0.0.1:443")
	profile := &DPIProfile{
		RawResults: []FingerprintResult{
			{
				TestName: "tls_version_support",
				Detected: true,
				Details: map[string]string{
					"tls10": "blocked",
					"tls11": "blocked",
					"tls12": "allowed",
					"tls13": "allowed",
				},
			},
		},
	}

	f.analyzeResults(profile)

	if !profile.HasCapability(CapTLSFingerprinting) {
		t.Error("should have TLS fingerprinting capability")
	}

	expectedVersions := map[uint16]bool{
		tls.VersionTLS12: false,
		tls.VersionTLS13: false,
	}
	for _, v := range profile.TLSVersions {
		expectedVersions[v] = true
	}
	for v, found := range expectedVersions {
		if !found {
			t.Errorf("TLS version 0x%04x not found in profile", v)
		}
	}
}

func TestAnalyzeResultsFragmentThreshold(t *testing.T) {
	f := NewFingerprinter("127.0.0.1:443")
	profile := &DPIProfile{
		RawResults: []FingerprintResult{
			{
				TestName: "fragment_handling",
				Detected: true,
				Details:  map[string]string{"threshold": "10"},
			},
		},
	}

	f.analyzeResults(profile)

	if profile.FragmentThreshold != 10 {
		t.Errorf("fragment threshold = %d, want 10", profile.FragmentThreshold)
	}
}

func TestAnalyzeResultsResetBehavior(t *testing.T) {
	f := NewFingerprinter("127.0.0.1:443")
	profile := &DPIProfile{
		RawResults: []FingerprintResult{
			{TestName: "reset_behavior", Detected: true, Details: map[string]string{"reset": "true"}},
		},
	}

	f.analyzeResults(profile)
	if !profile.ResetOnBlock {
		t.Error("ResetOnBlock should be true")
	}
}

func TestAnalyzeResultsSNIBehavior(t *testing.T) {
	f := NewFingerprinter("127.0.0.1:443")
	profile := &DPIProfile{
		RawResults: []FingerprintResult{
			{
				TestName: "sni_blocking",
				Detected: true,
				Details:  map[string]string{"behavior": "sni_value_based"},
			},
		},
	}

	f.analyzeResults(profile)
	if profile.SNIBehavior != "sni_value_based" {
		t.Errorf("SNIBehavior = %q, want %q", profile.SNIBehavior, "sni_value_based")
	}
}

func TestFingerprintLocalTarget(t *testing.T) {
	// Fingerprint against a local TCP server — no real DPI, so nothing should
	// be detected. This tests that the full pipeline works end-to-end.
	addr, cleanup := startTCPServer(t)
	defer cleanup()

	f := NewFingerprinter(addr)
	f.SetTimeout(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	profile, err := f.Fingerprint(ctx)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}

	if profile == nil {
		t.Fatal("profile is nil")
	}

	// Against localhost, no DPI should be detected.
	if profile.Vendor != VendorUnknown {
		t.Errorf("vendor = %q, expected unknown for localhost", profile.Vendor)
	}

	// Should have run all 8 tests.
	if len(profile.RawResults) != 8 {
		t.Errorf("got %d raw results, want 8", len(profile.RawResults))
	}
}

func TestDPICapabilityConstants(t *testing.T) {
	// Verify all capabilities are distinct powers of 2.
	caps := []DPICapability{
		CapSNIFiltering,
		CapTLSFingerprinting,
		CapQUICBlocking,
		CapFragmentReassembly,
		CapActiveProbing,
		CapHTTPFiltering,
		CapTimingAnalysis,
		CapCipherFiltering,
	}

	for i := 0; i < len(caps); i++ {
		for j := i + 1; j < len(caps); j++ {
			if caps[i]&caps[j] != 0 {
				t.Errorf("capabilities %d and %d overlap: %v & %v = %v",
					i, j, caps[i], caps[j], caps[i]&caps[j])
			}
		}
	}
}

func TestDPIVendorConstants(t *testing.T) {
	vendors := []DPIVendor{VendorUnknown, VendorTPDPI, VendorTSPU, VendorGFW, VendorSandvine}
	seen := make(map[DPIVendor]bool)
	for _, v := range vendors {
		if seen[v] {
			t.Errorf("duplicate vendor constant: %q", v)
		}
		seen[v] = true
		if v == "" {
			t.Error("vendor constant should not be empty string")
		}
	}
}

func TestBuildQUICProbe(t *testing.T) {
	probe := buildQUICProbe()

	t.Run("correct length", func(t *testing.T) {
		if len(probe) != 64 {
			t.Errorf("probe length = %d, want 64", len(probe))
		}
	})

	t.Run("long header form", func(t *testing.T) {
		if probe[0] != 0xC0 {
			t.Errorf("first byte = 0x%02x, want 0xC0 (long header)", probe[0])
		}
	})

	t.Run("QUIC version 1", func(t *testing.T) {
		if probe[1] != 0x00 || probe[2] != 0x00 || probe[3] != 0x00 || probe[4] != 0x01 {
			t.Error("QUIC version field incorrect")
		}
	})

	t.Run("DCID length", func(t *testing.T) {
		if probe[5] != 0x08 {
			t.Errorf("DCID length = %d, want 8", probe[5])
		}
	})
}

func TestRandomHex(t *testing.T) {
	tests := []struct {
		name string
		n    int
	}{
		{"length 1", 1},
		{"length 4", 4},
		{"length 8", 8},
		{"length 16", 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randomHex(tt.n)
			if len(result) != tt.n {
				t.Errorf("length = %d, want %d", len(result), tt.n)
			}
			for _, c := range result {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("invalid hex char: %c", c)
				}
			}
		})
	}
}

func TestStringToInt(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"0", 0},
		{"1", 1},
		{"42", 42},
		{"100", 100},
		{"999999", 999999},
		{"", 0},
		{"abc", 0},
		{"12abc", 12},
		{"0123", 123},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := stringToInt(tt.input); got != tt.want {
				t.Errorf("stringToInt(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
