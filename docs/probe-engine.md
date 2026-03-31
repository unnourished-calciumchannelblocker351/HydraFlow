# Probe Engine

The probe engine is HydraFlow's censorship detection system. It runs a suite of network tests to understand the DPI (Deep Packet Inspection) capabilities of the current network, then uses the results to select the optimal bypass protocol.

## Architecture

The probe engine has two layers:

1. **Prober** (`discovery.Prober`) -- runs individual probe tests and returns raw results
2. **Fingerprinter** (`discovery.Fingerprinter`) -- runs a comprehensive suite of DPI detection tests and produces a `DPIProfile` identifying the DPI vendor and capabilities

The Prober is used during normal connection establishment to quickly assess which protocols are viable. The Fingerprinter provides deeper analysis for diagnostics and protocol tuning.

## Probe Tests

### PortReachabilityTest

**What it does:** Attempts a TCP connection to the target host and port.

**How to interpret:**
- **Pass:** The port is open and reachable. Basic network connectivity exists.
- **Fail:** The port is blocked, the host is unreachable, or there is a firewall in the way.

**Weight:** 1.0 (highest -- if the port is blocked, nothing else matters)

### TLSFingerprintTest

**What it does:** Performs a TLS 1.3 handshake and checks if it completes successfully. Many DPI systems fingerprint TLS ClientHello messages using JA3/JA4 hashes and block connections that don't match known browser profiles.

**How to interpret:**
- **Pass:** TLS handshake succeeded. Reports the negotiated TLS version, cipher suite, and server name.
- **Fail:** The DPI may be fingerprinting TLS connections and blocking non-browser profiles. Consider using a browser-like TLS fingerprint (e.g., Chrome via uTLS).

**Weight:** 0.8

### SNIFilteringTest

**What it does:** Connects to the target with different SNI (Server Name Indication) values -- known-benign domains (microsoft.com, cloudflare.com, apple.com) and potentially blocked domains. Checks which SNI values are allowed through.

**How to interpret:**
- **Pass:** At least one domain's SNI is accessible. The details show which specific domains are blocked vs accessible.
- **Fail (all blocked):** The DPI is blocking all tested SNI values, or the target is unreachable regardless of SNI.
- **Mixed results:** The DPI is doing SNI-based filtering. Use the "accessible" domains as cover SNI values, or use REALITY with a known-good SNI.

**Weight:** 0.9

### QUICAvailabilityTest

**What it does:** Sends a UDP probe packet to the target to check if UDP/QUIC traffic is reachable.

**How to interpret:**
- **Pass:** UDP traffic reaches the target. QUIC-based protocols (Hysteria2) are viable.
- **Fail:** UDP traffic may be blocked. Stick to TCP-based protocols (REALITY, XHTTP, ShadowTLS).

**Weight:** 0.7

### FragmentBypassTest

**What it does:** Sends a TLS ClientHello in small TCP fragments (1, 2, 5, 10, 50, 100, 200 bytes) to test if the DPI can reassemble fragmented packets. Many DPI systems only inspect the first TCP segment and miss data split across multiple segments.

**How to interpret:**
- **Pass:** Some fragment sizes bypass the DPI. The details include `working_sizes` (which sizes work) and `optimal` (the smallest working size).
- **Fail:** Either all fragment sizes are blocked (DPI reassembles TCP) or the target is unreachable.

**Weight:** 0.6

## DPI Fingerprinting

The Fingerprinter runs a more comprehensive suite of 8 tests to identify the specific DPI system:

### TLS Version Support
Tests TLS 1.0, 1.1, 1.2, and 1.3 individually to see which versions are allowed. Some DPI systems block older TLS versions or only allow specific versions.

### Cipher Suite Filtering
Tests individual cipher suites (AES-GCM, ChaCha20-Poly1305, ECDHE variants) to detect cipher-based filtering.

### SNI Blocking Patterns
Extended SNI testing with benign domains, empty SNI, and randomized domains. Determines whether filtering is SNI-value-based or SNI-presence-based.

### Fragment Handling
Extended fragment testing with sizes from 1 to 500 bytes. Identifies the DPI's reassembly threshold -- the minimum fragment size that bypasses inspection.

### QUIC Blocking
Sends a QUIC Initial-like probe packet and checks for responses. Detects UDP/QUIC blocking.

### Timing Analysis
Measures TCP connection latency across multiple trials. DPI systems that inspect traffic introduce consistent latency overhead. Unusually consistent high latency (>100ms with low variance) suggests DPI presence.

### Reset Behavior
Checks if blocked connections receive TCP RST packets. Some DPI systems (notably GFW) inject RST packets to terminate blocked connections.

### Active Probing
Listens for unsolicited incoming connections after making suspicious-looking outgoing connections. Some DPI systems (GFW, TSPU) actively probe back to identify proxy servers.

## DPI Vendor Identification

Based on the combination of detected capabilities, the Fingerprinter identifies the DPI vendor:

| Pattern | Vendor |
|---------|--------|
| SNI filtering + active probing + fragment reassembly | TSPU (Roskomnadzor) |
| SNI filtering + active probing + QUIC blocking + TCP RST | GFW (Great Firewall) |
| Timing analysis + TLS fingerprinting + cipher filtering | Sandvine PacketLogic |
| SNI filtering without active probing | Generic TP-based DPI |

## Using the Probe Engine

### Quick Probe

```go
prober := discovery.NewProber("server.example.com:443")
results, err := prober.RunAll(ctx)
for _, r := range results {
    fmt.Printf("%-20s %s\n", r.TestName, statusStr(r.Success))
}
```

### Full DPI Fingerprint

```go
fp := discovery.NewFingerprinter("server.example.com:443")
fp.SetTimeout(5 * time.Second)

profile, err := fp.Fingerprint(ctx)
fmt.Printf("DPI Vendor: %s\n", profile.Vendor)
fmt.Printf("Capabilities: %v\n", profile.Capabilities)
fmt.Printf("QUIC Blocked: %v\n", profile.QUICBlocked)
fmt.Printf("Fragment Threshold: %d bytes\n", profile.FragmentThreshold)
```

### Integration with Protocol Selection

The probe results feed into the Selector which ranks protocols:

```go
engine, _ := core.New(cfg, logger)
// Protocols are automatically probed and ranked during Connect()
conn, err := engine.Connect(ctx)
```

The Selector computes a composite score: 50% probe results, 30% historical success rate, 20% configured priority.

## Adding Custom Probes

To add a custom probe test, implement the `core.ProbeTest` interface:

```go
type MyCustomTest struct{}

func (t *MyCustomTest) Name() string { return "my_custom_test" }

func (t *MyCustomTest) Weight() float64 { return 0.5 }

func (t *MyCustomTest) Run(ctx context.Context, target string) (*core.ProbeResult, error) {
    start := time.Now()

    // Your test logic here.
    success := runMyTest(target)

    return &core.ProbeResult{
        TestName:  t.Name(),
        Success:   success,
        Latency:   time.Since(start),
        Details:   map[string]string{"custom_field": "value"},
        Timestamp: time.Now(),
    }, nil
}
```

Then register it with a custom Prober or add it to a Protocol's `ProbeTests()` return value.

### Guidelines for Custom Probes

- **Keep tests fast.** Each test should complete within 5 seconds. Use context deadlines.
- **Be non-destructive.** Tests should only observe, never modify network state.
- **Set appropriate weights.** Use 0.0-1.0 where 1.0 means the test is critical (like port reachability) and lower values are supplementary.
- **Include details.** Put diagnostic information in the `Details` map so users can understand why a test passed or failed.
- **Handle errors gracefully.** Return a `ProbeResult` with `Success: false` rather than an error when the test itself runs but the network condition is unfavorable.
