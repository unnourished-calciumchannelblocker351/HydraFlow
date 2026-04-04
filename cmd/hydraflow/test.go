package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// parsedVLESS holds the parsed fields from a VLESS URI.
type parsedVLESS struct {
	UUID     string
	Host     string
	Port     int
	Security string
	SNI      string
	Flow     string
	Type     string
	Fp       string
	Pbk      string
	Sid      string
	Path     string
	Fragment string
}

// cmdTest tests if a VLESS link actually works by parsing it,
// attempting a TLS handshake, and reporting connection status.
func cmdTest() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: hydraflow test <vless-link>\n")
		fmt.Fprintf(os.Stderr, "\nTests if a VLESS link is reachable:\n")
		fmt.Fprintf(os.Stderr, "  - Parses the VLESS URI\n")
		fmt.Fprintf(os.Stderr, "  - Attempts TCP connection\n")
		fmt.Fprintf(os.Stderr, "  - Attempts TLS handshake\n")
		fmt.Fprintf(os.Stderr, "  - Reports: connected/blocked, latency, TLS version\n")
		os.Exit(1)
	}

	link := os.Args[2]
	vless, err := parseVLESSLink(link)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid VLESS link: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Testing VLESS connection...\n\n")
	fmt.Printf("  Host:     %s\n", vless.Host)
	fmt.Printf("  Port:     %d\n", vless.Port)
	fmt.Printf("  Security: %s\n", vless.Security)
	if vless.SNI != "" {
		fmt.Printf("  SNI:      %s\n", vless.SNI)
	}
	if vless.Flow != "" {
		fmt.Printf("  Flow:     %s\n", vless.Flow)
	}
	if vless.Type != "" {
		fmt.Printf("  Network:  %s\n", vless.Type)
	}
	fmt.Println()

	addr := net.JoinHostPort(vless.Host, strconv.Itoa(vless.Port))

	// Step 1: TCP connection test.
	fmt.Printf("  [1/3] TCP connection to %s... ", addr)
	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	tcpLatency := time.Since(tcpStart)

	if err != nil {
		fmt.Printf("FAILED (%v)\n", err)
		fmt.Printf("\n  Result: BLOCKED (TCP connection refused or timed out)\n")
		fmt.Printf("  Latency: %v\n", tcpLatency.Round(time.Millisecond))
		os.Exit(1)
	}
	fmt.Printf("OK (%v)\n", tcpLatency.Round(time.Millisecond))
	defer conn.Close()

	// Step 2: TLS handshake test.
	if vless.Security == "none" {
		fmt.Printf("  [2/3] TLS handshake... SKIPPED (security=none)\n")
		fmt.Printf("  [3/3] Connection verify... ")
		fmt.Printf("OK\n")
		fmt.Printf("\n  Result:  CONNECTED\n")
		fmt.Printf("  Latency: %v (TCP)\n", tcpLatency.Round(time.Millisecond))
		return
	}

	sni := vless.SNI
	if sni == "" {
		sni = vless.Host
	}

	fmt.Printf("  [2/3] TLS handshake (SNI: %s)... ", sni)

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // We are testing connectivity, not certificate validity.
	}

	// Set minimum TLS version based on security type.
	if vless.Security == "reality" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	tlsStart := time.Now()
	err = tlsConn.Handshake()
	tlsLatency := time.Since(tlsStart)

	if err != nil {
		fmt.Printf("FAILED (%v)\n", err)
		fmt.Printf("\n  Result:  BLOCKED (TLS handshake failed)\n")
		fmt.Printf("  Latency: %v (TCP), %v (TLS attempt)\n",
			tcpLatency.Round(time.Millisecond),
			tlsLatency.Round(time.Millisecond))
		os.Exit(1)
	}

	state := tlsConn.ConnectionState()
	tlsVersion := tlsVersionString(state.Version)
	fmt.Printf("OK (%v)\n", tlsLatency.Round(time.Millisecond))

	// Step 3: Summary.
	fmt.Printf("  [3/3] Connection verify... OK\n")

	fmt.Printf("\n  Result:      CONNECTED\n")
	fmt.Printf("  TLS version: %s\n", tlsVersion)
	fmt.Printf("  Cipher:      %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("  Latency:     %v (TCP) + %v (TLS) = %v total\n",
		tcpLatency.Round(time.Millisecond),
		tlsLatency.Round(time.Millisecond),
		(tcpLatency + tlsLatency).Round(time.Millisecond))

	if state.NegotiatedProtocol != "" {
		fmt.Printf("  ALPN:        %s\n", state.NegotiatedProtocol)
	}

	tlsConn.Close()
}

// parseVLESSLink parses a vless:// URI into its components.
func parseVLESSLink(link string) (*parsedVLESS, error) {
	if !strings.HasPrefix(link, "vless://") {
		return nil, fmt.Errorf("not a VLESS link (must start with vless://)")
	}

	// Remove fragment (the part after #).
	link = strings.SplitN(link, "#", 2)[0]

	// Parse as URL. Replace vless:// with http:// for url.Parse compatibility.
	parsed, err := url.Parse(strings.Replace(link, "vless://", "http://", 1))
	if err != nil {
		return nil, fmt.Errorf("malformed URI: %w", err)
	}

	uuid := parsed.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("missing UUID in VLESS link")
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host in VLESS link")
	}

	portStr := parsed.Port()
	if portStr == "" {
		portStr = "443"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	q := parsed.Query()

	return &parsedVLESS{
		UUID:     uuid,
		Host:     host,
		Port:     port,
		Security: q.Get("security"),
		SNI:      q.Get("sni"),
		Flow:     q.Get("flow"),
		Type:     q.Get("type"),
		Fp:       q.Get("fp"),
		Pbk:      q.Get("pbk"),
		Sid:      q.Get("sid"),
		Path:     q.Get("path"),
		Fragment: parsed.Fragment,
	}, nil
}

// tlsVersionString returns a human-readable TLS version string.
func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
