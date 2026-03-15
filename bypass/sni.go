package bypass

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// UnblockableSNIs contains domains that Russia, China, Iran, etc. cannot
// block without causing massive domestic disruption. These are ideal
// candidates for Reality SNI.
var UnblockableSNIs = map[string][]string{
	"russia": {
		"gosuslugi.ru",   // Russian government services
		"nalog.ru",       // Russian tax service
		"sberbank.ru",    // Largest Russian bank
		"ya.ru",          // Yandex (short domain)
		"yandex.ru",      // Yandex
		"vk.com",         // VKontakte social network
		"mail.ru",        // Mail.ru
		"wildberries.ru", // Largest Russian e-commerce
		"ozon.ru",        // Major e-commerce
		"mos.ru",         // Moscow city government
		"kremlin.ru",     // Kremlin official site
		"cbr.ru",         // Central Bank of Russia
		"pfr.gov.ru",     // Pension fund
		"gosuslugi.ru",   // E-government
		"nalog.gov.ru",   // Tax service
	},
	"china": {
		"www.apple.com",     // Apple
		"www.microsoft.com", // Microsoft
		"www.samsung.com",   // Samsung
		"www.tesla.com",     // Tesla
		"www.oracle.com",    // Oracle
		"www.ibm.com",       // IBM
		"www.cisco.com",     // Cisco
		"www.qualcomm.com",  // Qualcomm
		"www.intel.com",     // Intel
	},
	"iran": {
		"www.google.com",     // Google (not always blocked)
		"www.apple.com",      // Apple
		"www.microsoft.com",  // Microsoft
		"cloud.google.com",   // Google Cloud
		"www.cloudflare.com", // Cloudflare
		"www.akamai.com",     // Akamai
		"www.fastly.com",     // Fastly
	},
	"global": {
		"www.google.com",
		"www.microsoft.com",
		"www.apple.com",
		"cloudflare.com",
		"www.amazon.com",
		"www.cloudflare.com",
		"icloud.com",
		"github.com",
		"www.tesla.com",
	},
}

// SNIConfig holds configuration for SNI manipulation techniques.
type SNIConfig struct {
	// Domain is the primary SNI value.
	Domain string

	// Fallbacks are backup SNI domains tried in order if primary is blocked.
	Fallbacks []string

	// FakeSNI sends a decoy SNI in the first packet before the real one.
	FakeSNI bool

	// Rotation changes SNI every N connections (0 = disabled).
	Rotation int

	// DomainFronting uses CDN domain fronting.
	DomainFronting bool

	// DomainFrontHost is the real Host header when domain fronting.
	DomainFrontHost string
}

// SNITechnique manipulates the TLS Server Name Indication field to
// bypass SNI-based filtering.
type SNITechnique struct {
	config SNIConfig
	mu     sync.Mutex
	count  int
	pool   []string
}

// NewSNITechnique creates an SNI manipulation technique.
func NewSNITechnique(cfg SNIConfig) *SNITechnique {
	pool := []string{}
	if cfg.Domain != "" {
		pool = append(pool, cfg.Domain)
	}
	pool = append(pool, cfg.Fallbacks...)

	return &SNITechnique{
		config: cfg,
		pool:   pool,
	}
}

func (s *SNITechnique) Name() string    { return "sni" }
func (s *SNITechnique) Available() bool { return len(s.pool) > 0 }
func (s *SNITechnique) Effective() bool { return true }

// Wrap returns the connection unchanged; SNI is applied during dial.
func (s *SNITechnique) Wrap(conn net.Conn) net.Conn {
	return conn
}

// WrapDial does not modify the dialer since SNI is typically set by
// the protocol layer (xray, sing-box) rather than the bypass engine.
// The engine provides CurrentSNI() for protocols to query.
func (s *SNITechnique) WrapDial(next DialFunc) DialFunc {
	return next
}

// CurrentSNI returns the SNI domain for the current connection,
// accounting for rotation through the pool.
func (s *SNITechnique) CurrentSNI() string {
	if len(s.pool) == 0 {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.config.Rotation <= 0 {
		return s.pool[0]
	}

	idx := (s.count / s.config.Rotation) % len(s.pool)
	s.count++
	return s.pool[idx]
}

// RandomSNI returns a random domain from the pool.
func (s *SNITechnique) RandomSNI() string {
	if len(s.pool) == 0 {
		return ""
	}
	return s.pool[cryptoRandIntn(len(s.pool))]
}

// FindUnblockableSNI tests which "critical" domains in the given
// country list actually work for TLS 1.3 connections to the specified
// server IP. These domains are ideal for Reality because the country
// literally cannot block them without breaking essential services.
//
// It returns domains sorted by connection speed (fastest first).
func FindUnblockableSNI(serverIP string, country string, port int) []SNITestResult {
	if port <= 0 {
		port = 443
	}

	domains, ok := UnblockableSNIs[country]
	if !ok {
		domains = UnblockableSNIs["global"]
	}

	type result struct {
		domain  string
		latency time.Duration
		tls13   bool
		err     error
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var results []result

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			start := time.Now()
			addr := net.JoinHostPort(serverIP, fmt.Sprintf("%d", port))

			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
				ServerName:         d,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			})

			r := result{
				domain:  d,
				latency: time.Since(start),
				err:     err,
			}

			if err == nil {
				state := conn.ConnectionState()
				r.tls13 = state.Version == tls.VersionTLS13
				conn.Close()
			}

			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(domain)
	}

	wg.Wait()

	// Filter and sort by latency.
	var working []SNITestResult
	for _, r := range results {
		if r.err == nil && r.tls13 {
			working = append(working, SNITestResult{
				Domain:  r.domain,
				Latency: r.latency,
				TLS13:   true,
				Working: true,
			})
		}
	}

	// Sort by latency (fastest first).
	for i := 0; i < len(working); i++ {
		for j := i + 1; j < len(working); j++ {
			if working[j].Latency < working[i].Latency {
				working[i], working[j] = working[j], working[i]
			}
		}
	}

	return working
}

// SNITestResult holds the outcome of testing a single SNI domain.
type SNITestResult struct {
	Domain  string        `json:"domain"`
	Latency time.Duration `json:"latency"`
	TLS13   bool          `json:"tls13"`
	Working bool          `json:"working"`
}

// TestSNIBlocked checks whether a specific SNI domain is blocked on
// the path to the given server. It attempts a TLS handshake with the
// SNI and reports whether it succeeds.
func TestSNIBlocked(serverAddr, sni string) (blocked bool, err error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return true, err
	}
	conn.Close()
	return false, nil
}

// DomainFrontingInfo returns the SNI and Host header pair for domain
// fronting. The SNI is the CDN edge domain (unblocked), and the Host
// header is the real backend domain.
func DomainFrontingInfo(cfg SNIConfig) (sni, host string) {
	sni = cfg.Domain
	if sni == "" {
		sni = "www.cloudflare.com"
	}
	host = cfg.DomainFrontHost
	if host == "" {
		host = sni
	}
	return sni, host
}

// BuildSNIPool creates a pool of SNI domains from the config. The
// pool is used for rotation and random selection.
func BuildSNIPool(primary string, fallbacks []string, country string) []string {
	pool := make([]string, 0, 1+len(fallbacks))
	if primary != "" {
		pool = append(pool, primary)
	}
	pool = append(pool, fallbacks...)

	// If the pool is still empty, use unblockable domains for the country.
	if len(pool) == 0 {
		if domains, ok := UnblockableSNIs[country]; ok && len(domains) > 0 {
			pool = append(pool, domains[:min(5, len(domains))]...)
		} else if global, ok := UnblockableSNIs["global"]; ok {
			pool = append(pool, global[:min(5, len(global))]...)
		}
	}

	return pool
}

// FakeSNIDialFunc wraps a DialFunc and first sends a fake TLS
// ClientHello with a decoy SNI before the real connection. This
// can confuse DPI systems that track connection state by SNI.
func FakeSNIDialFunc(next DialFunc, fakeSNI string) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// Send a decoy TLS ClientHello to the same address with a fake SNI.
		// We open a throwaway connection, send a partial handshake, then
		// immediately close it. The DPI sees a "normal" connection to
		// the fake SNI, which primes its state.
		go func() {
			decoyConn, err := net.DialTimeout(network, address, 3*time.Second)
			if err != nil {
				return
			}
			// Send a fake ClientHello with the decoy SNI.
			hello := buildClientHelloWithSNI(fakeSNI)
			_, _ = decoyConn.Write(hello)
			time.Sleep(100 * time.Millisecond)
			decoyConn.Close()
		}()

		// Small delay for the decoy to prime DPI state.
		time.Sleep(50 * time.Millisecond)

		return next(ctx, network, address)
	}
}

// buildClientHelloWithSNI constructs a minimal TLS ClientHello record
// with the specified SNI extension.
func buildClientHelloWithSNI(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	// SNI extension structure.
	sniExtData := make([]byte, 0, 5+sniLen)
	// Server name list length.
	sniListLen := 3 + sniLen
	sniExtData = append(sniExtData, byte(sniListLen>>8), byte(sniListLen&0xFF))
	// Host name type (0 = DNS hostname).
	sniExtData = append(sniExtData, 0x00)
	// Host name length.
	sniExtData = append(sniExtData, byte(sniLen>>8), byte(sniLen&0xFF))
	// Host name.
	sniExtData = append(sniExtData, sniBytes...)

	// Extensions block.
	extType := []byte{0x00, 0x00} // SNI extension type = 0x0000
	extLen := []byte{byte(len(sniExtData) >> 8), byte(len(sniExtData) & 0xFF)}
	extensions := append(extType, extLen...)
	extensions = append(extensions, sniExtData...)

	extensionsTotal := []byte{byte(len(extensions) >> 8), byte(len(extensions) & 0xFF)}

	// ClientHello body.
	var body []byte
	// Client version: TLS 1.2.
	body = append(body, 0x03, 0x03)
	// Random (32 bytes).
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	// Session ID length: 0.
	body = append(body, 0x00)
	// Cipher suites: 2 bytes length + one suite.
	body = append(body, 0x00, 0x02) // length
	body = append(body, 0xc0, 0x2f) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	// Compression methods: null.
	body = append(body, 0x01, 0x00)
	// Extensions.
	body = append(body, extensionsTotal...)
	body = append(body, extensions...)

	// Handshake header.
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	hsLen := len(body)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen&0xFF))
	handshake = append(handshake, body...)

	// TLS record header.
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	recLen := len(handshake)
	record = append(record, byte(recLen>>8), byte(recLen&0xFF))
	record = append(record, handshake...)

	return record
}
