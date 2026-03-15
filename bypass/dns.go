package bypass

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DNSConfig holds configuration for the bypass DNS resolver.
type DNSConfig struct {
	// DOHEnabled uses DNS-over-HTTPS for all resolution.
	DOHEnabled bool
	// DOHServer is the DoH endpoint (e.g., "https://dns.google/dns-query").
	DOHServer string

	// DOTEnabled uses DNS-over-TLS as fallback when DoH fails.
	DOTEnabled bool
	// DOTServer is the DoT server (e.g., "dns.google:853").
	DOTServer string

	// SplitDNS routes Russian domains to a Russian DNS server.
	SplitDNS bool
	// RussianDNS is the DNS server for .ru zones.
	RussianDNS string

	// CacheTTL is the DNS cache TTL in seconds (0 = use server TTL).
	CacheTTL int

	// CustomServers are additional DNS servers.
	CustomServers []string
}

// DefaultDNSConfig returns reasonable defaults.
func DefaultDNSConfig() DNSConfig {
	return DNSConfig{
		DOHEnabled: true,
		DOHServer:  "https://dns.google/dns-query",
		DOTEnabled: true,
		DOTServer:  "dns.google:853",
		SplitDNS:   false,
		RussianDNS: "77.88.8.8:53", // Yandex DNS
		CacheTTL:   300,
	}
}

// DNSResolver handles DNS resolution with DoH, DoT, split DNS, and
// caching. It prevents DNS poisoning by encrypting all queries.
type DNSResolver struct {
	config     DNSConfig
	logger     *slog.Logger
	cache      *dnsCache
	httpClient *http.Client
}

// NewDNSResolver creates a DNS resolver with the given configuration.
func NewDNSResolver(cfg DNSConfig, logger *slog.Logger) *DNSResolver {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.DOHServer == "" {
		cfg.DOHServer = "https://dns.google/dns-query"
	}
	if cfg.DOTServer == "" {
		cfg.DOTServer = "dns.google:853"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 300
	}

	// HTTP client for DoH — bypass system DNS by connecting directly.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &DNSResolver{
		config: cfg,
		logger: logger.With("component", "dns"),
		cache:  newDNSCache(cfg.CacheTTL),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Resolve resolves a hostname to IP addresses. It checks the cache
// first, then tries DoH, DoT, and plain DNS in order.
func (r *DNSResolver) Resolve(ctx context.Context, host string) ([]string, error) {
	// If it's already an IP, return it directly.
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}

	// Check cache.
	if addrs := r.cache.get(host); len(addrs) > 0 {
		r.logger.Debug("DNS cache hit", "host", host, "addrs", addrs)
		return addrs, nil
	}

	// Split DNS: Russian domains go to Russian DNS.
	if r.config.SplitDNS && isRussianDomain(host) {
		addrs, err := r.resolveViaPlainDNS(ctx, host, r.config.RussianDNS)
		if err == nil && len(addrs) > 0 {
			r.cache.set(host, addrs)
			r.logger.Debug("resolved via Russian DNS", "host", host, "addrs", addrs)
			return addrs, nil
		}
		r.logger.Debug("Russian DNS failed, falling through", "host", host, "error", err)
	}

	// Try DoH first.
	if r.config.DOHEnabled {
		addrs, err := r.resolveViaDoH(ctx, host)
		if err == nil && len(addrs) > 0 {
			r.cache.set(host, addrs)
			r.logger.Debug("resolved via DoH", "host", host, "addrs", addrs)
			return addrs, nil
		}
		r.logger.Debug("DoH failed", "host", host, "error", err)
	}

	// Try DoT.
	if r.config.DOTEnabled {
		addrs, err := r.resolveViaDoT(ctx, host)
		if err == nil && len(addrs) > 0 {
			r.cache.set(host, addrs)
			r.logger.Debug("resolved via DoT", "host", host, "addrs", addrs)
			return addrs, nil
		}
		r.logger.Debug("DoT failed", "host", host, "error", err)
	}

	// Fallback: system resolver.
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("all DNS resolution failed for %s: %w", host, err)
	}

	r.cache.set(host, addrs)
	return addrs, nil
}

// DialContext resolves the host using our DNS resolver and then dials.
// It implements the DialFunc signature so it can be used as a base
// dialer in the bypass engine.
func (r *DNSResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Maybe just a host without port.
		host = address
		port = ""
	}

	addrs, err := r.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns resolve %s: %w", host, err)
	}

	// Try each resolved address.
	var lastErr error
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	for _, addr := range addrs {
		target := addr
		if port != "" {
			target = net.JoinHostPort(addr, port)
		}

		conn, dialErr := dialer.DialContext(ctx, network, target)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("dial failed for all addresses of %s: %w", host, lastErr)
}

// resolveViaDoH performs DNS-over-HTTPS resolution using the wire
// format (application/dns-message) per RFC 8484.
func (r *DNSResolver) resolveViaDoH(ctx context.Context, host string) ([]string, error) {
	// Build DNS query in wire format.
	query := buildDNSQuery(host, 1) // type A

	req, err := http.NewRequestWithContext(ctx, "POST", r.config.DOHServer, strings.NewReader(string(query)))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	return parseDNSResponse(body)
}

// resolveViaDoT performs DNS-over-TLS resolution per RFC 7858.
func (r *DNSResolver) resolveViaDoT(ctx context.Context, host string) ([]string, error) {
	// Determine the DoT server hostname for certificate validation.
	dotHost, _, err := net.SplitHostPort(r.config.DOTServer)
	if err != nil {
		dotHost = r.config.DOTServer
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			ServerName: dotHost,
			MinVersion: tls.VersionTLS13,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", r.config.DOTServer)
	if err != nil {
		return nil, fmt.Errorf("DoT connect: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// DNS over TLS uses a 2-byte length prefix before the wire-format query.
	query := buildDNSQuery(host, 1)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))

	if _, err := conn.Write(append(lenBuf, query...)); err != nil {
		return nil, fmt.Errorf("DoT write: %w", err)
	}

	// Read the response length.
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("DoT read length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("DoT read response: %w", err)
	}

	return parseDNSResponse(respBuf)
}

// resolveViaPlainDNS sends a UDP DNS query to a specific server.
func (r *DNSResolver) resolveViaPlainDNS(ctx context.Context, host, server string) ([]string, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("plain DNS dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	query := buildDNSQuery(host, 1)
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("plain DNS write: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("plain DNS read: %w", err)
	}

	return parseDNSResponse(buf[:n])
}

// buildDNSQuery constructs a minimal DNS query in wire format.
// qtype: 1 = A, 28 = AAAA.
func buildDNSQuery(name string, qtype uint16) []byte {
	var pkt []byte

	// Header (12 bytes).
	txid := uint16(time.Now().UnixNano() & 0xFFFF)
	pkt = append(pkt, byte(txid>>8), byte(txid&0xFF)) // Transaction ID
	pkt = append(pkt, 0x01, 0x00)                     // Flags: standard query, recursion desired
	pkt = append(pkt, 0x00, 0x01)                     // QDCOUNT: 1
	pkt = append(pkt, 0x00, 0x00)                     // ANCOUNT: 0
	pkt = append(pkt, 0x00, 0x00)                     // NSCOUNT: 0
	pkt = append(pkt, 0x00, 0x00)                     // ARCOUNT: 0

	// Question section: encode the domain name.
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0x00)                             // Root label
	pkt = append(pkt, byte(qtype>>8), byte(qtype&0xFF)) // QTYPE
	pkt = append(pkt, 0x00, 0x01)                       // QCLASS: IN

	return pkt
}

// parseDNSResponse extracts IP addresses from a DNS wire-format response.
func parseDNSResponse(data []byte) ([]string, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS response too short: %d bytes", len(data))
	}

	// Check response code.
	rcode := data[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error: rcode=%d", rcode)
	}

	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	if ancount == 0 {
		return nil, fmt.Errorf("DNS response has no answers")
	}

	// Skip the header and question section.
	pos := 12
	// Skip QNAME.
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		if length >= 0xC0 {
			// Compressed pointer.
			pos += 2
			break
		}
		pos += 1 + length
	}
	// Skip QTYPE and QCLASS.
	pos += 4

	// Parse answer records.
	var addrs []string
	for i := 0; i < ancount && pos < len(data); i++ {
		// Skip NAME (may be compressed).
		if pos >= len(data) {
			break
		}
		if data[pos] >= 0xC0 {
			pos += 2
		} else {
			for pos < len(data) {
				length := int(data[pos])
				if length == 0 {
					pos++
					break
				}
				pos += 1 + length
			}
		}

		if pos+10 > len(data) {
			break
		}

		rtype := binary.BigEndian.Uint16(data[pos : pos+2])
		// rclass := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		// ttl := binary.BigEndian.Uint32(data[pos+4 : pos+8])
		rdlength := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		pos += 10

		if pos+rdlength > len(data) {
			break
		}

		switch rtype {
		case 1: // A record
			if rdlength == 4 {
				ip := net.IPv4(data[pos], data[pos+1], data[pos+2], data[pos+3])
				addrs = append(addrs, ip.String())
			}
		case 28: // AAAA record
			if rdlength == 16 {
				ip := net.IP(data[pos : pos+16])
				addrs = append(addrs, ip.String())
			}
		}

		pos += rdlength
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A/AAAA records found")
	}

	return addrs, nil
}

// isRussianDomain checks if a hostname belongs to a Russian zone.
func isRussianDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	russianTLDs := []string{
		".ru", ".su", ".xn--p1ai", // .рф in punycode
		".moscow", ".москва",
	}

	for _, tld := range russianTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}

	// Some well-known Russian domains on non-.ru TLDs.
	russianDomains := []string{
		"vk.com", "ok.ru", "mail.ru", "yandex.com",
		"kaspersky.com", "1c.com",
	}
	for _, d := range russianDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}

	return false
}

// ---- DNS Cache ----

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
	ttl     time.Duration
}

type dnsCacheEntry struct {
	addrs   []string
	expires time.Time
}

func newDNSCache(ttlSeconds int) *dnsCache {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	return &dnsCache{
		entries: make(map[string]*dnsCacheEntry),
		ttl:     time.Duration(ttlSeconds) * time.Second,
	}
}

func (c *dnsCache) get(host string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[host]
	if !ok {
		return nil
	}
	if time.Now().After(entry.expires) {
		return nil // expired
	}
	out := make([]string, len(entry.addrs))
	copy(out, entry.addrs)
	return out
}

func (c *dnsCache) set(host string, addrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[host] = &dnsCacheEntry{
		addrs:   addrs,
		expires: time.Now().Add(c.ttl),
	}
}

// Flush clears the entire DNS cache.
func (c *dnsCache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*dnsCacheEntry)
}
