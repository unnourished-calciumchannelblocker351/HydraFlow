package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// SNIFinder discovers suitable domains for Reality protocol SNI
// by evaluating TLS 1.3 support, HTTP/2 support, handshake latency,
// ASN proximity, and traffic legitimacy.
type SNIFinder struct {
	logger      *slog.Logger
	serverIP    string
	serverASN   int
	concurrency int
	timeout     time.Duration
}

// SNIFinderConfig configures the SNI discovery process.
type SNIFinderConfig struct {
	// ServerIP is the server's public IP address.
	ServerIP string

	// Concurrency limits parallel domain checks.
	Concurrency int

	// Timeout is the overall timeout for the discovery process.
	Timeout time.Duration

	// CustomDomains are additional domains to evaluate.
	CustomDomains []string
}

// SNIResult contains the complete results of an SNI discovery run.
type SNIResult struct {
	ServerIP   string         `json:"server_ip"`
	ServerASN  int            `json:"server_asn"`
	Candidates []SNICandidate `json:"candidates"`
	ScanTime   time.Duration  `json:"scan_time"`
	Timestamp  time.Time      `json:"timestamp"`
}

// CTLogEntry represents a domain discovered from certificate transparency logs.
type CTLogEntry struct {
	Domain    string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
}

// NewSNIFinder creates a new SNI finder with the given configuration.
func NewSNIFinder(cfg SNIFinderConfig, logger *slog.Logger) (*SNIFinder, error) {
	if cfg.ServerIP == "" {
		return nil, fmt.Errorf("server IP is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 20
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}

	return &SNIFinder{
		logger:      logger,
		serverIP:    cfg.ServerIP,
		concurrency: cfg.Concurrency,
		timeout:     cfg.Timeout,
	}, nil
}

// Discover runs the full SNI discovery process and returns ranked candidates.
func (f *SNIFinder) Discover(ctx context.Context) (*SNIResult, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	f.logger.Info("starting SNI discovery", "server_ip", f.serverIP)

	// Step 1: Determine server ASN for proximity scoring.
	asn, err := f.lookupServerASN(ctx)
	if err != nil {
		f.logger.Warn("server ASN lookup failed", "error", err)
	} else {
		f.serverASN = asn
		f.logger.Info("server ASN detected", "asn", asn)
	}

	// Step 2: Gather candidate domains from multiple sources.
	candidates := f.gatherCandidates(ctx)
	f.logger.Info("candidate domains gathered", "count", len(candidates))

	// Step 3: Evaluate all candidates in parallel.
	evaluated := f.evaluateCandidates(ctx, candidates)
	f.logger.Info("candidates evaluated", "viable", len(evaluated))

	// Step 4: Sort by score.
	sort.Slice(evaluated, func(i, j int) bool {
		return evaluated[i].Score > evaluated[j].Score
	})

	result := &SNIResult{
		ServerIP:   f.serverIP,
		ServerASN:  f.serverASN,
		Candidates: evaluated,
		ScanTime:   time.Since(start),
		Timestamp:  time.Now(),
	}

	return result, nil
}

// gatherCandidates collects domain candidates from multiple sources.
func (f *SNIFinder) gatherCandidates(ctx context.Context) []string {
	seen := make(map[string]bool)
	var domains []string

	addDomain := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}

	// Source 1: Well-known high-traffic legitimate sites that commonly
	// support TLS 1.3 and H2.
	wellKnown := []string{
		// Tech companies
		"www.microsoft.com", "www.apple.com", "www.google.com",
		"www.amazon.com", "www.netflix.com", "www.spotify.com",
		"www.twitch.tv", "www.reddit.com", "www.github.com",

		// CDN and infra
		"cloudflare.com", "www.cloudflare.com",
		"www.fastly.com", "www.akamai.com",

		// Software and services
		"www.mozilla.org", "www.docker.com", "www.elastic.co",
		"www.grafana.com", "www.hashicorp.com", "www.jetbrains.com",

		// Enterprise
		"www.oracle.com", "www.cisco.com", "www.ibm.com",
		"www.dell.com", "www.hp.com", "www.samsung.com",
		"www.nvidia.com", "www.intel.com", "www.amd.com",

		// Media and content
		"www.bbc.com", "www.reuters.com", "www.nytimes.com",
		"www.bloomberg.com", "www.cnn.com",

		// E-commerce
		"www.ebay.com", "www.shopify.com", "www.etsy.com",
		"www.aliexpress.com", "www.walmart.com",

		// Education
		"www.mit.edu", "www.harvard.edu", "www.stanford.edu",
		"www.coursera.org", "www.edx.org",
	}
	for _, d := range wellKnown {
		addDomain(d)
	}

	// Source 2: Domains from certificate transparency logs
	// for IPs in the same subnet.
	ctDomains := f.discoverFromCTLogs(ctx)
	for _, d := range ctDomains {
		addDomain(d)
	}

	// Source 3: Reverse DNS lookup for nearby IPs.
	rdnsDomains := f.discoverFromReverseDNS(ctx)
	for _, d := range rdnsDomains {
		addDomain(d)
	}

	return domains
}

// discoverFromCTLogs queries certificate transparency logs to find
// domains that resolve to IPs near the server.
func (f *SNIFinder) discoverFromCTLogs(ctx context.Context) []string {
	// Use crt.sh to search for certificates by IP range.
	// We search for the /24 subnet of the server IP.
	ip := net.ParseIP(f.serverIP)
	if ip == nil {
		return nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil // IPv6 not supported in this lookup.
	}

	// Query crt.sh for certificates matching the /24 prefix.
	// This finds domains hosted on nearby IPs.
	prefix := fmt.Sprintf("%d.%d.%d", ip4[0], ip4[1], ip4[2])

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", prefix)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.logger.Debug("CT log request creation failed", "error", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		f.logger.Debug("CT log query failed", "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil
	}

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		f.logger.Debug("CT log parse failed", "error", err)
		return nil
	}

	var domains []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		for _, name := range []string{entry.CommonName, entry.NameValue} {
			// Clean the domain name.
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")

			// Skip wildcards and invalid entries.
			if name == "" || strings.Contains(name, "*") || strings.Contains(name, " ") {
				continue
			}

			if !seen[name] {
				seen[name] = true
				domains = append(domains, name)
			}
		}

		// Limit to prevent excessive results.
		if len(domains) >= 50 {
			break
		}
	}

	f.logger.Debug("CT log domains found", "count", len(domains))
	return domains
}

// discoverFromReverseDNS performs reverse DNS lookups on IPs near the server.
func (f *SNIFinder) discoverFromReverseDNS(ctx context.Context) []string {
	ip := net.ParseIP(f.serverIP)
	if ip == nil {
		return nil
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	var domains []string
	var mu sync.Mutex

	// Check a few IPs in the same /24 subnet.
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	// Sample some IPs in the /24 range.
	sampled := []byte{1, 2, 3, 10, 20, 50, 100, 128, 200, 250}
	for _, lastOctet := range sampled {
		if lastOctet == ip4[3] {
			continue // Skip our own IP.
		}

		checkIP := fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], lastOctet)

		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer func() { <-sem; wg.Done() }()

			names, err := net.DefaultResolver.LookupAddr(ctx, addr)
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, name := range names {
				name = strings.TrimSuffix(name, ".")
				if name != "" {
					domains = append(domains, name)
				}
			}
		}(checkIP)
	}

	wg.Wait()

	f.logger.Debug("reverse DNS domains found", "count", len(domains))
	return domains
}

// evaluateCandidates tests all candidate domains in parallel and returns
// those that meet the minimum requirements.
func (f *SNIFinder) evaluateCandidates(ctx context.Context, domains []string) []SNICandidate {
	type result struct {
		candidate SNICandidate
		ok        bool
	}

	results := make(chan result, len(domains))
	sem := make(chan struct{}, f.concurrency)

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer func() { <-sem; wg.Done() }()

			c, err := f.evaluateDomain(ctx, d)
			if err != nil {
				f.logger.Debug("domain evaluation failed",
					"domain", d,
					"error", err,
				)
				results <- result{ok: false}
				return
			}
			results <- result{candidate: c, ok: true}
		}(domain)
	}

	// Close results channel when all goroutines complete.
	go func() {
		wg.Wait()
		close(results)
	}()

	var candidates []SNICandidate
	for r := range results {
		if r.ok && r.candidate.Score > 0 {
			candidates = append(candidates, r.candidate)
		}
	}

	return candidates
}

// evaluateDomain performs a comprehensive evaluation of a single domain.
func (f *SNIFinder) evaluateDomain(ctx context.Context, domain string) (SNICandidate, error) {
	c := SNICandidate{Domain: domain}

	// Resolve the domain first.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return c, fmt.Errorf("resolve: %w", err)
	}
	if len(ips) == 0 {
		return c, fmt.Errorf("no IPs resolved")
	}

	// Check ASN proximity.
	if f.serverASN > 0 {
		for _, ip := range ips {
			domainASN, err := f.quickASNLookup(ctx, ip.IP.String())
			if err != nil {
				continue
			}
			if domainASN == f.serverASN {
				c.SameASN = true
				break
			}
			// Within ~100 ASN numbers is considered "nearby" (same provider).
			diff := domainASN - f.serverASN
			if diff < 0 {
				diff = -diff
			}
			if diff < 100 {
				c.NearbyASN = true
			}
		}
	}

	// TLS handshake test: check TLS 1.3 + H2 support and measure latency.
	// We do multiple measurements to get a more accurate latency.
	var totalLatency time.Duration
	attempts := 3
	successCount := 0

	for i := 0; i < attempts; i++ {
		latency, tls13, h2, err := f.tlsHandshake(ctx, domain)
		if err != nil {
			continue
		}
		successCount++
		totalLatency += latency
		c.TLS13 = tls13
		c.H2 = h2
	}

	if successCount == 0 {
		return c, fmt.Errorf("all TLS handshakes failed")
	}

	c.Latency = totalLatency / time.Duration(successCount)

	// TLS 1.3 is a hard requirement for Reality.
	if !c.TLS13 {
		return c, nil // Score will be 0.
	}

	// Compute final score.
	c.Score = f.computeScore(c, successCount, attempts)

	return c, nil
}

// tlsHandshake performs a single TLS handshake and returns metrics.
func (f *SNIFinder) tlsHandshake(ctx context.Context, domain string) (latency time.Duration, tls13, h2 bool, err error) {
	start := time.Now()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return 0, false, false, err
	}
	defer conn.Close()

	latency = time.Since(start)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return latency, false, false, fmt.Errorf("not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	tls13 = state.Version == tls.VersionTLS13
	h2 = state.NegotiatedProtocol == "h2"

	return latency, tls13, h2, nil
}

// quickASNLookup does a fast ASN number lookup using DNS TXT records
// against Team Cymru's service. Falls back to HTTP API.
func (f *SNIFinder) quickASNLookup(ctx context.Context, ip string) (int, error) {
	// Try DNS-based ASN lookup via Team Cymru.
	// Reverse the IP octets and query origin.asn.cymru.com.
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0, fmt.Errorf("invalid IP: %s", ip)
	}

	ip4 := parsedIP.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("IPv6 not supported for ASN lookup")
	}

	dnsQuery := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com",
		ip4[3], ip4[2], ip4[1], ip4[0])

	txts, err := net.DefaultResolver.LookupTXT(ctx, dnsQuery)
	if err == nil && len(txts) > 0 {
		// Format: "ASN | IP/Prefix | CC | Registry | Date"
		parts := strings.SplitN(txts[0], "|", 2)
		if len(parts) > 0 {
			var asn int
			asnStr := strings.TrimSpace(parts[0])
			if _, err := fmt.Sscanf(asnStr, "%d", &asn); err == nil && asn > 0 {
				return asn, nil
			}
		}
	}

	return 0, fmt.Errorf("ASN lookup failed for %s", ip)
}

// lookupServerASN determines the ASN for the server IP.
func (f *SNIFinder) lookupServerASN(ctx context.Context) (int, error) {
	return f.quickASNLookup(ctx, f.serverIP)
}

// computeScore calculates a weighted composite score for a domain.
func (f *SNIFinder) computeScore(c SNICandidate, successCount, attempts int) float64 {
	if !c.TLS13 {
		return 0
	}

	score := 0.0

	// TLS 1.3 support (required, gives base score).
	score += 0.20

	// HTTP/2 support.
	if c.H2 {
		score += 0.15
	}

	// ASN proximity (most important for Reality stealth).
	if c.SameASN {
		score += 0.30
	} else if c.NearbyASN {
		score += 0.15
	}

	// Handshake latency (lower is better).
	// Use a logarithmic scale: <20ms = best, >1000ms = worst.
	if c.Latency > 0 {
		latencyMs := float64(c.Latency.Milliseconds())
		if latencyMs <= 0 {
			latencyMs = 1
		}
		// Map latency to 0-0.20 range using inverse log.
		latencyScore := 0.20 * (1.0 - math.Log10(latencyMs)/math.Log10(1000))
		if latencyScore < 0 {
			latencyScore = 0
		}
		score += latencyScore
	}

	// Connection reliability.
	reliability := float64(successCount) / float64(attempts)
	score += 0.15 * reliability

	return score
}
