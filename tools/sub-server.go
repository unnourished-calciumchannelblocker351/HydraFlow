// sub-server is HydraFlow's smart ISP-aware subscription server.
// It detects the client's ISP from their IP address and returns protocols
// ordered by what works best for that specific ISP — the key differentiator
// of HydraFlow over regular VLESS subscription servers.
//
// Features:
//   - ISP detection via ip-api.com with 1-hour cache
//   - Per-ISP protocol priority based on blocking knowledge
//   - Client telemetry: anonymous reports improve recommendations
//   - Background health checking of all configured protocols
//   - Multi-format output: V2Ray base64, Clash YAML, sing-box JSON, raw JSON
//   - Admin status page with server health overview
//
// Build:  go build -o hydraflow-sub ./tools/sub-server.go
// Usage:  hydraflow-sub [-config /etc/hydraflow/sub-config.json]
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// hashIP returns the first 8 characters of the SHA-256 hex digest of an IP,
// suitable for privacy-preserving log output.
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return fmt.Sprintf("%x", h[:4])
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

// SubConfig is the top-level config read from sub-config.json.
type SubConfig struct {
	ServerIP  string                    `json:"server_ip"`
	Protocols map[string]ProtocolConfig `json:"protocols"`
	SubToken  string                    `json:"sub_token"`
	SubPort   int                       `json:"sub_port"`
}

// ProtocolConfig describes a single protocol available on this server.
type ProtocolConfig struct {
	Port        int    `json:"port"`
	UUID        string `json:"uuid,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	ShortID     string `json:"short_id,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Obfs        string `json:"obfs,omitempty"`
	Password    string `json:"password,omitempty"`
	Method      string `json:"method,omitempty"` // Shadowsocks cipher (e.g. 2022-blake3-aes-256-gcm)
}

// ---------------------------------------------------------------------------
// ISP priority knowledge base
// ---------------------------------------------------------------------------

// ispPriority maps normalized ISP names to protocol order (best first).
// This is the core intelligence of HydraFlow: which protocols survive DPI
// on which ISPs. Entries are updated over time by client telemetry.
var ispPriority = map[string][]string{
	// Russian ISPs
	"megafon":    {"ws-cdn", "grpc-cdn", "xhttp", "shadowtls"},
	"mts":        {"ws-cdn", "grpc-cdn", "reality"},
	"beeline":    {"reality", "ws-cdn", "hysteria2"},
	"tele2":      {"ws-cdn", "reality", "xhttp"},
	"rostelecom": {"ws-cdn", "grpc-cdn", "reality"},
	"domru":      {"reality", "ws-cdn"},
	"yota":       {"ws-cdn", "grpc-cdn", "reality"},
	"ttk":        {"ws-cdn", "grpc-cdn", "reality"},
	// Chinese ISPs
	"china-telecom": {"ws-cdn", "grpc-cdn", "naiveproxy"},
	"china-mobile":  {"ws-cdn", "grpc-cdn"},
	"china-unicom":  {"ws-cdn", "grpc-cdn", "reality"},
	// Iranian ISPs
	"mci":      {"ws-cdn", "grpc-cdn", "fragment"},
	"irancell": {"ws-cdn", "grpc-cdn"},
	// Default fallback
	"default": {"reality", "ws-cdn", "ss", "hysteria2"},
}

// ispBypassSettings contains per-ISP fragment/padding settings for DPI bypass.
// These are injected into xray/Hiddify configs via the subscription.
// Fragment splits TLS ClientHello to bypass SNI-based DPI.
// Padding adds random data to change packet size distribution.
type bypassSettings struct {
	FragmentPackets  string // "tlshello" or "1-3"
	FragmentLength   string // e.g. "1-3", "100-200"
	FragmentInterval string // e.g. "1-5" ms
	PaddingEnabled   bool
	PaddingLength    string // e.g. "100-200"
}

var ispBypass = map[string]*bypassSettings{
	"megafon": {
		FragmentPackets: "tlshello", FragmentLength: "1-3",
		FragmentInterval: "1-3", PaddingEnabled: true, PaddingLength: "100-200",
	},
	"mts": {
		FragmentPackets: "tlshello", FragmentLength: "1-5",
		FragmentInterval: "1-5", PaddingEnabled: true, PaddingLength: "50-100",
	},
	"tele2": {
		FragmentPackets: "tlshello", FragmentLength: "1-3",
		FragmentInterval: "1-3", PaddingEnabled: true, PaddingLength: "100-200",
	},
	"rostelecom": {
		FragmentPackets: "tlshello", FragmentLength: "3-5",
		FragmentInterval: "3-5", PaddingEnabled: false,
	},
	"yota": {
		FragmentPackets: "tlshello", FragmentLength: "1-3",
		FragmentInterval: "1-3", PaddingEnabled: true, PaddingLength: "100-200",
	},
	"mci": {
		FragmentPackets: "tlshello", FragmentLength: "1-5",
		FragmentInterval: "1-5", PaddingEnabled: true, PaddingLength: "50-100",
	},
	"irancell": {
		FragmentPackets: "tlshello", FragmentLength: "1-5",
		FragmentInterval: "1-5", PaddingEnabled: true, PaddingLength: "50-100",
	},
	"china-telecom": {
		FragmentPackets: "1-3", FragmentLength: "1-5",
		FragmentInterval: "1-5", PaddingEnabled: false,
	},
}

// asnToISP maps well-known ASN numbers to normalized ISP names.
var asnToISP = map[int]string{
	// Russia
	31213:  "megafon",
	25159:  "megafon",
	8359:   "mts",
	15640:  "mts",
	3216:   "mts",
	8402:   "mts",
	16345:  "beeline",
	3267:   "beeline",
	12389:  "rostelecom",
	25490:  "rostelecom",
	42610:  "rostelecom",
	15378:  "rostelecom",
	34533:  "tele2",
	47395:  "tele2",
	49048:  "domru",
	197695: "domru",
	47541:  "yota",
	15774:  "ttk",
	20485:  "ttk",
	// China
	4134:  "china-telecom",
	4812:  "china-telecom",
	4837:  "china-unicom",
	17816: "china-unicom",
	9808:  "china-mobile",
	56040: "china-mobile",
	56041: "china-mobile",
	56042: "china-mobile",
	// Iran
	44244:  "irancell",
	197207: "irancell",
	12880:  "mci",
	50810:  "mci",
}

// ---------------------------------------------------------------------------
// ISP lookup with cache
// ---------------------------------------------------------------------------

// ipAPIResponse is the JSON structure returned by ip-api.com.
type ipAPIResponse struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	ISP     string `json:"isp"`
	Org     string `json:"org"`
	AS      string `json:"as"`
	ASN     int    `json:"asn,omitempty"`
	Query   string `json:"query"`
}

// ispCacheEntry stores a cached ISP lookup result.
type ispCacheEntry struct {
	ispName   string
	raw       *ipAPIResponse
	expiresAt time.Time
}

const maxISPCacheSize = 10000

// ispLookup manages ISP detection with caching.
type ispLookup struct {
	mu    sync.RWMutex
	cache map[string]*ispCacheEntry
	ttl   time.Duration
}

func newISPLookup() *ispLookup {
	l := &ispLookup{
		cache: make(map[string]*ispCacheEntry),
		ttl:   1 * time.Hour,
	}
	// Clean expired entries periodically.
	go l.cleanupLoop()
	return l
}

func (l *ispLookup) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for ip, entry := range l.cache {
			if now.After(entry.expiresAt) {
				delete(l.cache, ip)
			}
		}
		l.mu.Unlock()
	}
}

// lookup returns the normalized ISP name for an IP address.
// Falls back to "default" on any error.
func (l *ispLookup) lookup(ip string) (string, *ipAPIResponse) {
	// Check cache first.
	l.mu.RLock()
	if entry, ok := l.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		l.mu.RUnlock()
		return entry.ispName, entry.raw
	}
	l.mu.RUnlock()

	// Skip lookups for private/loopback addresses.
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() {
		return "default", nil
	}

	// Query ip-api.com (free, no key required, 45 req/min).
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,isp,org,as,query", ip))
	if err != nil {
		log.Printf("[isp-lookup] error querying ip-api for %s: %v", hashIP(ip), err)
		return "default", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "default", nil
	}

	var result ipAPIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "default", nil
	}

	if result.Status != "success" {
		return "default", nil
	}

	// Extract ASN number from the "as" field (e.g., "AS31213 PJSC MegaFon").
	asn := 0
	if result.AS != "" {
		fmt.Sscanf(strings.TrimPrefix(result.AS, "AS"), "%d", &asn)
	}
	result.ASN = asn

	// Try ASN-based lookup first (most reliable).
	var ispName string
	if name, ok := asnToISP[asn]; ok {
		ispName = name
	} else {
		ispName = fuzzyMatchISP(result.ISP, result.Org)
	}
	if ispName == "" {
		ispName = "default"
	}

	// Cache result (with eviction if over limit).
	l.mu.Lock()
	if len(l.cache) >= maxISPCacheSize {
		// Delete the oldest entry by expiry time.
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range l.cache {
			if first || v.expiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expiresAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(l.cache, oldestKey)
		}
	}
	l.cache[ip] = &ispCacheEntry{
		ispName:   ispName,
		raw:       &result,
		expiresAt: time.Now().Add(l.ttl),
	}
	l.mu.Unlock()

	log.Printf("[isp-lookup] %s -> ASN %d, ISP=%q, mapped=%q", hashIP(ip), asn, result.ISP, ispName)
	return ispName, &result
}

// fuzzyMatchISP tries to match an ISP/org string to our known ISP names.
func fuzzyMatchISP(isp, org string) string {
	combined := strings.ToLower(isp + " " + org)

	patterns := map[string][]string{
		"megafon":       {"megafon", "мегафон"},
		"mts":           {"mts ", "mobile telesystems", "мтс"},
		"beeline":       {"beeline", "vimpelcom", "билайн"},
		"tele2":         {"tele2", "теле2"},
		"rostelecom":    {"rostelecom", "ростелеком"},
		"domru":         {"dom.ru", "domru", "ertelecom", "дом.ру"},
		"yota":          {"yota", "йота", "scartel"},
		"ttk":           {"ttk", "transtelecom", "транстелеком"},
		"china-telecom": {"china telecom", "chinanet"},
		"china-mobile":  {"china mobile", "cmnet"},
		"china-unicom":  {"china unicom", "unicom"},
		"mci":           {"mobile communication company", "mci ", "hamrah-e-aval"},
		"irancell":      {"irancell", "mtn irancell"},
	}

	for name, keywords := range patterns {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) {
				return name
			}
		}
	}

	return "default"
}

// ---------------------------------------------------------------------------
// Protocol health checker
// ---------------------------------------------------------------------------

// protocolHealth tracks the health status of a protocol.
type protocolHealth struct {
	mu       sync.RWMutex
	statuses map[string]*healthStatus
}

type healthStatus struct {
	Up        bool      `json:"up"`
	LastCheck time.Time `json:"last_check"`
	Latency   int64     `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
}

func newProtocolHealth() *protocolHealth {
	return &protocolHealth{
		statuses: make(map[string]*healthStatus),
	}
}

// startChecking runs background health checks every interval.
func (ph *protocolHealth) startChecking(cfg *SubConfig, interval time.Duration) {
	// Do an initial check immediately.
	ph.checkAll(cfg)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ph.checkAll(cfg)
	}
}

func (ph *protocolHealth) checkAll(cfg *SubConfig) {
	for name, proto := range cfg.Protocols {
		go ph.checkOne(name, cfg.ServerIP, proto)
	}
}

func (ph *protocolHealth) checkOne(name, serverIP string, proto ProtocolConfig) {
	host := serverIP
	if proto.Host != "" && proto.Host != serverIP {
		host = proto.Host
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", proto.Port))

	start := time.Now()
	status := &healthStatus{LastCheck: time.Now()}

	// Try a TCP connection first.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		status.Up = false
		status.Error = fmt.Sprintf("tcp dial: %v", err)
		status.Latency = time.Since(start).Milliseconds()
		ph.set(name, status)
		log.Printf("[health] %s: DOWN (%s)", name, status.Error)
		return
	}

	// If port is 443 or the protocol uses TLS, try a TLS handshake.
	if proto.Port == 443 || proto.SNI != "" {
		sni := proto.SNI
		if sni == "" {
			sni = serverIP
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
		tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		err = tlsConn.Handshake()
		tlsConn.Close()
	} else {
		conn.Close()
	}

	status.Latency = time.Since(start).Milliseconds()
	if err != nil {
		status.Up = false
		status.Error = fmt.Sprintf("tls handshake: %v", err)
		log.Printf("[health] %s: DOWN (%s, %dms)", name, status.Error, status.Latency)
	} else {
		status.Up = true
		log.Printf("[health] %s: UP (%dms)", name, status.Latency)
	}

	ph.set(name, status)
}

func (ph *protocolHealth) set(name string, s *healthStatus) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.statuses[name] = s
}

func (ph *protocolHealth) get(name string) *healthStatus {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	if s, ok := ph.statuses[name]; ok {
		return s
	}
	return &healthStatus{Up: true} // assume up if never checked
}

func (ph *protocolHealth) getAll() map[string]*healthStatus {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	out := make(map[string]*healthStatus, len(ph.statuses))
	for k, v := range ph.statuses {
		cp := *v
		out[k] = &cp
	}
	return out
}

// ---------------------------------------------------------------------------
// Client telemetry (anonymous blocking reports)
// ---------------------------------------------------------------------------

// telemetryReport is what clients POST to /report.
type telemetryReport struct {
	ASN      int    `json:"asn"`
	Protocol string `json:"protocol"`
	Status   string `json:"status"` // "ok", "blocked", "slow"
}

// telemetryStore holds in-memory aggregated telemetry data.
type telemetryStore struct {
	mu      sync.RWMutex
	reports map[string]*ispTelemetry // key: normalized ISP name
	total   int
}

type ispTelemetry struct {
	// Per-protocol counters: protocol -> {ok, blocked, slow}
	Protocols map[string]*protocolTelemetry `json:"protocols"`
}

type protocolTelemetry struct {
	OK      int `json:"ok"`
	Blocked int `json:"blocked"`
	Slow    int `json:"slow"`
}

func newTelemetryStore() *telemetryStore {
	return &telemetryStore{
		reports: make(map[string]*ispTelemetry),
	}
}

func (ts *telemetryStore) record(isp string, report telemetryReport) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.total++

	if _, ok := ts.reports[isp]; !ok {
		ts.reports[isp] = &ispTelemetry{
			Protocols: make(map[string]*protocolTelemetry),
		}
	}

	ispData := ts.reports[isp]
	if _, ok := ispData.Protocols[report.Protocol]; !ok {
		ispData.Protocols[report.Protocol] = &protocolTelemetry{}
	}

	pt := ispData.Protocols[report.Protocol]
	switch report.Status {
	case "ok":
		pt.OK++
	case "blocked":
		pt.Blocked++
	case "slow":
		pt.Slow++
	}
}

// isBlocked returns true if telemetry data suggests a protocol is blocked on this ISP.
// A protocol is considered blocked if >60% of reports say "blocked" and we have at least 10 reports.
func (ts *telemetryStore) isBlocked(isp, protocol string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	ispData, ok := ts.reports[isp]
	if !ok {
		return false
	}
	pt, ok := ispData.Protocols[protocol]
	if !ok {
		return false
	}

	total := pt.OK + pt.Blocked + pt.Slow
	if total < 10 {
		return false
	}
	return float64(pt.Blocked)/float64(total) > 0.6
}

// getSnapshot returns a deep copy of all telemetry data.
func (ts *telemetryStore) getSnapshot() map[string]*ispTelemetry {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make(map[string]*ispTelemetry, len(ts.reports))
	for k, v := range ts.reports {
		ispCopy := &ispTelemetry{
			Protocols: make(map[string]*protocolTelemetry, len(v.Protocols)),
		}
		for pk, pv := range v.Protocols {
			ptCopy := *pv
			ispCopy.Protocols[pk] = &ptCopy
		}
		out[k] = ispCopy
	}
	return out
}

// ---------------------------------------------------------------------------
// Global server state
// ---------------------------------------------------------------------------

var (
	configPath = flag.String("config", "/etc/hydraflow/sub-config.json", "path to subscription config")
	listenAddr = flag.String("listen", "", "override listen address")
)

// reportRateLimiter tracks per-IP report counts for rate limiting.
type reportRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	resetAt time.Time
}

func newReportRateLimiter() *reportRateLimiter {
	return &reportRateLimiter{
		counts:  make(map[string]int),
		resetAt: time.Now().Add(1 * time.Hour),
	}
}

// allow returns true if this IP has not exceeded maxPerHour reports.
func (rl *reportRateLimiter) allow(ip string, maxPerHour int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	if now.After(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = now.Add(1 * time.Hour)
	}
	rl.counts[ip]++
	return rl.counts[ip] <= maxPerHour
}

type server struct {
	cfg           *SubConfig
	isp           *ispLookup
	health        *protocolHealth
	telemetry     *telemetryStore
	reportLimiter *reportRateLimiter
	startTime     time.Time
}

func main() {
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	addr := *listenAddr
	if addr == "" {
		addr = fmt.Sprintf("0.0.0.0:%d", cfg.SubPort)
	}

	srv := &server{
		cfg:           cfg,
		isp:           newISPLookup(),
		health:        newProtocolHealth(),
		telemetry:     newTelemetryStore(),
		reportLimiter: newReportRateLimiter(),
		startTime:     time.Now(),
	}

	// Start background health checks every 5 minutes.
	go srv.health.startChecking(cfg, 5*time.Minute)

	mux := http.NewServeMux()

	// Subscription endpoint: /sub/{token}
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		srv.handleSubscription(w, r)
	})

	// Client telemetry endpoint.
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		srv.handleReport(w, r)
	})

	// Admin status page: /admin/{token}/status
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		srv.handleAdmin(w, r)
	})

	// Health check (simple).
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"time":   time.Now().UTC().Format(time.RFC3339),
			"uptime": time.Since(srv.startTime).String(),
		})
	})

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("HydraFlow Smart Subscription Server starting on %s", addr)
	log.Printf("Subscription URL: http://%s:%d/sub/%s", cfg.ServerIP, cfg.SubPort, cfg.SubToken)
	log.Printf("Configured protocols: %s", strings.Join(protocolNames(cfg), ", "))
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func protocolNames(cfg *SubConfig) []string {
	names := make([]string, 0, len(cfg.Protocols))
	for name := range cfg.Protocols {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

func loadConfig(path string) (*SubConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg SubConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.SubToken == "" {
		return nil, fmt.Errorf("sub_token is required in config")
	}
	if cfg.ServerIP == "" {
		return nil, fmt.Errorf("server_ip is required in config")
	}
	if len(cfg.Protocols) == 0 {
		return nil, fmt.Errorf("at least one protocol must be configured")
	}
	if cfg.SubPort == 0 {
		cfg.SubPort = 10086
	}

	return &cfg, nil
}

// ---------------------------------------------------------------------------
// Subscription handler (the main brain)
// ---------------------------------------------------------------------------

func (s *server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract and validate token from URL: /sub/{token}
	pathToken := strings.TrimPrefix(r.URL.Path, "/sub/")
	pathToken = strings.TrimSuffix(pathToken, "/")

	if pathToken == "" || subtle.ConstantTimeCompare([]byte(pathToken), []byte(s.cfg.SubToken)) != 1 {
		http.NotFound(w, r)
		return
	}

	// Step 1: Detect client ISP.
	clientIP := extractClientIP(r)
	ispName, ispInfo := s.isp.lookup(clientIP)

	log.Printf("[sub] client=%s isp=%s format=%s ua=%s",
		hashIP(clientIP), ispName, r.URL.Query().Get("format"), r.UserAgent())

	// Step 2: Get protocol priority for this ISP.
	ordered := s.buildProtocolList(ispName)

	// Step 3: Determine output format.
	format := detectFormat(r)

	// Step 4: Set common headers.
	s.setSubHeaders(w, ispName)

	// Step 5: Serve in requested format.
	switch format {
	case "clash":
		s.serveClash(w, ordered, ispName)
	case "singbox":
		s.serveSingBox(w, ordered, ispName)
	case "json":
		s.serveJSON(w, ordered, ispName, ispInfo)
	default:
		s.serveV2Ray(w, ordered, ispName)
	}
}

// orderedProtocol is a protocol with its priority metadata.
type orderedProtocol struct {
	Name      string
	Config    ProtocolConfig
	Label     string // human-readable label with recommendation
	Rank      int    // 0=recommended, 1=available, 2=fallback (down)
	HealthUp  bool
	LatencyMs int64
}

// buildProtocolList produces a list of available protocols ordered by ISP priority,
// with health status and telemetry-informed blocking taken into account.
func (s *server) buildProtocolList(ispName string) []orderedProtocol {
	// Get priority order for this ISP.
	priority, ok := ispPriority[ispName]
	if !ok {
		priority = ispPriority["default"]
	}

	// Build a set of configured protocols on this server.
	configured := make(map[string]bool)
	for name := range s.cfg.Protocols {
		configured[name] = true
	}

	// Also create a mapping from generic priority names to actual protocol names.
	// e.g., "ws-cdn" could match "ws" protocol; "grpc-cdn" could match "grpc".
	priorityToActual := map[string]string{
		"ws-cdn":   "ws",
		"grpc-cdn": "grpc",
	}
	for name := range s.cfg.Protocols {
		priorityToActual[name] = name
	}

	// Track which protocols we've already added to avoid duplicates.
	added := make(map[string]bool)
	var result []orderedProtocol

	// First pass: add protocols in ISP priority order.
	rank := 0
	for _, pName := range priority {
		actual := pName
		if mapped, ok := priorityToActual[pName]; ok {
			actual = mapped
		}
		proto, exists := s.cfg.Protocols[actual]
		if !exists {
			continue
		}
		if added[actual] {
			continue
		}

		// Check if telemetry says this is blocked.
		if s.telemetry.isBlocked(ispName, actual) {
			continue
		}

		hs := s.health.get(actual)

		label := "HydraFlow-" + formatProtocolName(actual)
		if rank == 0 {
			label += " (recommended)"
		} else {
			label += " (fallback)"
		}

		result = append(result, orderedProtocol{
			Name:      actual,
			Config:    proto,
			Label:     label,
			Rank:      rank,
			HealthUp:  hs.Up,
			LatencyMs: hs.Latency,
		})
		added[actual] = true
		rank++
	}

	// Second pass: add any remaining configured protocols not in the priority list.
	remaining := make([]string, 0)
	for name := range s.cfg.Protocols {
		if !added[name] {
			remaining = append(remaining, name)
		}
	}
	sort.Strings(remaining)

	for _, name := range remaining {
		proto := s.cfg.Protocols[name]

		// Check if telemetry says this is blocked.
		if s.telemetry.isBlocked(ispName, name) {
			continue
		}

		hs := s.health.get(name)

		label := "HydraFlow-" + formatProtocolName(name)
		label += " (fallback)"

		result = append(result, orderedProtocol{
			Name:      name,
			Config:    proto,
			Label:     label,
			Rank:      rank,
			HealthUp:  hs.Up,
			LatencyMs: hs.Latency,
		})
		added[name] = true
		rank++
	}

	// Move down protocols to the end of the list.
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].HealthUp != result[j].HealthUp {
			return result[i].HealthUp
		}
		return false
	})

	return result
}

// formatProtocolName produces a clean display name for a protocol key.
func formatProtocolName(name string) string {
	replacer := strings.NewReplacer(
		"reality", "Reality",
		"ws", "WS-CDN",
		"grpc", "gRPC-CDN",
		"xhttp", "XHTTP",
		"ss", "SS-2022",
		"hysteria2", "Hysteria2",
		"shadowtls", "ShadowTLS",
		"naiveproxy", "NaiveProxy",
	)
	result := replacer.Replace(name)
	if result == name {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return result
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

func detectFormat(r *http.Request) string {
	if f := r.URL.Query().Get("format"); f != "" {
		switch strings.ToLower(f) {
		case "clash", "clashmeta", "clash-meta":
			return "clash"
		case "singbox", "sing-box", "sb":
			return "singbox"
		case "v2ray", "base64", "b64":
			return "v2ray"
		case "json":
			return "json"
		}
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "clash") || strings.Contains(ua, "stash") || strings.Contains(ua, "mihomo"):
		return "clash"
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox") || strings.Contains(ua, "sfi") || strings.Contains(ua, "sfa"):
		return "singbox"
	case strings.Contains(ua, "v2ray") || strings.Contains(ua, "v2rayn") ||
		strings.Contains(ua, "v2rayng") || strings.Contains(ua, "hiddify") ||
		strings.Contains(ua, "nekoray") || strings.Contains(ua, "nekobox") ||
		strings.Contains(ua, "streisand") || strings.Contains(ua, "shadowrocket"):
		return "v2ray"
	}

	return "v2ray"
}

// ---------------------------------------------------------------------------
// Common headers
// ---------------------------------------------------------------------------

func (s *server) setSubHeaders(w http.ResponseWriter, ispName string) {
	w.Header().Set("Subscription-UserInfo", fmt.Sprintf(
		"upload=0; download=0; total=107374182400; expire=%d",
		time.Now().Add(30*24*time.Hour).Unix(),
	))
	w.Header().Set("Profile-Update-Interval", "6")
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString(
		[]byte("HydraFlow")))
	w.Header().Set("X-HydraFlow-ISP", ispName)
}

// ---------------------------------------------------------------------------
// V2Ray base64 format
// ---------------------------------------------------------------------------

func (s *server) serveV2Ray(w http.ResponseWriter, protocols []orderedProtocol, ispName string) {
	var links []string

	for _, p := range protocols {
		link := s.buildV2RayLinkForISP(p, ispName)
		if link != "" {
			links = append(links, link)
		}
	}

	if len(links) == 0 {
		http.Error(w, "no protocols available", http.StatusServiceUnavailable)
		return
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"hydraflow.txt\"")
	w.Write([]byte(encoded))
}

func (s *server) buildV2RayLink(p orderedProtocol) string {
	return s.buildV2RayLinkForISP(p, "")
}

func (s *server) buildV2RayLinkForISP(p orderedProtocol, ispName string) string {
	cfg := p.Config
	serverIP := s.cfg.ServerIP
	params := url.Values{}
	label := url.PathEscape(p.Label)

	// Add fragment/bypass settings if this ISP needs them.
	// Hiddify and v2rayN support fragment in VLESS URL params.
	if bypass, ok := ispBypass[ispName]; ok && bypass != nil {
		if bypass.FragmentPackets != "" {
			params.Set("fragment", bypass.FragmentPackets+","+bypass.FragmentLength+","+bypass.FragmentInterval)
		}
	}

	switch p.Name {
	case "reality":
		params.Set("security", "reality")
		params.Set("sni", cfg.SNI)
		params.Set("fp", coalesce(cfg.Fingerprint, "chrome"))
		params.Set("pbk", cfg.PublicKey)
		params.Set("sid", cfg.ShortID)
		params.Set("type", "tcp")
		params.Set("flow", coalesce(cfg.Flow, "xtls-rprx-vision"))
		params.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, serverIP, cfg.Port, params.Encode(), label)

	case "ws":
		host := coalesce(cfg.Host, serverIP)
		params.Set("security", "tls")
		params.Set("type", "ws")
		params.Set("path", cfg.Path)
		params.Set("host", host)
		params.Set("sni", coalesce(cfg.SNI, host))
		params.Set("fp", coalesce(cfg.Fingerprint, "chrome"))
		params.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, host, cfg.Port, params.Encode(), label)

	case "grpc":
		host := coalesce(cfg.Host, serverIP)
		params.Set("security", "tls")
		params.Set("type", "grpc")
		params.Set("serviceName", cfg.ServiceName)
		params.Set("host", host)
		params.Set("sni", coalesce(cfg.SNI, host))
		params.Set("fp", coalesce(cfg.Fingerprint, "chrome"))
		params.Set("encryption", "none")
		params.Set("mode", "gun")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, host, cfg.Port, params.Encode(), label)

	case "xhttp":
		host := coalesce(cfg.Host, serverIP)
		params.Set("security", "tls")
		params.Set("type", "xhttp")
		params.Set("path", cfg.Path)
		params.Set("host", host)
		params.Set("sni", coalesce(cfg.SNI, host))
		params.Set("fp", coalesce(cfg.Fingerprint, "chrome"))
		params.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, host, cfg.Port, params.Encode(), label)

	case "hysteria2":
		params.Set("sni", cfg.SNI)
		if cfg.Obfs != "" {
			params.Set("obfs", "salamander")
			params.Set("obfs-password", cfg.Obfs)
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
			coalesce(cfg.Password, cfg.UUID), serverIP, cfg.Port, params.Encode(), label)

	case "ss":
		// Shadowsocks-2022: ss://base64(method:password)@host:port#label
		method := coalesce(cfg.Method, "2022-blake3-aes-256-gcm")
		userInfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + cfg.Password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, serverIP, cfg.Port, label)

	case "shadowtls":
		// ShadowTLS typically needs custom handling; output a generic VLESS link.
		params.Set("security", "tls")
		params.Set("type", "tcp")
		params.Set("sni", cfg.SNI)
		params.Set("fp", coalesce(cfg.Fingerprint, "chrome"))
		params.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, serverIP, cfg.Port, params.Encode(), label)

	default:
		// Generic VLESS link.
		params.Set("security", "none")
		params.Set("type", "tcp")
		params.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			cfg.UUID, serverIP, cfg.Port, params.Encode(), label)
	}
}

// ---------------------------------------------------------------------------
// Clash Meta YAML format
// ---------------------------------------------------------------------------

func (s *server) serveClash(w http.ResponseWriter, protocols []orderedProtocol, ispName string) {
	var b strings.Builder

	b.WriteString("# HydraFlow Smart Subscription - Clash Meta\n")
	b.WriteString(fmt.Sprintf("# ISP detected: %s | Generated: %s\n\n", ispName, time.Now().UTC().Format(time.RFC3339)))

	b.WriteString("mixed-port: 7890\n")
	b.WriteString("allow-lan: false\n")
	b.WriteString("mode: rule\n")
	b.WriteString("log-level: info\n")
	b.WriteString("external-controller: 127.0.0.1:9090\n\n")

	// DNS.
	b.WriteString("dns:\n")
	b.WriteString("  enable: true\n")
	b.WriteString("  enhanced-mode: fake-ip\n")
	b.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	b.WriteString("  nameserver:\n")
	b.WriteString("    - https://dns.google/dns-query\n")
	b.WriteString("    - https://cloudflare-dns.com/dns-query\n")
	b.WriteString("  fallback:\n")
	b.WriteString("    - https://1.0.0.1/dns-query\n")
	b.WriteString("    - https://8.8.4.4/dns-query\n")
	b.WriteString("  fallback-filter:\n")
	b.WriteString("    geoip: true\n")
	b.WriteString("    geoip-code: CN\n\n")

	// Proxies.
	b.WriteString("proxies:\n")
	var proxyNames []string
	for _, p := range protocols {
		proxy := s.buildClashProxy(p)
		if proxy != "" {
			b.WriteString(proxy)
			proxyNames = append(proxyNames, p.Label)
		}
	}
	b.WriteString("\n")

	// Proxy groups.
	b.WriteString("proxy-groups:\n")
	b.WriteString("  - name: proxy\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	b.WriteString("      - auto\n")
	for _, name := range proxyNames {
		fmt.Fprintf(&b, "      - \"%s\"\n", name)
	}
	b.WriteString("\n")

	b.WriteString("  - name: auto\n")
	b.WriteString("    type: url-test\n")
	b.WriteString("    proxies:\n")
	for _, name := range proxyNames {
		fmt.Fprintf(&b, "      - \"%s\"\n", name)
	}
	b.WriteString("    url: https://www.gstatic.com/generate_204\n")
	b.WriteString("    interval: 300\n")
	b.WriteString("    tolerance: 50\n\n")

	b.WriteString("  - name: fallback\n")
	b.WriteString("    type: fallback\n")
	b.WriteString("    proxies:\n")
	for _, name := range proxyNames {
		fmt.Fprintf(&b, "      - \"%s\"\n", name)
	}
	b.WriteString("    url: https://www.gstatic.com/generate_204\n")
	b.WriteString("    interval: 300\n\n")

	// Rules — split tunneling: Russian sites go DIRECT to avoid VPN detection.
	b.WriteString("rules:\n")
	b.WriteString("  - DOMAIN-SUFFIX,ya.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,yandex.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,yandex.com,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,yandex.net,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,vk.com,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,vk.me,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,vkontakte.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,mail.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,ok.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,ozon.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,ozon.travel,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,wildberries.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,wb.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,sber.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,sberbank.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,gosuslugi.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,mos.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,nalog.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,nalog.gov.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,avito.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,cian.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,hh.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,tinkoff.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,alfa-bank.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,vtb.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,ria.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,rbc.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,tass.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,rt.com,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,1tv.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,kinopoisk.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,ivi.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,okko.tv,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,rutube.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,dzen.ru,DIRECT\n")
	b.WriteString("  - DOMAIN-SUFFIX,vkusvill.ru,DIRECT\n")
	b.WriteString("  - GEOSITE,category-ru,DIRECT\n")
	b.WriteString("  - GEOIP,PRIVATE,DIRECT\n")
	b.WriteString("  - GEOSITE,category-ads-all,REJECT\n")
	b.WriteString("  - GEOIP,CN,DIRECT\n")
	b.WriteString("  - GEOIP,RU,DIRECT\n")
	b.WriteString("  - MATCH,proxy\n")

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"clash.yml\"")
	w.Write([]byte(b.String()))
}

func (s *server) buildClashProxy(p orderedProtocol) string {
	cfg := p.Config
	serverIP := s.cfg.ServerIP
	var b strings.Builder

	fmt.Fprintf(&b, "  - name: \"%s\"\n", p.Label)

	switch p.Name {
	case "reality":
		b.WriteString("    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", serverIP)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", cfg.UUID)
		b.WriteString("    network: tcp\n")
		b.WriteString("    tls: true\n")
		b.WriteString("    udp: true\n")
		fmt.Fprintf(&b, "    flow: %s\n", coalesce(cfg.Flow, "xtls-rprx-vision"))
		fmt.Fprintf(&b, "    servername: %s\n", cfg.SNI)
		fmt.Fprintf(&b, "    client-fingerprint: %s\n", coalesce(cfg.Fingerprint, "chrome"))
		b.WriteString("    reality-opts:\n")
		fmt.Fprintf(&b, "      public-key: %s\n", cfg.PublicKey)
		fmt.Fprintf(&b, "      short-id: %s\n", cfg.ShortID)

	case "ws":
		host := coalesce(cfg.Host, serverIP)
		b.WriteString("    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", host)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", cfg.UUID)
		b.WriteString("    network: ws\n")
		b.WriteString("    tls: true\n")
		b.WriteString("    udp: true\n")
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "    servername: %s\n", cfg.SNI)
		} else {
			fmt.Fprintf(&b, "    servername: %s\n", host)
		}
		b.WriteString("    ws-opts:\n")
		fmt.Fprintf(&b, "      path: %s\n", cfg.Path)
		b.WriteString("      headers:\n")
		fmt.Fprintf(&b, "        Host: %s\n", host)

	case "grpc":
		host := coalesce(cfg.Host, serverIP)
		b.WriteString("    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", host)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", cfg.UUID)
		b.WriteString("    network: grpc\n")
		b.WriteString("    tls: true\n")
		b.WriteString("    udp: true\n")
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "    servername: %s\n", cfg.SNI)
		} else {
			fmt.Fprintf(&b, "    servername: %s\n", host)
		}
		b.WriteString("    grpc-opts:\n")
		fmt.Fprintf(&b, "      grpc-service-name: %s\n", cfg.ServiceName)

	case "xhttp":
		host := coalesce(cfg.Host, serverIP)
		b.WriteString("    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", host)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", cfg.UUID)
		b.WriteString("    network: xhttp\n")
		b.WriteString("    tls: true\n")
		b.WriteString("    udp: true\n")
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "    servername: %s\n", cfg.SNI)
		} else {
			fmt.Fprintf(&b, "    servername: %s\n", host)
		}
		b.WriteString("    xhttp-opts:\n")
		fmt.Fprintf(&b, "      path: %s\n", cfg.Path)

	case "ss":
		method := coalesce(cfg.Method, "2022-blake3-aes-256-gcm")
		b.WriteString("    type: ss\n")
		fmt.Fprintf(&b, "    server: %s\n", serverIP)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    cipher: %s\n", method)
		fmt.Fprintf(&b, "    password: \"%s\"\n", cfg.Password)
		b.WriteString("    udp: true\n")

	case "hysteria2":
		b.WriteString("    type: hysteria2\n")
		fmt.Fprintf(&b, "    server: %s\n", serverIP)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    password: %s\n", coalesce(cfg.Password, cfg.UUID))
		if cfg.Obfs != "" {
			b.WriteString("    obfs: salamander\n")
			fmt.Fprintf(&b, "    obfs-password: %s\n", cfg.Obfs)
		}
		if cfg.SNI != "" {
			fmt.Fprintf(&b, "    sni: %s\n", cfg.SNI)
		}

	default:
		b.WriteString("    type: vless\n")
		fmt.Fprintf(&b, "    server: %s\n", serverIP)
		fmt.Fprintf(&b, "    port: %d\n", cfg.Port)
		fmt.Fprintf(&b, "    uuid: %s\n", cfg.UUID)
		b.WriteString("    network: tcp\n")
		b.WriteString("    udp: true\n")
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// sing-box JSON format
// ---------------------------------------------------------------------------

func (s *server) serveSingBox(w http.ResponseWriter, protocols []orderedProtocol, ispName string) {
	outbounds := make([]interface{}, 0, len(protocols)+5)
	outboundNames := make([]string, 0, len(protocols))

	for _, p := range protocols {
		outboundNames = append(outboundNames, p.Label)
	}

	// Selector and urltest groups.
	outbounds = append(outbounds,
		map[string]interface{}{
			"type":      "selector",
			"tag":       "proxy",
			"outbounds": append([]string{"auto"}, outboundNames...),
			"default":   "auto",
		},
		map[string]interface{}{
			"type":      "urltest",
			"tag":       "auto",
			"outbounds": outboundNames,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  "3m",
			"tolerance": 50,
		},
	)

	// Protocol outbounds.
	for _, p := range protocols {
		ob := s.buildSingBoxOutbound(p)
		if ob != nil {
			outbounds = append(outbounds, ob)
		}
	}

	// System outbounds.
	outbounds = append(outbounds,
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "block", "tag": "block"},
		map[string]interface{}{"type": "dns", "tag": "dns-out"},
	)

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":              "google",
					"address":          "https://dns.google/dns-query",
					"address_resolver": "local",
					"detour":           "proxy",
				},
				{
					"tag":     "local",
					"address": "local",
					"detour":  "direct",
				},
			},
			"rules": []map[string]interface{}{
				{"outbound": []string{"any"}, "server": "local"},
			},
		},
		"inbounds": []map[string]interface{}{
			{
				"type":                       "tun",
				"tag":                        "tun-in",
				"inet4_address":              "172.19.0.1/30",
				"auto_route":                 true,
				"strict_route":               true,
				"stack":                      "system",
				"sniff":                      true,
				"sniff_override_destination": true,
			},
		},
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"rules": []map[string]interface{}{
				{"protocol": "dns", "outbound": "dns-out"},
				{
					"domain_suffix": []string{
						".ya.ru", ".yandex.ru", ".yandex.com", ".yandex.net",
						".vk.com", ".vk.me", ".vkontakte.ru", ".vkusvill.ru",
						".mail.ru", ".ok.ru",
						".ozon.ru", ".ozon.travel",
						".wildberries.ru", ".wb.ru",
						".sber.ru", ".sberbank.ru",
						".gosuslugi.ru", ".mos.ru", ".nalog.ru", ".nalog.gov.ru",
						".avito.ru", ".cian.ru", ".hh.ru",
						".tinkoff.ru", ".alfa-bank.ru", ".vtb.ru",
						".ria.ru", ".rbc.ru", ".tass.ru", ".rt.com", ".1tv.ru",
						".kinopoisk.ru", ".ivi.ru", ".okko.tv",
						".rutube.ru", ".dzen.ru",
					},
					"outbound": "direct",
				},
				{"geosite": []string{"category-ru"}, "outbound": "direct"},
				{"geoip": []string{"ru"}, "outbound": "direct"},
				{"geoip": []string{"private"}, "outbound": "direct"},
				{"geosite": []string{"category-ads-all"}, "outbound": "block"},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"singbox.json\"")
	w.Write(data)
}

func (s *server) buildSingBoxOutbound(p orderedProtocol) map[string]interface{} {
	cfg := p.Config
	serverIP := s.cfg.ServerIP

	switch p.Name {
	case "reality":
		return map[string]interface{}{
			"type":        "vless",
			"tag":         p.Label,
			"server":      serverIP,
			"server_port": cfg.Port,
			"uuid":        cfg.UUID,
			"flow":        coalesce(cfg.Flow, "xtls-rprx-vision"),
			"tls": map[string]interface{}{
				"enabled":     true,
				"server_name": cfg.SNI,
				"utls": map[string]interface{}{
					"enabled":     true,
					"fingerprint": coalesce(cfg.Fingerprint, "chrome"),
				},
				"reality": map[string]interface{}{
					"enabled":    true,
					"public_key": cfg.PublicKey,
					"short_id":   cfg.ShortID,
				},
			},
		}

	case "ws":
		host := coalesce(cfg.Host, serverIP)
		ob := map[string]interface{}{
			"type":        "vless",
			"tag":         p.Label,
			"server":      host,
			"server_port": cfg.Port,
			"uuid":        cfg.UUID,
			"tls": map[string]interface{}{
				"enabled":     true,
				"server_name": coalesce(cfg.SNI, host),
				"utls": map[string]interface{}{
					"enabled":     true,
					"fingerprint": coalesce(cfg.Fingerprint, "chrome"),
				},
			},
			"transport": map[string]interface{}{
				"type":    "ws",
				"path":    cfg.Path,
				"headers": map[string]string{"Host": host},
			},
		}
		return ob

	case "grpc":
		host := coalesce(cfg.Host, serverIP)
		return map[string]interface{}{
			"type":        "vless",
			"tag":         p.Label,
			"server":      host,
			"server_port": cfg.Port,
			"uuid":        cfg.UUID,
			"tls": map[string]interface{}{
				"enabled":     true,
				"server_name": coalesce(cfg.SNI, host),
				"utls": map[string]interface{}{
					"enabled":     true,
					"fingerprint": coalesce(cfg.Fingerprint, "chrome"),
				},
			},
			"transport": map[string]interface{}{
				"type":         "grpc",
				"service_name": cfg.ServiceName,
			},
		}

	case "xhttp":
		host := coalesce(cfg.Host, serverIP)
		return map[string]interface{}{
			"type":        "vless",
			"tag":         p.Label,
			"server":      host,
			"server_port": cfg.Port,
			"uuid":        cfg.UUID,
			"tls": map[string]interface{}{
				"enabled":     true,
				"server_name": coalesce(cfg.SNI, host),
				"utls": map[string]interface{}{
					"enabled":     true,
					"fingerprint": coalesce(cfg.Fingerprint, "chrome"),
				},
			},
			"transport": map[string]interface{}{
				"type": "httpupgrade",
				"path": cfg.Path,
				"host": host,
			},
		}

	case "ss":
		method := coalesce(cfg.Method, "2022-blake3-aes-256-gcm")
		return map[string]interface{}{
			"type":        "shadowsocks",
			"tag":         p.Label,
			"server":      serverIP,
			"server_port": cfg.Port,
			"method":      method,
			"password":    cfg.Password,
		}

	case "hysteria2":
		ob := map[string]interface{}{
			"type":        "hysteria2",
			"tag":         p.Label,
			"server":      serverIP,
			"server_port": cfg.Port,
			"password":    coalesce(cfg.Password, cfg.UUID),
		}
		if cfg.Obfs != "" {
			ob["obfs"] = map[string]interface{}{
				"type":     "salamander",
				"password": cfg.Obfs,
			}
		}
		if cfg.SNI != "" {
			ob["tls"] = map[string]interface{}{
				"enabled":     true,
				"server_name": cfg.SNI,
			}
		}
		return ob

	default:
		return map[string]interface{}{
			"type":        "vless",
			"tag":         p.Label,
			"server":      serverIP,
			"server_port": cfg.Port,
			"uuid":        cfg.UUID,
		}
	}
}

// ---------------------------------------------------------------------------
// Raw JSON format
// ---------------------------------------------------------------------------

func (s *server) serveJSON(w http.ResponseWriter, protocols []orderedProtocol, ispName string, ispInfo *ipAPIResponse) {
	type protoJSON struct {
		Name      string `json:"name"`
		Label     string `json:"label"`
		Protocol  string `json:"protocol"`
		Rank      int    `json:"rank"`
		HealthUp  bool   `json:"health_up"`
		LatencyMs int64  `json:"latency_ms"`
		Port      int    `json:"port"`
	}

	protos := make([]protoJSON, 0, len(protocols))
	for _, p := range protocols {
		protos = append(protos, protoJSON{
			Name:      p.Name,
			Label:     p.Label,
			Protocol:  p.Name,
			Rank:      p.Rank,
			HealthUp:  p.HealthUp,
			LatencyMs: p.LatencyMs,
			Port:      p.Config.Port,
		})
	}

	result := map[string]interface{}{
		"isp":       ispName,
		"server":    s.cfg.ServerIP,
		"generated": time.Now().UTC().Format(time.RFC3339),
		"protocols": protos,
	}
	if ispInfo != nil {
		result["isp_detail"] = map[string]interface{}{
			"name":    ispInfo.ISP,
			"org":     ispInfo.Org,
			"as":      ispInfo.AS,
			"country": ispInfo.Country,
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result)
}

// ---------------------------------------------------------------------------
// Client telemetry endpoint
// ---------------------------------------------------------------------------

func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: max 3 reports per IP per hour.
	clientIP := extractClientIP(r)
	if !s.reportLimiter.allow(clientIP, 3) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	var report telemetryReport
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&report); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if report.Protocol == "" || report.Status == "" {
		http.Error(w, "protocol and status are required", http.StatusBadRequest)
		return
	}

	// Validate status value.
	switch report.Status {
	case "ok", "blocked", "slow":
		// valid
	default:
		http.Error(w, "status must be ok, blocked, or slow", http.StatusBadRequest)
		return
	}

	// Determine ISP: use reported ASN if available, otherwise detect from IP.
	ispName := "default"
	if report.ASN > 0 {
		if name, ok := asnToISP[report.ASN]; ok {
			ispName = name
		}
	}
	if ispName == "default" {
		clientIP := extractClientIP(r)
		ispName, _ = s.isp.lookup(clientIP)
	}

	s.telemetry.record(ispName, report)

	log.Printf("[telemetry] isp=%s protocol=%s status=%s", ispName, report.Protocol, report.Status)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "recorded",
		"isp":    ispName,
	})
}

// ---------------------------------------------------------------------------
// Admin status page
// ---------------------------------------------------------------------------

func (s *server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token: /admin/{token}/status
	path := strings.TrimPrefix(r.URL.Path, "/admin/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[1] != "status" {
		http.NotFound(w, r)
		return
	}

	token := parts[0]
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.SubToken)) != 1 {
		http.NotFound(w, r)
		return
	}

	// Build status response.
	healthStatuses := s.health.getAll()
	telemetrySnapshot := s.telemetry.getSnapshot()

	// Gather ISP cache stats.
	s.isp.mu.RLock()
	ispCacheCount := len(s.isp.cache)
	ispEntries := make(map[string]string, len(s.isp.cache))
	for ip, entry := range s.isp.cache {
		ispEntries[ip] = entry.ispName
	}
	s.isp.mu.RUnlock()

	// Build protocol health map.
	healthMap := make(map[string]interface{}, len(healthStatuses))
	for name, hs := range healthStatuses {
		healthMap[name] = map[string]interface{}{
			"up":         hs.Up,
			"last_check": hs.LastCheck.Format(time.RFC3339),
			"latency_ms": hs.Latency,
			"error":      hs.Error,
		}
	}

	// Build ISP recommendation overview.
	ispRecommendations := make(map[string][]string)
	for ispName, priority := range ispPriority {
		// Filter to only configured protocols.
		var available []string
		for _, pName := range priority {
			actual := pName
			mapped := map[string]string{"ws-cdn": "ws", "grpc-cdn": "grpc"}
			if m, ok := mapped[pName]; ok {
				actual = m
			}
			if _, exists := s.cfg.Protocols[actual]; exists {
				available = append(available, pName)
			}
		}
		if len(available) > 0 {
			ispRecommendations[ispName] = available
		}
	}

	// Build telemetry summary.
	telemetryMap := make(map[string]interface{}, len(telemetrySnapshot))
	for isp, data := range telemetrySnapshot {
		telemetryMap[isp] = data.Protocols
	}

	status := map[string]interface{}{
		"server": map[string]interface{}{
			"uptime":    time.Since(s.startTime).String(),
			"started":   s.startTime.Format(time.RFC3339),
			"server_ip": s.cfg.ServerIP,
			"sub_port":  s.cfg.SubPort,
			"protocols": protocolNames(s.cfg),
		},
		"health":              healthMap,
		"isp_cache_count":     ispCacheCount,
		"isp_clients":         ispEntries,
		"isp_recommendations": ispRecommendations,
		"telemetry":           telemetryMap,
		"telemetry_total":     s.telemetry.total,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// extractClientIP extracts the client IP from the request.
// Proxy headers (X-Forwarded-For, X-Real-IP) are only trusted when
// the direct peer is localhost, preventing spoofing from the internet.
func extractClientIP(r *http.Request) string {
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peerIP == "" {
		peerIP = r.RemoteAddr
	}
	trusted := peerIP == "127.0.0.1" || peerIP == "::1"

	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	return peerIP
}

// coalesce returns the first non-empty string.
func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
