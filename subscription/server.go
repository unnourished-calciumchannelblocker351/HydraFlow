package subscription

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SubServerConfig configures the subscription HTTP server.
type SubServerConfig struct {
	// Listen is the address to serve subscriptions on.
	Listen string `yaml:"listen"`

	// Token is the bearer token for authentication.
	Token string `yaml:"token"`

	// RateLimit is the maximum requests per minute per IP.
	RateLimit int `yaml:"rate_limit"`

	// BaseSub is the base subscription template to serve.
	BaseSub *Subscription `yaml:"-"`
}

// SubServer serves smart subscriptions over HTTP with content negotiation,
// per-client UUID generation, rate limiting, and token-based auth.
type SubServer struct {
	config  SubServerConfig
	logger  *slog.Logger
	server  *http.Server
	limiter *rateLimiter

	mu      sync.RWMutex
	baseSub *Subscription

	// clientUUIDs maps client tokens/identifiers to their unique UUIDs.
	clientUUIDs map[string]string
}

// NewSubServer creates a new subscription server.
func NewSubServer(cfg SubServerConfig, logger *slog.Logger) (*SubServer, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:10086"
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("subscription token is required")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 30 // 30 requests per minute per IP.
	}
	if logger == nil {
		logger = slog.Default()
	}

	s := &SubServer{
		config:      cfg,
		logger:      logger,
		limiter:     newRateLimiter(cfg.RateLimit, time.Minute),
		baseSub:     cfg.BaseSub,
		clientUUIDs: make(map[string]string),
	}

	return s, nil
}

// SetSubscription updates the base subscription template that is served
// to clients. This can be called at runtime to update configs.
func (s *SubServer) SetSubscription(sub *Subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baseSub = sub
	s.logger.Info("subscription template updated",
		"protocols", len(sub.Protocols),
		"version", sub.Version,
	)
}

// Start begins serving subscriptions. It blocks until the context
// is cancelled or Stop is called.
func (s *SubServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/sub", s.handleSubscription)
	mux.HandleFunc("/sub/", s.handleSubscription)
	mux.HandleFunc("/health", s.handleHealth)

	s.server = &http.Server{
		Addr:              s.config.Listen,
		Handler:           s.middleware(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", s.config.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.config.Listen, err)
	}

	s.logger.Info("subscription server started", "addr", s.config.Listen)

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("subscription server shutting down")
	case err := <-errCh:
		return fmt.Errorf("subscription server error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(shutdownCtx)
}

// Stop gracefully shuts down the subscription server.
func (s *SubServer) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// middleware applies logging, recovery, and rate limiting to all requests.
func (s *SubServer) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Recover from panics.
		defer func() {
			if rv := recover(); rv != nil {
				s.logger.Error("panic in subscription handler",
					"panic", rv,
					"path", r.URL.Path,
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()

		// Rate limiting by client IP.
		clientIP := extractClientIP(r)
		if !s.limiter.allow(clientIP) {
			s.logger.Warn("rate limit exceeded",
				"ip", clientIP,
				"path", r.URL.Path,
			)
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)

		s.logger.Debug("subscription request",
			"method", r.Method,
			"path", r.URL.Path,
			"ip", clientIP,
			"duration", time.Since(start),
		)
	})
}

// handleSubscription serves subscription configs with content negotiation.
func (s *SubServer) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the request.
	if !s.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.mu.RLock()
	baseSub := s.baseSub
	s.mu.RUnlock()

	if baseSub == nil {
		http.Error(w, "subscription not configured", http.StatusServiceUnavailable)
		return
	}

	// Generate or retrieve per-client UUID.
	clientID := s.identifyClient(r)
	clientUUID := s.getOrCreateUUID(clientID)

	// Create a per-client copy of the subscription with unique UUIDs.
	clientSub := s.createClientSubscription(baseSub, clientUUID)

	// Content negotiation: determine output format.
	format := s.negotiateFormat(r)

	switch format {
	case "hydraflow":
		s.serveHydraFlow(w, clientSub)
	case "v2ray":
		s.serveV2Ray(w, clientSub)
	case "clash":
		s.serveClash(w, clientSub)
	case "singbox":
		s.serveSingBox(w, clientSub)
	default:
		s.serveHydraFlow(w, clientSub)
	}
}

// authenticate verifies the request carries a valid token.
func (s *SubServer) authenticate(r *http.Request) bool {
	// Check Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.config.Token)) == 1 {
			return true
		}
	}

	// Check URL path token: /sub/{token}
	path := strings.TrimPrefix(r.URL.Path, "/sub/")
	if path != "" && path != "/" {
		if subtle.ConstantTimeCompare([]byte(path), []byte(s.config.Token)) == 1 {
			return true
		}
	}

	// Check query parameter.
	if token := r.URL.Query().Get("token"); token != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.config.Token)) == 1 {
			return true
		}
	}

	return false
}

// identifyClient creates a stable identifier for the client.
func (s *SubServer) identifyClient(r *http.Request) string {
	// Use a combination of IP and User-Agent for client identification.
	// This ensures different devices get different UUIDs.
	ip := extractClientIP(r)
	ua := r.UserAgent()
	return ip + "|" + ua
}

// getOrCreateUUID returns an existing UUID for the client or generates a new one.
func (s *SubServer) getOrCreateUUID(clientID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.clientUUIDs[clientID]; ok {
		return existing
	}

	// Generate a deterministic UUID v5 based on client ID.
	// This ensures the same client always gets the same UUID.
	namespace := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	clientUUID := uuid.NewSHA1(namespace, []byte(clientID)).String()
	s.clientUUIDs[clientID] = clientUUID

	s.logger.Debug("new client UUID generated",
		"client_id_hash", clientID[:min(len(clientID), 20)]+"...",
		"uuid", clientUUID,
	)

	return clientUUID
}

// createClientSubscription creates a copy with per-client UUIDs.
func (s *SubServer) createClientSubscription(base *Subscription, clientUUID string) *Subscription {
	clientSub := &Subscription{
		Version:     base.Version,
		Server:      base.Server,
		Updated:     time.Now(),
		TTL:         base.TTL,
		BlockingMap: base.BlockingMap,
	}

	clientSub.Protocols = make([]ProtocolConfig, len(base.Protocols))
	for i, p := range base.Protocols {
		clientSub.Protocols[i] = p
		clientSub.Protocols[i].UUID = clientUUID
	}

	return clientSub
}

// negotiateFormat determines the output format based on the request.
func (s *SubServer) negotiateFormat(r *http.Request) string {
	// Check explicit format query parameter.
	if format := r.URL.Query().Get("format"); format != "" {
		switch strings.ToLower(format) {
		case "hydraflow", "hydra", "yaml":
			return "hydraflow"
		case "v2ray", "base64":
			return "v2ray"
		case "clash", "clashmeta":
			return "clash"
		case "singbox", "sing-box":
			return "singbox"
		}
	}

	// Check User-Agent for automatic detection.
	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "hydraflow"):
		return "hydraflow"
	case strings.Contains(ua, "clash") || strings.Contains(ua, "stash"):
		return "clash"
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "singbox"):
		return "singbox"
	case strings.Contains(ua, "v2ray") || strings.Contains(ua, "v2rayn") ||
		strings.Contains(ua, "v2rayng") || strings.Contains(ua, "nekoray") ||
		strings.Contains(ua, "hiddify"):
		return "v2ray"
	}

	// Check Accept header.
	accept := r.Header.Get("Accept")
	switch {
	case strings.Contains(accept, "application/yaml") ||
		strings.Contains(accept, "application/x-hydraflow"):
		return "hydraflow"
	case strings.Contains(accept, "application/json"):
		return "singbox"
	case strings.Contains(accept, "text/plain"):
		return "v2ray"
	}

	// Default to HydraFlow native format.
	return "hydraflow"
}

// serveHydraFlow writes the subscription in native HydraFlow YAML format.
func (s *SubServer) serveHydraFlow(w http.ResponseWriter, sub *Subscription) {
	data, err := sub.Marshal()
	if err != nil {
		s.logger.Error("failed to marshal subscription", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"hydraflow.yml\"")
	s.setSubHeaders(w, sub)
	w.Write(data)
}

// serveV2Ray writes the subscription as base64-encoded V2Ray links.
func (s *SubServer) serveV2Ray(w http.ResponseWriter, sub *Subscription) {
	data := ExportV2RayFull(sub)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"v2ray.txt\"")
	s.setSubHeaders(w, sub)
	w.Write([]byte(data))
}

// serveClash writes the subscription in Clash Meta YAML format.
func (s *SubServer) serveClash(w http.ResponseWriter, sub *Subscription) {
	data, err := ExportClashFull(sub)
	if err != nil {
		s.logger.Error("failed to export Clash config", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"clash.yml\"")
	s.setSubHeaders(w, sub)
	w.Write(data)
}

// serveSingBox writes the subscription in sing-box JSON format.
func (s *SubServer) serveSingBox(w http.ResponseWriter, sub *Subscription) {
	data, err := ExportSingBoxFull(sub)
	if err != nil {
		s.logger.Error("failed to export sing-box config", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"singbox.json\"")
	s.setSubHeaders(w, sub)
	w.Write(data)
}

// setSubHeaders sets common subscription response headers.
func (s *SubServer) setSubHeaders(w http.ResponseWriter, sub *Subscription) {
	w.Header().Set("Subscription-UserInfo", fmt.Sprintf(
		"upload=0; download=0; total=0; expire=%d",
		time.Now().Add(30*24*time.Hour).Unix(),
	))
	if sub.TTL > 0 {
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", sub.TTL))
	}
	w.Header().Set("X-Subscription-Version", fmt.Sprintf("%d", sub.Version))
}

// handleHealth is a simple health check endpoint.
func (s *SubServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	hasSub := s.baseSub != nil
	s.mu.RUnlock()

	status := map[string]interface{}{
		"status":  "ok",
		"has_sub": hasSub,
		"clients": len(s.clientUUIDs),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// extractClientIP extracts the real client IP from the request.
// Proxy headers (X-Forwarded-For, X-Real-IP) are only trusted when
// the direct peer is localhost (127.0.0.1 or ::1), preventing header
// spoofing from untrusted sources.
func extractClientIP(r *http.Request) string {
	peerIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peerIP == "" {
		peerIP = r.RemoteAddr
	}
	trusted := peerIP == "127.0.0.1" || peerIP == "::1"

	if trusted {
		// Check X-Forwarded-For header.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}

		// Check X-Real-IP header.
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	return peerIP
}

// rateLimiter implements a simple token bucket rate limiter per key.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	maxRate  int
	window   time.Duration
	cleanTTL time.Duration
}

type bucket struct {
	tokens    int
	lastReset time.Time
}

func newRateLimiter(maxRate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		buckets:  make(map[string]*bucket),
		maxRate:  maxRate,
		window:   window,
		cleanTTL: 5 * time.Minute,
	}

	// Periodically clean up stale entries.
	go rl.cleanupLoop()

	return rl
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{
			tokens:    rl.maxRate - 1,
			lastReset: now,
		}
		return true
	}

	// Reset bucket if window has elapsed.
	if now.Sub(b.lastReset) >= rl.window {
		b.tokens = rl.maxRate - 1
		b.lastReset = now
		return true
	}

	if b.tokens <= 0 {
		return false
	}

	b.tokens--
	return true
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanTTL)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.Sub(b.lastReset) > rl.cleanTTL {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}
