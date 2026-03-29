package blockmap

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed static
var staticFiles embed.FS

// ServerConfig holds configuration for the map server.
type ServerConfig struct {
	Listen  string
	DataDir string
	NoSeed  bool
}

// MapServer is the HTTP server for the censorship monitoring dashboard.
type MapServer struct {
	cfg    ServerConfig
	store  *MapStore
	logger *slog.Logger
	mux    *http.ServeMux

	// Rate limiter: IP -> (count, window start)
	rateMu  sync.Mutex
	rateMap map[string]*rateEntry
}

type rateEntry struct {
	count int
	start time.Time
}

// NewMapServer creates a new map server.
func NewMapServer(cfg ServerConfig, logger *slog.Logger) (*MapServer, error) {
	store, err := NewMapStore(cfg.DataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}

	s := &MapServer{
		cfg:     cfg,
		store:   store,
		logger:  logger,
		mux:     http.NewServeMux(),
		rateMap: make(map[string]*rateEntry),
	}

	s.setupRoutes()

	// Load seed data if this is a fresh install.
	if !cfg.NoSeed {
		store.AddSeedData(GenerateSeedData())
	}

	return s, nil
}

// setupRoutes registers all HTTP handlers.
func (s *MapServer) setupRoutes() {
	// API endpoints.
	s.mux.HandleFunc("/api/v1/map", s.cors(s.handleMap))
	s.mux.HandleFunc("/api/v1/stats", s.cors(s.handleStats))
	s.mux.HandleFunc("/api/v1/countries", s.cors(s.handleCountries))
	s.mux.HandleFunc("/api/v1/report", s.cors(s.handleReport))
	s.mux.HandleFunc("/api/v1/events", s.cors(s.handleEvents))
	s.mux.HandleFunc("/api/v1/timeline/", s.cors(s.handleTimeline))
	s.mux.HandleFunc("/api/v1/map/", s.cors(s.handleMapFiltered))

	// Static frontend.
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		s.logger.Error("failed to get static subtree", "error", err)
		return
	}
	s.mux.Handle("/", http.FileServer(http.FS(staticSub)))
}

// cors wraps a handler with CORS headers.
func (s *MapServer) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleMap returns the full blocking map.
func (s *MapServer) handleMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data := s.store.GetMapData()
	writeJSON(w, http.StatusOK, data)
}

// handleMapFiltered returns data for a specific country or country/ISP.
func (s *MapServer) handleMapFiltered(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse path: /api/v1/map/{country} or /api/v1/map/{country}/{isp}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/map/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) == 0 || parts[0] == "" {
		// Fall back to full map.
		data := s.store.GetMapData()
		writeJSON(w, http.StatusOK, data)
		return
	}

	country := strings.ToUpper(parts[0])

	if len(parts) == 2 && parts[1] != "" {
		// Country + ISP.
		isp := parts[1]
		data := s.store.GetISPData(country, isp)
		if data == nil {
			writeError(w, http.StatusNotFound, "no data for this ISP")
			return
		}
		writeJSON(w, http.StatusOK, data)
		return
	}

	// Country only.
	data := s.store.GetCountryData(country)
	if data == nil {
		writeError(w, http.StatusNotFound, "no data for this country")
		return
	}
	writeJSON(w, http.StatusOK, data)
}

// handleStats returns global statistics.
func (s *MapServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stats := s.store.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

// handleCountries returns a list of countries.
func (s *MapServer) handleCountries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	countries := s.store.GetCountries()
	writeJSON(w, http.StatusOK, countries)
}

// handleTimeline returns timeline data for a protocol.
func (s *MapServer) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	protocol := strings.TrimPrefix(r.URL.Path, "/api/v1/timeline/")
	if protocol == "" {
		writeError(w, http.StatusBadRequest, "protocol required")
		return
	}

	// Validate protocol.
	valid := false
	for _, p := range KnownProtocols {
		if p == protocol {
			valid = true
			break
		}
	}
	if !valid {
		writeError(w, http.StatusBadRequest, "unknown protocol")
		return
	}

	data := s.store.GetTimeline(protocol, 7)
	writeJSON(w, http.StatusOK, data)
}

// handleEvents returns recent events.
func (s *MapServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	events := s.store.GetRecentEvents(20)
	writeJSON(w, http.StatusOK, events)
}

// reportRequest is the JSON body for report submission.
type reportRequest struct {
	Country   string `json:"country"`
	ASN       int    `json:"asn"`
	ISP       string `json:"isp"`
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
	LatencyMs int    `json:"latency_ms"`
	Timestamp string `json:"timestamp"`
}

// handleReport receives anonymous blocking reports.
func (s *MapServer) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Rate limit.
	ip := extractIP(r)
	if !s.checkRateLimit(ip) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded (max 10 reports per hour)")
		return
	}

	// Parse body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req reportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate.
	if req.Country == "" || len(req.Country) > 5 {
		writeError(w, http.StatusBadRequest, "invalid country code")
		return
	}
	if req.ISP == "" || len(req.ISP) > 100 {
		writeError(w, http.StatusBadRequest, "invalid ISP name")
		return
	}
	if req.Protocol == "" {
		writeError(w, http.StatusBadRequest, "protocol required")
		return
	}

	validProto := false
	for _, p := range KnownProtocols {
		if p == req.Protocol {
			validProto = true
			break
		}
	}
	if !validProto {
		writeError(w, http.StatusBadRequest, "unknown protocol")
		return
	}

	if req.Status != "working" && req.Status != "slow" && req.Status != "blocked" {
		writeError(w, http.StatusBadRequest, "status must be working, slow, or blocked")
		return
	}

	ts := time.Now().UTC()
	if req.Timestamp != "" {
		parsed, err := time.Parse(time.RFC3339, req.Timestamp)
		if err == nil {
			// Don't accept timestamps too far in the past or future.
			if time.Since(parsed) < 24*time.Hour && time.Until(parsed) < time.Hour {
				ts = parsed
			}
		}
	}

	report := Report{
		Country:   strings.ToUpper(req.Country),
		ASN:       req.ASN,
		ISP:       req.ISP,
		Protocol:  req.Protocol,
		Status:    req.Status,
		LatencyMs: req.LatencyMs,
		Timestamp: ts,
	}

	s.store.AddReport(report)

	s.logger.Info("report received",
		"country", report.Country,
		"isp", report.ISP,
		"protocol", report.Protocol,
		"status", report.Status,
	)

	writeJSON(w, http.StatusCreated, map[string]string{
		"status": "accepted",
	})
}

// checkRateLimit checks if an IP is within the rate limit.
func (s *MapServer) checkRateLimit(ip string) bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	entry, exists := s.rateMap[ip]

	if !exists || now.Sub(entry.start) > time.Hour {
		s.rateMap[ip] = &rateEntry{count: 1, start: now}
		return true
	}

	if entry.count >= 10 {
		return false
	}

	entry.count++
	return true
}

// extractIP extracts the client IP from the request.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For, X-Real-IP.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Start starts the map server and blocks until context is cancelled.
func (s *MapServer) Start(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Background tasks.
	go s.backgroundTasks(ctx)

	// Start server in goroutine.
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("HTTP server listening", "addr", s.cfg.Listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown.
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.logger.Info("shutting down HTTP server")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutCtx); err != nil {
			s.logger.Error("shutdown error", "error", err)
		}

		// Final save.
		if err := s.store.Save(); err != nil {
			s.logger.Error("final save failed", "error", err)
		} else {
			s.logger.Info("data saved to disk")
		}

		return nil
	}
}

// backgroundTasks runs periodic maintenance.
func (s *MapServer) backgroundTasks(ctx context.Context) {
	saveTicker := time.NewTicker(5 * time.Minute)
	pruneTicker := time.NewTicker(1 * time.Hour)
	rateTicker := time.NewTicker(10 * time.Minute)
	defer saveTicker.Stop()
	defer pruneTicker.Stop()
	defer rateTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-saveTicker.C:
			if err := s.store.Save(); err != nil {
				s.logger.Error("periodic save failed", "error", err)
			} else {
				s.logger.Debug("data saved to disk")
			}
		case <-pruneTicker.C:
			pruned := s.store.Prune()
			if pruned > 0 {
				s.logger.Info("pruned old reports", "count", pruned)
			}
		case <-rateTicker.C:
			s.cleanRateLimit()
		}
	}
}

// cleanRateLimit removes expired rate limit entries.
func (s *MapServer) cleanRateLimit() {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	for ip, entry := range s.rateMap {
		if now.Sub(entry.start) > time.Hour {
			delete(s.rateMap, ip)
		}
	}
}
