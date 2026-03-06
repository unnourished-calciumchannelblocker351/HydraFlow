package xray

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// StatsClient queries the xray-core stats API via the dokodemo-door
// inbound. It uses HTTP to the xray API handler endpoint, which is
// simpler than raw gRPC and works without proto file generation.
type StatsClient struct {
	apiAddr string
	client  *http.Client
	logger  *slog.Logger
}

// TrafficStats holds upload/download byte counts.
type TrafficStats struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// statsAPIResponse is the JSON structure returned by the xray stats API.
type statsAPIResponse struct {
	Stat []statEntry `json:"stat"`
}

type statEntry struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// NewStatsClient creates a new StatsClient connecting to the xray API
// at the given address (e.g., "127.0.0.1:10085").
func NewStatsClient(apiAddr string, logger *slog.Logger) *StatsClient {
	if logger == nil {
		logger = slog.Default()
	}
	if apiAddr == "" {
		apiAddr = "127.0.0.1:10085"
	}

	return &StatsClient{
		apiAddr: apiAddr,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// GetUserTraffic returns the upload and download byte counts for a user
// identified by their email. The email must match what was configured
// in the xray inbound user list.
func (s *StatsClient) GetUserTraffic(email string) (*TrafficStats, error) {
	uplink, err := s.queryStat(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email), false)
	if err != nil {
		return nil, fmt.Errorf("get uplink for %s: %w", email, err)
	}

	downlink, err := s.queryStat(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email), false)
	if err != nil {
		return nil, fmt.Errorf("get downlink for %s: %w", email, err)
	}

	return &TrafficStats{
		Uplink:   uplink,
		Downlink: downlink,
	}, nil
}

// GetInboundTraffic returns the total traffic for an inbound by its tag.
func (s *StatsClient) GetInboundTraffic(tag string) (*TrafficStats, error) {
	uplink, err := s.queryStat(fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", tag), false)
	if err != nil {
		return nil, fmt.Errorf("get inbound uplink for %s: %w", tag, err)
	}

	downlink, err := s.queryStat(fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", tag), false)
	if err != nil {
		return nil, fmt.Errorf("get inbound downlink for %s: %w", tag, err)
	}

	return &TrafficStats{
		Uplink:   uplink,
		Downlink: downlink,
	}, nil
}

// ResetUserTraffic resets the traffic counters for a user and returns
// the traffic accumulated since the last reset.
func (s *StatsClient) ResetUserTraffic(email string) (*TrafficStats, error) {
	uplink, err := s.queryStat(fmt.Sprintf("user>>>%s>>>traffic>>>uplink", email), true)
	if err != nil {
		return nil, fmt.Errorf("reset uplink for %s: %w", email, err)
	}

	downlink, err := s.queryStat(fmt.Sprintf("user>>>%s>>>traffic>>>downlink", email), true)
	if err != nil {
		return nil, fmt.Errorf("reset downlink for %s: %w", email, err)
	}

	return &TrafficStats{
		Uplink:   uplink,
		Downlink: downlink,
	}, nil
}

// GetAllUserTraffic queries stats for all users matching the pattern.
// It returns a map of email -> TrafficStats.
func (s *StatsClient) GetAllUserTraffic(reset bool) (map[string]*TrafficStats, error) {
	resp, err := s.queryAllStats("user", reset)
	if err != nil {
		return nil, fmt.Errorf("query all user stats: %w", err)
	}

	result := make(map[string]*TrafficStats)

	for _, entry := range resp {
		// Pattern: "user>>>email>>>traffic>>>uplink" or "downlink"
		email, direction := parseStatName(entry.Name, "user")
		if email == "" {
			continue
		}

		stats, ok := result[email]
		if !ok {
			stats = &TrafficStats{}
			result[email] = stats
		}

		switch direction {
		case "uplink":
			stats.Uplink = entry.Value
		case "downlink":
			stats.Downlink = entry.Value
		}
	}

	return result, nil
}

// GetAllInboundTraffic queries stats for all inbounds.
func (s *StatsClient) GetAllInboundTraffic(reset bool) (map[string]*TrafficStats, error) {
	resp, err := s.queryAllStats("inbound", reset)
	if err != nil {
		return nil, fmt.Errorf("query all inbound stats: %w", err)
	}

	result := make(map[string]*TrafficStats)

	for _, entry := range resp {
		tag, direction := parseStatName(entry.Name, "inbound")
		if tag == "" {
			continue
		}

		stats, ok := result[tag]
		if !ok {
			stats = &TrafficStats{}
			result[tag] = stats
		}

		switch direction {
		case "uplink":
			stats.Uplink = entry.Value
		case "downlink":
			stats.Downlink = entry.Value
		}
	}

	return result, nil
}

// queryStat queries a single stat by its full name.
func (s *StatsClient) queryStat(name string, reset bool) (int64, error) {
	params := url.Values{}
	params.Set("pattern", name)
	if reset {
		params.Set("reset", "true")
	}

	reqURL := fmt.Sprintf("http://%s/api/v1/stats/query?%s", s.apiAddr, params.Encode())

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("stats request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("stats API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp statsAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return 0, fmt.Errorf("parse stats response: %w", err)
	}

	if len(apiResp.Stat) == 0 {
		return 0, nil
	}

	return apiResp.Stat[0].Value, nil
}

// queryAllStats queries all stats matching the given prefix pattern.
func (s *StatsClient) queryAllStats(prefix string, reset bool) ([]statEntry, error) {
	params := url.Values{}
	params.Set("pattern", prefix)
	if reset {
		params.Set("reset", "true")
	}

	reqURL := fmt.Sprintf("http://%s/api/v1/stats/query?%s", s.apiAddr, params.Encode())

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stats request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stats API error %d: %s", resp.StatusCode, string(body))
	}

	var apiResp statsAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("parse stats response: %w", err)
	}

	return apiResp.Stat, nil
}

// parseStatName extracts the identifier and direction from a stat name.
// Pattern: "prefix>>>name>>>traffic>>>direction"
func parseStatName(name, prefix string) (string, string) {
	// Manual parsing to avoid importing strings for just this.
	expected := prefix + ">>>"
	if len(name) <= len(expected) {
		return "", ""
	}
	if name[:len(expected)] != expected {
		return "", ""
	}

	rest := name[len(expected):]

	// Find ">>>traffic>>>"
	trafficSep := ">>>traffic>>>"
	idx := -1
	for i := 0; i <= len(rest)-len(trafficSep); i++ {
		if rest[i:i+len(trafficSep)] == trafficSep {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", ""
	}

	identifier := rest[:idx]
	direction := rest[idx+len(trafficSep):]

	return identifier, direction
}
