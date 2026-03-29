package blockmap

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Report is a single anonymous blocking report from a HydraFlow user.
type Report struct {
	Country    string    `json:"country"`
	ASN        int       `json:"asn"`
	ISP        string    `json:"isp"`
	Protocol   string    `json:"protocol"`
	Status     string    `json:"status"` // "working", "slow", "blocked"
	LatencyMs  int       `json:"latency_ms"`
	Timestamp  time.Time `json:"timestamp"`
	Historical bool      `json:"historical,omitempty"`
}

// ProtocolStatus is the aggregated status for a single protocol on a single ISP.
type ProtocolStatus struct {
	Protocol    string  `json:"protocol"`
	Status      string  `json:"status"` // "working", "degraded", "blocked", "nodata"
	WorkingPct  float64 `json:"working_pct"`
	ReportCount int     `json:"report_count"`
	AvgLatency  float64 `json:"avg_latency_ms"`
	LastReport  string  `json:"last_report"`
}

// ISPData is the aggregated data for a single ISP.
type ISPData struct {
	ISP       string           `json:"isp"`
	ASN       int              `json:"asn"`
	Protocols []ProtocolStatus `json:"protocols"`
}

// CountryData is the aggregated data for a single country.
type CountryData struct {
	Country        string    `json:"country"`
	ISPs           []ISPData `json:"isps"`
	TotalReports   int       `json:"total_reports"`
	WorkingCount   int       `json:"working_count"`
	TotalProtocols int       `json:"total_protocols"`
	WorkingPct     float64   `json:"working_pct"`
	LastUpdate     string    `json:"last_update"`
}

// MapData is the full aggregated map.
type MapData struct {
	Countries []CountryData `json:"countries"`
	Updated   string        `json:"updated"`
}

// Stats holds global statistics.
type Stats struct {
	TotalReports   int    `json:"total_reports"`
	CountriesCount int    `json:"countries_count"`
	ISPsCount      int    `json:"isps_count"`
	ProtocolsCount int    `json:"protocols_count"`
	LastUpdate     string `json:"last_update"`
	OldestReport   string `json:"oldest_report"`
}

// CountryInfo is a summary for the countries list endpoint.
type CountryInfo struct {
	Country     string  `json:"country"`
	ReportCount int     `json:"report_count"`
	ISPCount    int     `json:"isp_count"`
	WorkingPct  float64 `json:"working_pct"`
}

// TimelinePoint is a single point in a timeline chart.
type TimelinePoint struct {
	Time       string  `json:"time"`
	WorkingPct float64 `json:"working_pct"`
	Reports    int     `json:"reports"`
}

// TimelineData is the timeline response.
type TimelineData struct {
	Protocol string          `json:"protocol"`
	Points   []TimelinePoint `json:"points"`
}

// Event is a recent blocking change event.
type Event struct {
	Time     string `json:"time"`
	Country  string `json:"country"`
	ISP      string `json:"isp"`
	Protocol string `json:"protocol"`
	OldState string `json:"old_status"`
	NewState string `json:"new_status"`
}

// MapStore stores all reports in memory with periodic disk persistence.
type MapStore struct {
	mu       sync.RWMutex
	reports  []Report
	events   []Event
	dataFile string
	logger   *slog.Logger

	// Cache of last known states for event detection.
	lastState map[string]string // "country:isp:protocol" -> status
}

// NewMapStore creates a new store, loading persisted data if available.
func NewMapStore(dataDir string, logger *slog.Logger) (*MapStore, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &MapStore{
		dataFile:  filepath.Join(dataDir, "reports.json"),
		logger:    logger,
		lastState: make(map[string]string),
	}

	if err := s.load(); err != nil {
		logger.Warn("no existing data loaded", "error", err)
	} else {
		logger.Info("loaded persisted data", "reports", len(s.reports))
	}

	return s, nil
}

// persistenceData is the JSON structure saved to disk.
type persistenceData struct {
	Reports []Report `json:"reports"`
	Events  []Event  `json:"events"`
}

func (s *MapStore) load() error {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return err
	}

	var pd persistenceData
	if err := json.Unmarshal(data, &pd); err != nil {
		return fmt.Errorf("parse data file: %w", err)
	}

	s.reports = pd.Reports
	s.events = pd.Events

	// Rebuild last state cache.
	s.rebuildStateCache()

	return nil
}

func (s *MapStore) rebuildStateCache() {
	s.lastState = make(map[string]string)
	// Process reports in chronological order to get last state.
	sorted := make([]Report, len(s.reports))
	copy(sorted, s.reports)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	for _, r := range sorted {
		key := r.Country + ":" + r.ISP + ":" + r.Protocol
		s.lastState[key] = r.Status
	}
}

// Save persists current data to disk.
func (s *MapStore) Save() error {
	s.mu.RLock()
	pd := persistenceData{
		Reports: s.reports,
		Events:  s.events,
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	tmpFile := s.dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpFile, s.dataFile); err != nil {
		return fmt.Errorf("rename data file: %w", err)
	}

	return nil
}

// AddReport adds a new report and detects state changes.
func (s *MapStore) AddReport(r Report) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reports = append(s.reports, r)

	// Detect state changes for events.
	key := r.Country + ":" + r.ISP + ":" + r.Protocol
	oldStatus, exists := s.lastState[key]
	if exists && oldStatus != r.Status {
		event := Event{
			Time:     r.Timestamp.Format(time.RFC3339),
			Country:  r.Country,
			ISP:      r.ISP,
			Protocol: r.Protocol,
			OldState: oldStatus,
			NewState: r.Status,
		}
		s.events = append(s.events, event)
		// Keep only last 200 events.
		if len(s.events) > 200 {
			s.events = s.events[len(s.events)-200:]
		}
	}
	s.lastState[key] = r.Status
}

// AddSeedData adds historical seed reports.
func (s *MapStore) AddSeedData(reports []Report) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only add seed data if we have no real reports.
	realCount := 0
	for _, r := range s.reports {
		if !r.Historical {
			realCount++
		}
	}
	if realCount > 0 {
		s.logger.Info("skipping seed data, real reports exist", "count", realCount)
		return
	}

	// Remove old seed data.
	var kept []Report
	for _, r := range s.reports {
		if !r.Historical {
			kept = append(kept, r)
		}
	}
	s.reports = kept

	s.reports = append(s.reports, reports...)
	s.rebuildStateCache()
	s.logger.Info("loaded seed data", "reports", len(reports))
}

// Prune removes reports older than 30 days.
func (s *MapStore) Prune() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	var kept []Report
	pruned := 0
	for _, r := range s.reports {
		if r.Timestamp.After(cutoff) {
			kept = append(kept, r)
		} else {
			pruned++
		}
	}
	s.reports = kept

	// Prune old events too.
	var keptEvents []Event
	cutoffStr := cutoff.Format(time.RFC3339)
	for _, e := range s.events {
		if e.Time > cutoffStr {
			keptEvents = append(keptEvents, e)
		}
	}
	s.events = keptEvents

	return pruned
}

// timeDecayWeight returns a weight for a report based on its age.
// Recent reports get weight ~1.0, older reports decay towards 0.
func timeDecayWeight(reportTime time.Time) float64 {
	hours := time.Since(reportTime).Hours()
	if hours < 0 {
		hours = 0
	}
	// Half-life of 48 hours.
	return math.Exp(-0.014 * hours)
}

// aggregateStatus computes the aggregate status from a set of reports.
func aggregateStatus(reports []Report) ProtocolStatus {
	if len(reports) == 0 {
		return ProtocolStatus{Status: "nodata"}
	}

	var weightedWorking, weightedTotal float64
	var totalLatency float64
	var latencyCount int
	var lastTime time.Time

	for _, r := range reports {
		w := timeDecayWeight(r.Timestamp)
		weightedTotal += w

		switch r.Status {
		case "working":
			weightedWorking += w
		case "slow":
			weightedWorking += w * 0.5
		}

		if r.LatencyMs > 0 {
			totalLatency += float64(r.LatencyMs) * w
			latencyCount++
		}

		if r.Timestamp.After(lastTime) {
			lastTime = r.Timestamp
		}
	}

	pct := 0.0
	if weightedTotal > 0 {
		pct = (weightedWorking / weightedTotal) * 100
	}

	avgLatency := 0.0
	if latencyCount > 0 {
		avgLatency = totalLatency / float64(latencyCount)
	}

	status := "blocked"
	if pct > 80 {
		status = "working"
	} else if pct > 40 {
		status = "degraded"
	}

	return ProtocolStatus{
		Status:      status,
		WorkingPct:  math.Round(pct*10) / 10,
		ReportCount: len(reports),
		AvgLatency:  math.Round(avgLatency*10) / 10,
		LastReport:  lastTime.Format(time.RFC3339),
	}
}

// KnownProtocols is the list of tracked protocols.
var KnownProtocols = []string{
	"vless-reality",
	"vless-ws-cdn",
	"shadowsocks-2022",
	"hysteria2",
	"shadowtls",
	"chain-proxy",
}

// GetMapData returns the full aggregated blocking map.
func (s *MapStore) GetMapData() MapData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.buildMapData("")
}

// GetCountryData returns data for a specific country.
func (s *MapStore) GetCountryData(country string) *CountryData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	md := s.buildMapData(country)
	for _, c := range md.Countries {
		if c.Country == country {
			return &c
		}
	}
	return nil
}

// GetISPData returns data for a specific ISP in a country.
func (s *MapStore) GetISPData(country, isp string) *ISPData {
	cd := s.GetCountryData(country)
	if cd == nil {
		return nil
	}
	for _, i := range cd.ISPs {
		if i.ISP == isp {
			return &i
		}
	}
	return nil
}

// buildMapData aggregates reports into the map structure.
func (s *MapStore) buildMapData(filterCountry string) MapData {
	// Group reports: country -> isp -> protocol -> []Report
	type key struct {
		country, isp, protocol string
	}
	groups := make(map[key][]Report)
	asnMap := make(map[string]int) // isp -> asn

	cutoff := time.Now().Add(-30 * 24 * time.Hour)

	for _, r := range s.reports {
		if r.Timestamp.Before(cutoff) {
			continue
		}
		if filterCountry != "" && r.Country != filterCountry {
			continue
		}
		k := key{r.Country, r.ISP, r.Protocol}
		groups[k] = append(groups[k], r)
		if r.ASN > 0 {
			asnMap[r.ISP] = r.ASN
		}
	}

	// Build country -> ISP -> protocol structure.
	countryISPs := make(map[string]map[string]bool)
	for k := range groups {
		if countryISPs[k.country] == nil {
			countryISPs[k.country] = make(map[string]bool)
		}
		countryISPs[k.country][k.isp] = true
	}

	var countries []CountryData
	for country, isps := range countryISPs {
		var ispList []ISPData
		totalReports := 0
		workingCount := 0
		totalProtos := 0
		var latestTime time.Time

		ispNames := make([]string, 0, len(isps))
		for isp := range isps {
			ispNames = append(ispNames, isp)
		}
		sort.Strings(ispNames)

		for _, ispName := range ispNames {
			var protos []ProtocolStatus
			for _, proto := range KnownProtocols {
				k := key{country, ispName, proto}
				reports := groups[k]
				ps := aggregateStatus(reports)
				ps.Protocol = proto
				protos = append(protos, ps)
				totalReports += ps.ReportCount
				if ps.Status == "working" {
					workingCount++
				}
				if ps.ReportCount > 0 {
					totalProtos++
				}
				if ps.ReportCount > 0 {
					t, err := time.Parse(time.RFC3339, ps.LastReport)
					if err == nil && t.After(latestTime) {
						latestTime = t
					}
				}
			}

			ispData := ISPData{
				ISP:       ispName,
				ASN:       asnMap[ispName],
				Protocols: protos,
			}
			ispList = append(ispList, ispData)
		}

		workPct := 0.0
		if totalProtos > 0 {
			workPct = float64(workingCount) / float64(totalProtos) * 100
			workPct = math.Round(workPct*10) / 10
		}

		lastUp := ""
		if !latestTime.IsZero() {
			lastUp = latestTime.Format(time.RFC3339)
		}

		cd := CountryData{
			Country:        country,
			ISPs:           ispList,
			TotalReports:   totalReports,
			WorkingCount:   workingCount,
			TotalProtocols: totalProtos,
			WorkingPct:     workPct,
			LastUpdate:     lastUp,
		}
		countries = append(countries, cd)
	}

	// Sort countries by report count descending.
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].TotalReports > countries[j].TotalReports
	})

	return MapData{
		Countries: countries,
		Updated:   time.Now().Format(time.RFC3339),
	}
}

// GetTimeline returns hourly aggregation for a protocol over the last N days.
func (s *MapStore) GetTimeline(protocol string, days int) TimelineData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if days <= 0 || days > 30 {
		days = 7
	}

	now := time.Now().UTC()
	start := now.Add(-time.Duration(days) * 24 * time.Hour)

	// Group reports into 6-hour buckets.
	bucketDuration := 6 * time.Hour
	bucketCount := (days * 24) / 6

	type bucket struct {
		working float64
		total   float64
		count   int
	}
	buckets := make([]bucket, bucketCount)

	for _, r := range s.reports {
		if r.Protocol != protocol {
			continue
		}
		if r.Timestamp.Before(start) || r.Timestamp.After(now) {
			continue
		}

		idx := int(r.Timestamp.Sub(start) / bucketDuration)
		if idx < 0 || idx >= bucketCount {
			continue
		}

		w := timeDecayWeight(r.Timestamp)
		buckets[idx].total += w
		buckets[idx].count++
		switch r.Status {
		case "working":
			buckets[idx].working += w
		case "slow":
			buckets[idx].working += w * 0.5
		}
	}

	var points []TimelinePoint
	for i := 0; i < bucketCount; i++ {
		t := start.Add(time.Duration(i) * bucketDuration)
		pct := 0.0
		if buckets[i].total > 0 {
			pct = math.Round((buckets[i].working/buckets[i].total)*1000) / 10
		}
		points = append(points, TimelinePoint{
			Time:       t.Format(time.RFC3339),
			WorkingPct: pct,
			Reports:    buckets[i].count,
		})
	}

	return TimelineData{
		Protocol: protocol,
		Points:   points,
	}
}

// GetStats returns global statistics.
func (s *MapStore) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	countries := make(map[string]bool)
	isps := make(map[string]bool)
	protocols := make(map[string]bool)
	var oldest, newest time.Time

	for _, r := range s.reports {
		countries[r.Country] = true
		isps[r.Country+":"+r.ISP] = true
		protocols[r.Protocol] = true
		if oldest.IsZero() || r.Timestamp.Before(oldest) {
			oldest = r.Timestamp
		}
		if r.Timestamp.After(newest) {
			newest = r.Timestamp
		}
	}

	oldestStr := ""
	if !oldest.IsZero() {
		oldestStr = oldest.Format(time.RFC3339)
	}
	newestStr := ""
	if !newest.IsZero() {
		newestStr = newest.Format(time.RFC3339)
	}

	return Stats{
		TotalReports:   len(s.reports),
		CountriesCount: len(countries),
		ISPsCount:      len(isps),
		ProtocolsCount: len(protocols),
		LastUpdate:     newestStr,
		OldestReport:   oldestStr,
	}
}

// GetCountries returns a list of countries with summary info.
func (s *MapStore) GetCountries() []CountryInfo {
	md := s.GetMapData()
	var result []CountryInfo
	for _, c := range md.Countries {
		ispCount := len(c.ISPs)
		result = append(result, CountryInfo{
			Country:     c.Country,
			ReportCount: c.TotalReports,
			ISPCount:    ispCount,
			WorkingPct:  c.WorkingPct,
		})
	}
	return result
}

// GetRecentEvents returns the most recent events.
func (s *MapStore) GetRecentEvents(limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 50 {
		limit = 20
	}

	if len(s.events) <= limit {
		result := make([]Event, len(s.events))
		copy(result, s.events)
		// Reverse for newest first.
		for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
			result[i], result[j] = result[j], result[i]
		}
		return result
	}

	result := make([]Event, limit)
	copy(result, s.events[len(s.events)-limit:])
	// Reverse for newest first.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}
