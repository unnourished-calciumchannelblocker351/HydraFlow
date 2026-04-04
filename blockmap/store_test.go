package blockmap

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *MapStore {
	t.Helper()
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s, err := NewMapStore(tmpDir, logger)
	if err != nil {
		t.Fatalf("NewMapStore: %v", err)
	}
	return s
}

func TestAddReport_And_GetMapData(t *testing.T) {
	s := newTestStore(t)

	s.AddReport(Report{
		Country:   "IR",
		ASN:       44244,
		ISP:       "Irancell",
		Protocol:  "vless-reality",
		Status:    "working",
		LatencyMs: 120,
		Timestamp: time.Now(),
	})

	md := s.GetMapData()
	if len(md.Countries) != 1 {
		t.Fatalf("expected 1 country, got %d", len(md.Countries))
	}
	if md.Countries[0].Country != "IR" {
		t.Fatalf("expected country 'IR', got %q", md.Countries[0].Country)
	}
	if md.Countries[0].TotalReports < 1 {
		t.Fatalf("expected at least 1 report, got %d", md.Countries[0].TotalReports)
	}
}

func TestAddReport_MultipleCountries(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	s.AddReport(Report{Country: "IR", ISP: "ISP-1", Protocol: "vless-reality", Status: "working", Timestamp: now})
	s.AddReport(Report{Country: "CN", ISP: "ISP-2", Protocol: "vless-reality", Status: "blocked", Timestamp: now})

	md := s.GetMapData()
	if len(md.Countries) != 2 {
		t.Fatalf("expected 2 countries, got %d", len(md.Countries))
	}
}

func TestTimeDecayWeight(t *testing.T) {
	now := time.Now()

	// A report from right now should have weight ~1.0.
	w := timeDecayWeight(now)
	if w < 0.99 || w > 1.01 {
		t.Fatalf("expected weight ~1.0 for now, got %f", w)
	}

	// A report from 48 hours ago (half-life) should have weight ~0.5.
	old := now.Add(-48 * time.Hour)
	wOld := timeDecayWeight(old)
	if wOld < 0.45 || wOld > 0.55 {
		t.Fatalf("expected weight ~0.5 for 48h old, got %f", wOld)
	}

	// Very old report should have very low weight.
	veryOld := now.Add(-240 * time.Hour) // 10 days
	wVeryOld := timeDecayWeight(veryOld)
	if wVeryOld > 0.05 {
		t.Fatalf("expected very low weight for 10-day old, got %f", wVeryOld)
	}
}

func TestPrune_RemovesOldData(t *testing.T) {
	s := newTestStore(t)

	// Add an old report (35 days ago) and a recent one.
	s.AddReport(Report{
		Country:   "IR",
		ISP:       "ISP-1",
		Protocol:  "vless-reality",
		Status:    "working",
		Timestamp: time.Now().Add(-35 * 24 * time.Hour),
	})
	s.AddReport(Report{
		Country:   "IR",
		ISP:       "ISP-1",
		Protocol:  "vless-reality",
		Status:    "working",
		Timestamp: time.Now(),
	})

	pruned := s.Prune()
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}

	stats := s.GetStats()
	if stats.TotalReports != 1 {
		t.Fatalf("expected 1 report after prune, got %d", stats.TotalReports)
	}
}

func TestPrune_KeepsRecentData(t *testing.T) {
	s := newTestStore(t)

	s.AddReport(Report{
		Country:   "IR",
		ISP:       "ISP-1",
		Protocol:  "vless-reality",
		Status:    "working",
		Timestamp: time.Now(),
	})

	pruned := s.Prune()
	if pruned != 0 {
		t.Fatalf("expected 0 pruned for recent data, got %d", pruned)
	}
}

func TestGetCountryData_Filtering(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	s.AddReport(Report{Country: "IR", ISP: "Irancell", Protocol: "vless-reality", Status: "working", Timestamp: now})
	s.AddReport(Report{Country: "CN", ISP: "China Telecom", Protocol: "vless-reality", Status: "blocked", Timestamp: now})

	ir := s.GetCountryData("IR")
	if ir == nil {
		t.Fatal("GetCountryData('IR') should not be nil")
	}
	if ir.Country != "IR" {
		t.Fatalf("expected country 'IR', got %q", ir.Country)
	}

	// Verify CN data is not mixed in.
	for _, isp := range ir.ISPs {
		if isp.ISP == "China Telecom" {
			t.Fatal("IR data should not contain CN ISP")
		}
	}

	// Non-existent country returns nil.
	if s.GetCountryData("XX") != nil {
		t.Fatal("expected nil for non-existent country")
	}
}

func TestAggregateStatus_Thresholds(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		reports  []Report
		expected string
	}{
		{
			name:     "no reports",
			reports:  nil,
			expected: "nodata",
		},
		{
			name: "all working -> working",
			reports: []Report{
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
			},
			expected: "working",
		},
		{
			name: "all blocked -> blocked",
			reports: []Report{
				{Status: "blocked", Timestamp: now},
				{Status: "blocked", Timestamp: now},
			},
			expected: "blocked",
		},
		{
			name: "mixed degraded (50/50)",
			reports: []Report{
				{Status: "working", Timestamp: now},
				{Status: "blocked", Timestamp: now},
			},
			expected: "degraded",
		},
		{
			name: "mostly working -> working (>80%)",
			reports: []Report{
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
				{Status: "working", Timestamp: now},
				{Status: "blocked", Timestamp: now},
			},
			// 5/6 = 83.3% > 80% -> "working"
			expected: "working",
		},
		{
			name: "slow reports count as 50%",
			reports: []Report{
				{Status: "slow", Timestamp: now},
				{Status: "slow", Timestamp: now},
			},
			// 50% working -> degraded (>40 but <=80)
			expected: "degraded",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := aggregateStatus(tc.reports)
			if ps.Status != tc.expected {
				t.Fatalf("expected status %q, got %q (pct=%.1f)", tc.expected, ps.Status, ps.WorkingPct)
			}
		})
	}
}

func TestAggregateStatus_LatencyAverage(t *testing.T) {
	now := time.Now()
	reports := []Report{
		{Status: "working", LatencyMs: 100, Timestamp: now},
		{Status: "working", LatencyMs: 200, Timestamp: now},
	}

	ps := aggregateStatus(reports)
	// Average should be ~150 (close, accounting for time decay weighting).
	if ps.AvgLatency < 140 || ps.AvgLatency > 160 {
		t.Fatalf("expected avg latency ~150, got %.1f", ps.AvgLatency)
	}
}

func TestAggregateStatus_ReportCount(t *testing.T) {
	now := time.Now()
	reports := []Report{
		{Status: "working", Timestamp: now},
		{Status: "blocked", Timestamp: now},
		{Status: "slow", Timestamp: now},
	}

	ps := aggregateStatus(reports)
	if ps.ReportCount != 3 {
		t.Fatalf("expected 3 reports, got %d", ps.ReportCount)
	}
}

func TestSave_And_Load_Roundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	s1, err := NewMapStore(tmpDir, logger)
	if err != nil {
		t.Fatalf("NewMapStore: %v", err)
	}

	now := time.Now().Truncate(time.Second) // truncate for comparison
	s1.AddReport(Report{
		Country:   "IR",
		ASN:       44244,
		ISP:       "Irancell",
		Protocol:  "vless-reality",
		Status:    "working",
		LatencyMs: 100,
		Timestamp: now,
	})

	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into a new store from the same directory.
	s2, err := NewMapStore(tmpDir, logger)
	if err != nil {
		t.Fatalf("NewMapStore (reload): %v", err)
	}

	stats := s2.GetStats()
	if stats.TotalReports != 1 {
		t.Fatalf("expected 1 report after reload, got %d", stats.TotalReports)
	}

	md := s2.GetMapData()
	if len(md.Countries) != 1 {
		t.Fatalf("expected 1 country after reload, got %d", len(md.Countries))
	}
}

func TestSave_ProducesValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	s, _ := NewMapStore(tmpDir, logger)
	s.AddReport(Report{
		Country:   "DE",
		ISP:       "Deutsche Telekom",
		Protocol:  "vless-ws-cdn",
		Status:    "working",
		LatencyMs: 50,
		Timestamp: time.Now(),
	})

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if !json.Valid(data) {
		t.Fatal("saved data is not valid JSON")
	}

	var pd persistenceData
	if err := json.Unmarshal(data, &pd); err != nil {
		t.Fatalf("unmarshal persisted data: %v", err)
	}
	if len(pd.Reports) != 1 {
		t.Fatalf("expected 1 report in persisted data, got %d", len(pd.Reports))
	}
}

func TestGetStats(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	s.AddReport(Report{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "working", Timestamp: now})
	s.AddReport(Report{Country: "IR", ISP: "ISP-B", Protocol: "vless-ws-cdn", Status: "blocked", Timestamp: now.Add(-time.Hour)})
	s.AddReport(Report{Country: "CN", ISP: "ISP-C", Protocol: "vless-reality", Status: "working", Timestamp: now.Add(-2 * time.Hour)})

	stats := s.GetStats()
	if stats.TotalReports != 3 {
		t.Fatalf("expected 3 total reports, got %d", stats.TotalReports)
	}
	if stats.CountriesCount != 2 {
		t.Fatalf("expected 2 countries, got %d", stats.CountriesCount)
	}
	if stats.ProtocolsCount != 2 {
		t.Fatalf("expected 2 protocols, got %d", stats.ProtocolsCount)
	}
}

func TestStateChangeEvents(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	// First report: no event (no previous state).
	s.AddReport(Report{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "working", Timestamp: now})

	events := s.GetRecentEvents(10)
	if len(events) != 0 {
		t.Fatalf("expected 0 events on first report, got %d", len(events))
	}

	// Second report with same status: no event.
	s.AddReport(Report{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "working", Timestamp: now.Add(time.Minute)})
	events = s.GetRecentEvents(10)
	if len(events) != 0 {
		t.Fatalf("expected 0 events for same status, got %d", len(events))
	}

	// Third report with different status: generates event.
	s.AddReport(Report{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "blocked", Timestamp: now.Add(2 * time.Minute)})
	events = s.GetRecentEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event on status change, got %d", len(events))
	}
	if events[0].OldState != "working" || events[0].NewState != "blocked" {
		t.Fatalf("unexpected event: old=%q new=%q", events[0].OldState, events[0].NewState)
	}
}

func TestGetCountries(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	s.AddReport(Report{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "working", Timestamp: now})
	s.AddReport(Report{Country: "CN", ISP: "ISP-B", Protocol: "vless-reality", Status: "blocked", Timestamp: now})

	countries := s.GetCountries()
	if len(countries) != 2 {
		t.Fatalf("expected 2 countries, got %d", len(countries))
	}
}

func TestGetISPData(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	s.AddReport(Report{Country: "IR", ASN: 44244, ISP: "Irancell", Protocol: "vless-reality", Status: "working", Timestamp: now})

	isp := s.GetISPData("IR", "Irancell")
	if isp == nil {
		t.Fatal("expected non-nil ISP data")
	}
	if isp.ISP != "Irancell" {
		t.Fatalf("expected ISP 'Irancell', got %q", isp.ISP)
	}
	if isp.ASN != 44244 {
		t.Fatalf("expected ASN 44244, got %d", isp.ASN)
	}

	// Non-existent ISP.
	if s.GetISPData("IR", "NonExistent") != nil {
		t.Fatal("expected nil for non-existent ISP")
	}
}

func TestAddSeedData(t *testing.T) {
	s := newTestStore(t)

	seed := []Report{
		{Country: "IR", ISP: "ISP-A", Protocol: "vless-reality", Status: "working", Timestamp: time.Now(), Historical: true},
		{Country: "CN", ISP: "ISP-B", Protocol: "vless-reality", Status: "blocked", Timestamp: time.Now(), Historical: true},
	}

	s.AddSeedData(seed)

	stats := s.GetStats()
	if stats.TotalReports != 2 {
		t.Fatalf("expected 2 reports from seed, got %d", stats.TotalReports)
	}
}

func TestAddSeedData_SkippedWhenRealReportsExist(t *testing.T) {
	s := newTestStore(t)

	// Add a real report first.
	s.AddReport(Report{
		Country:   "IR",
		ISP:       "ISP-A",
		Protocol:  "vless-reality",
		Status:    "working",
		Timestamp: time.Now(),
	})

	// Now try adding seed data -- should be skipped.
	seed := []Report{
		{Country: "CN", ISP: "ISP-B", Protocol: "vless-reality", Status: "blocked", Timestamp: time.Now(), Historical: true},
	}
	s.AddSeedData(seed)

	stats := s.GetStats()
	if stats.TotalReports != 1 {
		t.Fatalf("expected 1 report (seed should be skipped), got %d", stats.TotalReports)
	}
}

func TestGetTimeline(t *testing.T) {
	s := newTestStore(t)

	now := time.Now().UTC()
	// Add reports across multiple time points.
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(i*6) * time.Hour)
		status := "working"
		if i > 7 {
			status = "blocked"
		}
		s.AddReport(Report{
			Country:   "IR",
			ISP:       "ISP-A",
			Protocol:  "vless-reality",
			Status:    status,
			Timestamp: ts,
		})
	}

	tl := s.GetTimeline("vless-reality", 7)
	if tl.Protocol != "vless-reality" {
		t.Fatalf("expected protocol 'vless-reality', got %q", tl.Protocol)
	}
	if len(tl.Points) == 0 {
		t.Fatal("expected at least some timeline points")
	}
}

func TestGetRecentEvents_Limit(t *testing.T) {
	s := newTestStore(t)

	now := time.Now()
	// Generate events by alternating status.
	for i := 0; i < 10; i++ {
		status := "working"
		if i%2 == 0 {
			status = "blocked"
		}
		s.AddReport(Report{
			Country:   "IR",
			ISP:       "ISP-A",
			Protocol:  "vless-reality",
			Status:    status,
			Timestamp: now.Add(time.Duration(i) * time.Minute),
		})
	}

	events := s.GetRecentEvents(3)
	if len(events) > 3 {
		t.Fatalf("expected at most 3 events, got %d", len(events))
	}
}
