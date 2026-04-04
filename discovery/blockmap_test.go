package discovery

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestBlockMapAddReport(t *testing.T) {
	tests := []struct {
		name      string
		reports   []BlockReport
		wantISPs  int
		wantCount int
	}{
		{
			name:      "empty map",
			reports:   nil,
			wantISPs:  0,
			wantCount: 0,
		},
		{
			name: "single report",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
			},
			wantISPs:  1,
			wantCount: 1,
		},
		{
			name: "multiple reports same ISP same protocol",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: time.Now()},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
			},
			wantISPs:  1,
			wantCount: 3,
		},
		{
			name: "multiple reports same ISP different protocols",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
				{ASNumber: 12345, Protocol: "xhttp", Status: StatusBlocked, Timestamp: time.Now()},
				{ASNumber: 12345, Protocol: "shadowtls", Status: StatusSlow, Timestamp: time.Now()},
			},
			wantISPs:  1,
			wantCount: 3,
		},
		{
			name: "multiple ISPs",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
				{ASNumber: 67890, Protocol: "reality", Status: StatusBlocked, Timestamp: time.Now()},
			},
			wantISPs:  2,
			wantCount: 2,
		},
		{
			name: "report with ISP name",
			reports: []BlockReport{
				{ASNumber: 12345, ISPName: "TestISP", Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()},
			},
			wantISPs:  1,
			wantCount: 1,
		},
		{
			name: "report with latency",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusSlow, Latency: 500 * time.Millisecond, Timestamp: time.Now()},
			},
			wantISPs:  1,
			wantCount: 1,
		},
		{
			name: "ten reports same protocol",
			reports: func() []BlockReport {
				var reports []BlockReport
				for i := 0; i < 10; i++ {
					reports = append(reports, BlockReport{
						ASNumber:  12345,
						Protocol:  "reality",
						Status:    StatusWorking,
						Timestamp: time.Now(),
					})
				}
				return reports
			}(),
			wantISPs:  1,
			wantCount: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			if got := len(bm.ISPs); got != tt.wantISPs {
				t.Errorf("ISP count = %d, want %d", got, tt.wantISPs)
			}
			if got := bm.ReportCount(); got != tt.wantCount {
				t.Errorf("ReportCount() = %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestBlockMapGetStatus(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		reports        []BlockReport
		queryAS        uint32
		queryProto     string
		wantStatus     ProtocolStatus
		wantConfidence float64 // 0 means don't check
	}{
		{
			name:       "unknown ISP",
			reports:    nil,
			queryAS:    99999,
			queryProto: "reality",
			wantStatus: StatusUnknown,
		},
		{
			name: "unknown protocol",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
			},
			queryAS:    12345,
			queryProto: "xhttp",
			wantStatus: StatusUnknown,
		},
		{
			name: "all working reports",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
			},
			queryAS:        12345,
			queryProto:     "reality",
			wantStatus:     StatusWorking,
			wantConfidence: 1.0,
		},
		{
			name: "all blocked reports",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now},
			},
			queryAS:        12345,
			queryProto:     "reality",
			wantStatus:     StatusBlocked,
			wantConfidence: 1.0,
		},
		{
			name: "mixed reports majority working",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now},
			},
			queryAS:    12345,
			queryProto: "reality",
			wantStatus: StatusWorking,
		},
		{
			name: "slow status",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "xhttp", Status: StatusSlow, Timestamp: now},
			},
			queryAS:        12345,
			queryProto:     "xhttp",
			wantStatus:     StatusSlow,
			wantConfidence: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			bm.nowFunc = func() time.Time { return now }

			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			status, confidence := bm.GetStatus(tt.queryAS, tt.queryProto)
			if status != tt.wantStatus {
				t.Errorf("status = %v, want %v", status, tt.wantStatus)
			}
			if tt.wantConfidence > 0 && confidence != tt.wantConfidence {
				t.Errorf("confidence = %v, want %v", confidence, tt.wantConfidence)
			}
		})
	}
}

func TestBlockMapTimeDecay(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		reports    []BlockReport
		wantStatus ProtocolStatus
	}{
		{
			name: "recent report outweighs old report",
			reports: []BlockReport{
				// Old blocked report (3 days ago, heavily decayed).
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-72 * time.Hour)},
				// Recent working report (1 hour ago, barely decayed).
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now.Add(-1 * time.Hour)},
			},
			wantStatus: StatusWorking,
		},
		{
			name: "multiple old reports vs one recent",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-96 * time.Hour)},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-72 * time.Hour)},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-48 * time.Hour)},
				// One recent working report should outweigh three old blocked reports.
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now.Add(-30 * time.Minute)},
			},
			wantStatus: StatusWorking,
		},
		{
			name: "very old reports have negligible weight",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-240 * time.Hour)},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now.Add(-1 * time.Hour)},
			},
			wantStatus: StatusWorking,
		},
		{
			name: "equal age reports use majority",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-1 * time.Hour)},
				{ASNumber: 12345, Protocol: "reality", Status: StatusBlocked, Timestamp: now.Add(-1 * time.Hour)},
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now.Add(-1 * time.Hour)},
			},
			wantStatus: StatusBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			bm.nowFunc = func() time.Time { return now }
			bm.DecayHalfLife = 24 * time.Hour

			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			status, _ := bm.GetStatus(12345, "reality")
			if status != tt.wantStatus {
				t.Errorf("status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

func TestBlockMapRecommend(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		reports        []BlockReport
		queryAS        uint32
		wantLen        int
		wantFirstProto string
		wantLastProto  string
	}{
		{
			name:    "unknown ISP returns nil",
			reports: nil,
			queryAS: 99999,
			wantLen: 0,
		},
		{
			name: "single working protocol",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusWorking, Timestamp: now},
			},
			queryAS:        12345,
			wantLen:        1,
			wantFirstProto: "reality",
		},
		{
			name: "working before blocked",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "blocked-proto", Status: StatusBlocked, Timestamp: now},
				{ASNumber: 12345, Protocol: "working-proto", Status: StatusWorking, Timestamp: now},
			},
			queryAS:        12345,
			wantLen:        2,
			wantFirstProto: "working-proto",
			wantLastProto:  "blocked-proto",
		},
		{
			name: "working before slow before blocked",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "blocked", Status: StatusBlocked, Timestamp: now},
				{ASNumber: 12345, Protocol: "slow", Status: StatusSlow, Timestamp: now},
				{ASNumber: 12345, Protocol: "working", Status: StatusWorking, Timestamp: now},
			},
			queryAS:        12345,
			wantLen:        3,
			wantFirstProto: "working",
			wantLastProto:  "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			bm.nowFunc = func() time.Time { return now }

			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			recs := bm.Recommend(tt.queryAS)
			if len(recs) != tt.wantLen {
				t.Fatalf("Recommend() returned %d items, want %d", len(recs), tt.wantLen)
			}
			if tt.wantFirstProto != "" && recs[0].Protocol != tt.wantFirstProto {
				t.Errorf("first recommendation = %s, want %s", recs[0].Protocol, tt.wantFirstProto)
			}
			if tt.wantLastProto != "" && recs[len(recs)-1].Protocol != tt.wantLastProto {
				t.Errorf("last recommendation = %s, want %s", recs[len(recs)-1].Protocol, tt.wantLastProto)
			}
		})
	}
}

func TestBlockMapSerialization(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		reports []BlockReport
	}{
		{
			name: "empty map",
		},
		{
			name: "single ISP single protocol",
			reports: []BlockReport{
				{ASNumber: 12345, ISPName: "TestISP", Protocol: "reality", Status: StatusWorking, Timestamp: now},
			},
		},
		{
			name: "multiple ISPs multiple protocols",
			reports: []BlockReport{
				{ASNumber: 12345, ISPName: "ISP-A", Protocol: "reality", Status: StatusWorking, Timestamp: now},
				{ASNumber: 12345, Protocol: "xhttp", Status: StatusBlocked, Timestamp: now},
				{ASNumber: 67890, ISPName: "ISP-B", Protocol: "reality", Status: StatusSlow, Timestamp: now},
				{ASNumber: 67890, Protocol: "shadowtls", Status: StatusWorking, Timestamp: now},
			},
		},
		{
			name: "with latency data",
			reports: []BlockReport{
				{ASNumber: 12345, Protocol: "reality", Status: StatusSlow, Latency: 500 * time.Millisecond, Timestamp: now},
			},
		},
		{
			name: "large AS number",
			reports: []BlockReport{
				{ASNumber: 4294967295, Protocol: "reality", Status: StatusWorking, Timestamp: now},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			bm.nowFunc = func() time.Time { return now }

			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			// Marshal.
			data, err := json.Marshal(bm)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}

			// Verify it's valid JSON.
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("produced invalid JSON: %v", err)
			}

			// Unmarshal into new BlockMap.
			bm2 := NewBlockMap()
			if err := json.Unmarshal(data, bm2); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			// Verify report counts match.
			if bm.ReportCount() != bm2.ReportCount() {
				t.Errorf("report count after unmarshal: got %d, want %d", bm2.ReportCount(), bm.ReportCount())
			}

			// Verify ISP count matches.
			if len(bm.ISPs) != len(bm2.ISPs) {
				t.Errorf("ISP count after unmarshal: got %d, want %d", len(bm2.ISPs), len(bm.ISPs))
			}
		})
	}
}

func TestBlockMapConcurrency(t *testing.T) {
	bm := NewBlockMap()
	now := time.Now()

	const goroutines = 50
	const reportsPerGoroutine = 100

	var wg sync.WaitGroup

	// Concurrent writers.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < reportsPerGoroutine; i++ {
				bm.AddReport(BlockReport{
					ASNumber:  uint32(id % 10),
					Protocol:  "reality",
					Status:    StatusWorking,
					Timestamp: now.Add(time.Duration(i) * time.Second),
				})
			}
		}(g)
	}

	// Concurrent readers.
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < reportsPerGoroutine; i++ {
				bm.GetStatus(uint32(id%10), "reality")
				bm.Recommend(uint32(id % 10))
				bm.ReportCount()
			}
		}(g)
	}

	// Concurrent serialization.
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				data, err := json.Marshal(bm)
				if err != nil {
					t.Errorf("Marshal error during concurrent access: %v", err)
					return
				}
				bm2 := NewBlockMap()
				if err := json.Unmarshal(data, bm2); err != nil {
					t.Errorf("Unmarshal error during concurrent access: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Verify data integrity.
	totalReports := bm.ReportCount()
	if totalReports == 0 {
		t.Error("expected reports after concurrent writes")
	}

	// All goroutines write to AS numbers 0-9, each with a capped report buffer.
	// The exact count depends on interleaving but should be > 0.
	t.Logf("total reports after concurrent writes: %d", totalReports)
}

func TestBlockMapPrune(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		reports       []BlockReport
		maxAge        time.Duration
		wantRemoved   int
		wantRemaining int
	}{
		{
			name:          "nothing to prune",
			reports:       nil,
			maxAge:        24 * time.Hour,
			wantRemoved:   0,
			wantRemaining: 0,
		},
		{
			name: "all recent, nothing pruned",
			reports: []BlockReport{
				{ASNumber: 1, Protocol: "a", Status: StatusWorking, Timestamp: now.Add(-1 * time.Hour)},
				{ASNumber: 1, Protocol: "a", Status: StatusWorking, Timestamp: now.Add(-2 * time.Hour)},
			},
			maxAge:        24 * time.Hour,
			wantRemoved:   0,
			wantRemaining: 2,
		},
		{
			name: "all old, all pruned",
			reports: []BlockReport{
				{ASNumber: 1, Protocol: "a", Status: StatusWorking, Timestamp: now.Add(-48 * time.Hour)},
				{ASNumber: 1, Protocol: "a", Status: StatusWorking, Timestamp: now.Add(-72 * time.Hour)},
			},
			maxAge:        24 * time.Hour,
			wantRemoved:   2,
			wantRemaining: 0,
		},
		{
			name: "mixed old and new",
			reports: []BlockReport{
				{ASNumber: 1, Protocol: "a", Status: StatusWorking, Timestamp: now.Add(-1 * time.Hour)},
				{ASNumber: 1, Protocol: "a", Status: StatusBlocked, Timestamp: now.Add(-48 * time.Hour)},
				{ASNumber: 1, Protocol: "b", Status: StatusSlow, Timestamp: now.Add(-72 * time.Hour)},
			},
			maxAge:        24 * time.Hour,
			wantRemoved:   2,
			wantRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBlockMap()
			bm.nowFunc = func() time.Time { return now }

			for _, r := range tt.reports {
				bm.AddReport(r)
			}

			removed := bm.Prune(tt.maxAge)
			if removed != tt.wantRemoved {
				t.Errorf("Prune() removed %d, want %d", removed, tt.wantRemoved)
			}
			if remaining := bm.ReportCount(); remaining != tt.wantRemaining {
				t.Errorf("remaining reports = %d, want %d", remaining, tt.wantRemaining)
			}
		})
	}
}

func TestBlockMapMaxReports(t *testing.T) {
	bm := NewBlockMap()
	bm.MaxReportsPerProtocol = 5

	now := time.Now()
	for i := 0; i < 20; i++ {
		bm.AddReport(BlockReport{
			ASNumber:  12345,
			Protocol:  "reality",
			Status:    StatusWorking,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	if count := bm.ReportCount(); count != 5 {
		t.Errorf("ReportCount() = %d, want 5 (max limit)", count)
	}
}

func TestBlockMapISPNames(t *testing.T) {
	bm := NewBlockMap()
	bm.AddReport(BlockReport{ASNumber: 100, ISPName: "Alpha ISP", Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()})
	bm.AddReport(BlockReport{ASNumber: 200, ISPName: "Beta ISP", Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()})
	bm.AddReport(BlockReport{ASNumber: 300, Protocol: "reality", Status: StatusWorking, Timestamp: time.Now()})

	names := bm.ISPNames()
	if len(names) != 3 {
		t.Fatalf("ISPNames() returned %d entries, want 3", len(names))
	}
	if names[100] != "Alpha ISP" {
		t.Errorf("names[100] = %q, want %q", names[100], "Alpha ISP")
	}
	if names[200] != "Beta ISP" {
		t.Errorf("names[200] = %q, want %q", names[200], "Beta ISP")
	}
	if names[300] != "" {
		t.Errorf("names[300] = %q, want empty", names[300])
	}
}

func TestISPDetector(t *testing.T) {
	tests := []struct {
		name      string
		register  map[uint32]string
		lookupAS  uint32
		wantName  string
		wantFound bool
	}{
		{
			name:      "lookup unknown AS",
			register:  nil,
			lookupAS:  12345,
			wantName:  "",
			wantFound: false,
		},
		{
			name:      "lookup known AS",
			register:  map[uint32]string{12345: "Test ISP"},
			lookupAS:  12345,
			wantName:  "Test ISP",
			wantFound: true,
		},
		{
			name:      "lookup one of many",
			register:  map[uint32]string{100: "ISP-A", 200: "ISP-B", 300: "ISP-C"},
			lookupAS:  200,
			wantName:  "ISP-B",
			wantFound: true,
		},
		{
			name:      "lookup after bulk register",
			register:  map[uint32]string{1: "One", 2: "Two", 3: "Three", 4: "Four"},
			lookupAS:  3,
			wantName:  "Three",
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewISPDetector()
			if tt.register != nil {
				d.RegisterBulk(tt.register)
			}

			name, found := d.Lookup(tt.lookupAS)
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

func TestISPDetectorConcurrency(t *testing.T) {
	d := NewISPDetector()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d.Register(uint32(id), "ISP")
			d.Lookup(uint32(id))
			d.ASCount()
		}(i)
	}

	wg.Wait()

	if d.ASCount() != 50 {
		t.Errorf("ASCount() = %d, want 50", d.ASCount())
	}
}

func TestProtocolStatusString(t *testing.T) {
	tests := []struct {
		status ProtocolStatus
		want   string
	}{
		{StatusUnknown, "unknown"},
		{StatusWorking, "working"},
		{StatusSlow, "slow"},
		{StatusBlocked, "blocked"},
		{ProtocolStatus(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.status.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseProtocolStatus(t *testing.T) {
	tests := []struct {
		input string
		want  ProtocolStatus
	}{
		{"working", StatusWorking},
		{"slow", StatusSlow},
		{"blocked", StatusBlocked},
		{"unknown", StatusUnknown},
		{"invalid", StatusUnknown},
		{"", StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseProtocolStatus(tt.input); got != tt.want {
				t.Errorf("ParseProtocolStatus(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBlockMapRecommendScoreOrdering(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	bm := NewBlockMap()
	bm.nowFunc = func() time.Time { return now }

	// Add various protocol statuses for the same ISP.
	protocols := []struct {
		name   string
		status ProtocolStatus
	}{
		{"reality", StatusWorking},
		{"xhttp", StatusSlow},
		{"shadowtls", StatusBlocked},
		{"hysteria2", StatusWorking},
	}

	for _, p := range protocols {
		bm.AddReport(BlockReport{
			ASNumber:  12345,
			Protocol:  p.name,
			Status:    p.status,
			Timestamp: now,
		})
	}

	recs := bm.Recommend(12345)
	if len(recs) != 4 {
		t.Fatalf("got %d recommendations, want 4", len(recs))
	}

	// Verify scores are in descending order.
	for i := 1; i < len(recs); i++ {
		if recs[i].Score > recs[i-1].Score {
			t.Errorf("recommendations not sorted: [%d].Score=%f > [%d].Score=%f",
				i, recs[i].Score, i-1, recs[i-1].Score)
		}
	}

	// Working protocols should have higher scores than blocked.
	lastRec := recs[len(recs)-1]
	if lastRec.Status != StatusBlocked {
		t.Errorf("last recommendation should be blocked, got %v", lastRec.Status)
	}
}
