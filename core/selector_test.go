package core

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestSelectorNewDefaults(t *testing.T) {
	s, err := NewSelector(SelectionConfig{}, testLogger())
	if err != nil {
		t.Fatalf("NewSelector() error: %v", err)
	}

	if s.config.ProbeTimeout != 5*time.Second {
		t.Errorf("expected default probe timeout 5s, got %v", s.config.ProbeTimeout)
	}
	if s.config.MinProbeScore != 0.3 {
		t.Errorf("expected default min probe score 0.3, got %v", s.config.MinProbeScore)
	}
}

func TestSelectorRankByPriority(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{}, testLogger())

	protocols := []Protocol{
		&mockProtocol{name: "low-priority", priority: 3},
		&mockProtocol{name: "high-priority", priority: 1},
		&mockProtocol{name: "mid-priority", priority: 2},
	}

	// Without probe results, ranking should fall back to priority
	ranked := s.Rank(protocols, nil)

	if len(ranked) != 3 {
		t.Fatalf("expected 3 ranked protocols, got %d", len(ranked))
	}
	if ranked[0].Name() != "high-priority" {
		t.Errorf("expected first ranked to be 'high-priority', got '%s'", ranked[0].Name())
	}
}

func TestSelectorRankWithProbes(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{}, testLogger())

	protocols := []Protocol{
		&mockProtocol{name: "high-priority-blocked", priority: 1},
		&mockProtocol{name: "low-priority-works", priority: 3},
	}

	probeResults := map[string][]*ProbeResult{
		"high-priority-blocked": {
			{TestName: "port", Success: false, Timestamp: time.Now()},
			{TestName: "tls", Success: false, Timestamp: time.Now()},
		},
		"low-priority-works": {
			{TestName: "port", Success: true, Timestamp: time.Now()},
			{TestName: "tls", Success: true, Timestamp: time.Now()},
		},
	}

	ranked := s.Rank(protocols, probeResults)

	if len(ranked) == 0 {
		t.Fatal("expected at least one ranked protocol")
	}
	// The working protocol should rank higher despite lower priority
	if ranked[0].Name() != "low-priority-works" {
		t.Errorf("working protocol should rank first, got '%s'", ranked[0].Name())
	}
}

func TestSelectorHistoryTracking(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{}, testLogger())

	// Record some history
	s.RecordSuccess("proto-a")
	s.RecordSuccess("proto-a")
	s.RecordSuccess("proto-a")
	s.RecordFailure("proto-b")
	s.RecordFailure("proto-b")
	s.RecordSuccess("proto-b")

	rateA := s.history.successRate("proto-a")
	rateB := s.history.successRate("proto-b")

	if rateA != 1.0 {
		t.Errorf("proto-a success rate should be 1.0, got %v", rateA)
	}
	if rateB < 0.3 || rateB > 0.4 {
		t.Errorf("proto-b success rate should be ~0.33, got %v", rateB)
	}
}

func TestSelectorHistoryDefaultRate(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{}, testLogger())

	rate := s.history.successRate("unknown-protocol")
	if rate != 0.5 {
		t.Errorf("unknown protocol should have 0.5 default rate, got %v", rate)
	}
}

func TestSelectorHistoryInfluencesRanking(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{}, testLogger())

	// Build history: proto-b has better track record
	for i := 0; i < 10; i++ {
		s.RecordFailure("proto-a")
		s.RecordSuccess("proto-b")
	}

	protocols := []Protocol{
		&mockProtocol{name: "proto-a", priority: 1},
		&mockProtocol{name: "proto-b", priority: 2},
	}

	ranked := s.Rank(protocols, nil)

	// proto-b should rank higher due to history despite lower priority
	if ranked[0].Name() != "proto-b" {
		t.Errorf("protocol with better history should rank first, got '%s'", ranked[0].Name())
	}
}

func TestSelectorProbeParallel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s, _ := NewSelector(SelectionConfig{
		ProbeParallel: true,
		ProbeTimeout:  2 * time.Second,
	}, logger)

	protocols := []Protocol{
		&mockProtocol{name: "proto-a", priority: 1},
		&mockProtocol{name: "proto-b", priority: 2},
	}

	results, err := s.Probe(context.Background(), protocols)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	// No probes registered on mock protocols, so results should be empty
	if len(results) != 0 {
		t.Errorf("expected 0 results from mock protocols, got %d", len(results))
	}
}

func TestSelectorMinProbeScore(t *testing.T) {
	s, _ := NewSelector(SelectionConfig{
		MinProbeScore: 0.5,
	}, testLogger())

	protocols := []Protocol{
		&mockProtocol{name: "good", priority: 1},
		&mockProtocol{name: "bad", priority: 2},
	}

	probeResults := map[string][]*ProbeResult{
		"good": {
			{TestName: "test1", Success: true},
			{TestName: "test2", Success: true},
		},
		"bad": {
			{TestName: "test1", Success: false},
			{TestName: "test2", Success: false},
		},
	}

	ranked := s.Rank(protocols, probeResults)

	// "bad" protocol should be filtered out due to low score
	if len(ranked) != 1 {
		t.Errorf("expected 1 protocol after filtering, got %d", len(ranked))
	}
	if ranked[0].Name() != "good" {
		t.Errorf("expected 'good' protocol, got '%s'", ranked[0].Name())
	}
}
