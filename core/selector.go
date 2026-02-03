package core

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// SelectionConfig controls how the protocol selector behaves.
type SelectionConfig struct {
	// ProbeTimeout is the maximum time to spend on all probes.
	ProbeTimeout time.Duration `yaml:"probe_timeout"`

	// ProbeParallel controls whether probes run in parallel.
	ProbeParallel bool `yaml:"probe_parallel"`

	// MinProbeScore is the minimum score a protocol must achieve
	// to be considered viable (0.0 to 1.0).
	MinProbeScore float64 `yaml:"min_probe_score"`

	// PreferLowLatency gives more weight to latency vs reliability.
	PreferLowLatency bool `yaml:"prefer_low_latency"`
}

// Selector determines which protocol to use based on probe results,
// historical data, and configuration priorities.
type Selector struct {
	config  SelectionConfig
	history *selectionHistory
	logger  *slog.Logger
}

// NewSelector creates a protocol selector with the given configuration.
func NewSelector(cfg SelectionConfig, logger *slog.Logger) (*Selector, error) {
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 5 * time.Second
	}
	if cfg.MinProbeScore == 0 {
		cfg.MinProbeScore = 0.3
	}

	return &Selector{
		config:  cfg,
		history: newSelectionHistory(),
		logger:  logger,
	}, nil
}

// Probe runs censorship detection tests for all given protocols.
// Tests are run in parallel if configured. Returns a map of
// protocol name to aggregated probe results.
func (s *Selector) Probe(ctx context.Context, protocols []Protocol) (map[string][]*ProbeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.config.ProbeTimeout)
	defer cancel()

	results := make(map[string][]*ProbeResult)
	var mu sync.Mutex

	if s.config.ProbeParallel {
		var wg sync.WaitGroup
		for _, p := range protocols {
			for _, t := range p.ProbeTests() {
				wg.Add(1)
				go func(proto Protocol, test ProbeTest) {
					defer wg.Done()
					result, err := test.Run(ctx, "")
					if err != nil {
						s.logger.Debug("probe test failed",
							"protocol", proto.Name(),
							"test", test.Name(),
							"error", err,
						)
						return
					}
					mu.Lock()
					results[proto.Name()] = append(results[proto.Name()], result)
					mu.Unlock()
				}(p, t)
			}
		}
		wg.Wait()
	} else {
		for _, p := range protocols {
			for _, t := range p.ProbeTests() {
				result, err := t.Run(ctx, "")
				if err != nil {
					continue
				}
				results[p.Name()] = append(results[p.Name()], result)
			}
		}
	}

	return results, nil
}

// Rank orders protocols by suitability given the probe results.
// The ranking considers: probe scores, configured priority,
// and historical success rates.
func (s *Selector) Rank(protocols []Protocol, probeResults map[string][]*ProbeResult) []Protocol {
	type scored struct {
		protocol Protocol
		score    float64
	}

	var items []scored
	for _, p := range protocols {
		score := s.computeScore(p, probeResults[p.Name()])
		if score >= s.config.MinProbeScore || probeResults == nil {
			items = append(items, scored{protocol: p, score: score})
		} else {
			s.logger.Debug("protocol below threshold",
				"protocol", p.Name(),
				"score", score,
				"threshold", s.config.MinProbeScore,
			)
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].score > items[j].score
	})

	result := make([]Protocol, len(items))
	for i, item := range items {
		result[i] = item.protocol
		s.logger.Debug("protocol ranked",
			"rank", i+1,
			"protocol", item.protocol.Name(),
			"score", item.score,
		)
	}

	return result
}

// computeScore calculates a composite score for a protocol based on
// probe results, priority, and historical success.
func (s *Selector) computeScore(p Protocol, results []*ProbeResult) float64 {
	// Base score from priority (lower priority number = higher score)
	priorityScore := 1.0 / float64(p.Priority()+1)

	// Probe score from test results
	probeScore := 1.0 // default if no probes ran
	if len(results) > 0 {
		var totalWeight float64
		var weightedSuccess float64
		for _, r := range results {
			weight := 1.0 // TODO: get from test
			totalWeight += weight
			if r.Success {
				weightedSuccess += weight
			}
		}
		if totalWeight > 0 {
			probeScore = weightedSuccess / totalWeight
		}
	}

	// Historical success rate
	historyScore := s.history.successRate(p.Name())

	// Composite: probes matter most, then history, then priority
	return probeScore*0.5 + historyScore*0.3 + priorityScore*0.2
}

// RecordSuccess records a successful connection for history tracking.
func (s *Selector) RecordSuccess(protocolName string) {
	s.history.record(protocolName, true)
}

// RecordFailure records a failed connection for history tracking.
func (s *Selector) RecordFailure(protocolName string) {
	s.history.record(protocolName, false)
}

// selectionHistory tracks protocol success/failure rates.
type selectionHistory struct {
	mu      sync.RWMutex
	records map[string]*historyRecord
}

type historyRecord struct {
	successes int
	failures  int
	lastUsed  time.Time
}

func newSelectionHistory() *selectionHistory {
	return &selectionHistory{
		records: make(map[string]*historyRecord),
	}
}

func (h *selectionHistory) record(name string, success bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.records[name]
	if !ok {
		r = &historyRecord{}
		h.records[name] = r
	}

	if success {
		r.successes++
	} else {
		r.failures++
	}
	r.lastUsed = time.Now()
}

func (h *selectionHistory) successRate(name string) float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	r, ok := h.records[name]
	if !ok {
		return 0.5 // no history, assume neutral
	}

	total := r.successes + r.failures
	if total == 0 {
		return 0.5
	}

	return float64(r.successes) / float64(total)
}
