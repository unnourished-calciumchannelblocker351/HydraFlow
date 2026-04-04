package discovery

import "time"
import "context"


// ProbeResult holds the outcome of a single censorship probe test.
type ProbeResult struct {
	TestName  string            `json:"test_name"`
	Success   bool              `json:"success"`
	Latency   time.Duration     `json:"latency,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// ProbeTest is the interface for censorship detection tests.
type ProbeTest interface {
	Name() string
	Weight() float64
	Run(ctx context.Context, target string) (*ProbeResult, error)
}
